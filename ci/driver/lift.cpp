// Isolated AOT experiment. All guest data accesses remain external checked calls.
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/Util.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CodeGen.h>
#include <llvm/TargetParser/Triple.h>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void require(bool test, const std::string &message) {
    if (!test) throw std::runtime_error(message);
}
struct Body { uint64_t start; std::string bytes; };
bool allowed_word(uint32_t w) {
    if ((w & 0xffe0ffe0U) == 0xaa0003e0U) return true; // MOV X (ORR alias)
    if ((w & 0xff800000U) == 0x91000000U) return true; // ADD X immediate
    const uint32_t top = w & 0xffc00000U;
    if (top == 0xf9400000U || top == 0xf9000000U) return true;
    if ((w & 0xffe00c00U) == 0xf8000c00U ||
        (w & 0xffe00c00U) == 0xf8400400U) {
        const unsigned base = (w >> 5) & 31, rt = w & 31;
        return base == 31 || base != rt;
    }
    if (top == 0xa9000000U || top == 0xa9800000U ||
        top == 0xa9400000U || top == 0xa8c00000U) {
        const unsigned base = (w >> 5) & 31, rt = w & 31, rt2 = (w >> 10) & 31;
        if ((top == 0xa9800000U || top == 0xa8c00000U) && base != 31 && (base == rt || base == rt2)) return false;
        return (top != 0xa9400000U && top != 0xa8c00000U) || rt != rt2;
    }
    if ((w & 0xff000000U) == 0xb4000000U || (w & 0xff000000U) == 0xb5000000U) return true;
    if ((w & 0xfc000000U) == 0x14000000U || (w & 0xfc000000U) == 0x94000000U) return true;
    return w == 0xd65f03c0U;
}
uint32_t word(const std::string &s, size_t p) {
    uint32_t v = 0;
    for (unsigned i = 0; i != 4; ++i) v |= uint32_t(uint8_t(s[p+i])) << (i*8);
    return v;
}
llvm::Value *byte_at(llvm::IRBuilder<> &b, llvm::Value *p, uint64_t off) {
    return b.CreateConstGEP1_64(b.getInt8Ty(), p, off);
}
void strip_unwind_claims(llvm::Module &m) {
    for (auto &f : m) {
        f.removeFnAttr(llvm::Attribute::NoUnwind);
        f.removeFnAttr("target-cpu"); f.removeFnAttr("target-features"); f.removeFnAttr("tune-cpu");
        if (!f.isDeclaration()) f.setUWTableKind(llvm::UWTableKind::Default);
        for (auto &bb : f) for (auto &i : bb)
            if (auto *c = llvm::dyn_cast<llvm::CallBase>(&i)) c->removeFnAttr(llvm::Attribute::NoUnwind);
    }
}
}
int main(int argc, char **argv) {
    try {
        if (argc==2 && std::string(argv[1])=="--toolchain-check") {
            llvm::LLVMContext c;auto a=remill::Arch::Get(c,"linux","aarch64");
            auto m=std::unique_ptr<llvm::Module>(remill::LoadArchSemantics(a.get()));
            require(bool(m),"missing semantics");
            require(m->getDataLayout().getTypeAllocSize(a->StateStructType()).getFixedValue()==1200,"private state size mismatch");
            std::cout<<"AArch64 semantics loaded; private state is 1200 bytes; no guest input read\n";return 0;
        }
        require(argc == 3, "usage: proof-lift body-file output-directory");
        std::ifstream input(argv[1]);
        require(bool(input), "cannot open body input");
        std::map<uint64_t,Body> bodies;
        std::string address, hex;
        while (input >> address >> hex) {
            Body body{std::stoull(address,nullptr,16),{}};
            require(body.start % 4 == 0 && hex.size() % 8 == 0 && !hex.empty() && hex.find_first_not_of("0123456789abcdefABCDEF")==std::string::npos, "unaligned/incomplete/invalid body");
            for (size_t i=0; i<hex.size(); i+=2) body.bytes.push_back(char(std::stoul(hex.substr(i,2),nullptr,16)));
            require(bodies.emplace(body.start,body).second, "duplicate function entry");
        }
        require(bodies.size()==2 && bodies.count(0x26f81c) && bodies.count(0x26f85c), "closure identity mismatch");
        require(bodies.at(0x26f81c).bytes.size()==64 && bodies.at(0x26f85c).bytes.size()==60, "body extent mismatch");
        llvm::LLVMContext context;
        auto arch = remill::Arch::Get(context, "linux", "aarch64");
        auto module = std::unique_ptr<llvm::Module>(remill::LoadArchSemantics(arch.get()));
        require(bool(module), "missing AArch64 semantics");
        std::map<uint64_t,std::unique_ptr<remill::Instruction>> instructions;
        std::map<uint64_t,std::vector<uint64_t>> successors;
        std::map<uint64_t,std::vector<uint64_t>> function_pcs;
        for (auto &pair : bodies) {
            const auto &body=pair.second;
            for (size_t off=0; off<body.bytes.size(); off+=4) {
                uint64_t pc=body.start+off;
                require(allowed_word(word(body.bytes,off)), "encoding outside experimental allowlist at "+std::to_string(pc));
                auto inst=std::make_unique<remill::Instruction>();
                require(arch->DecodeInstruction(pc,std::string_view(body.bytes).substr(off,4),*inst,arch->CreateInitialContext()), "Remill decode failed");
                require(!inst->is_atomic_read_modify_write, "unsupported atomic instruction");
                std::vector<uint64_t> next;
                using I=remill::Instruction;
                switch(inst->category) {
                case I::kCategoryNormal: case I::kCategoryNoOp: next={pc+4}; break;
                case I::kCategoryConditionalBranch: next={inst->branch_taken_pc,pc+4}; break;
                case I::kCategoryDirectJump: next={inst->branch_taken_pc}; break;
                case I::kCategoryDirectFunctionCall:
                    require(bodies.count(inst->branch_taken_pc), "call target outside closure"); next={pc+4}; break;
                case I::kCategoryFunctionReturn: break;
                default: throw std::runtime_error("unsupported control flow");
                }
                for (uint64_t n : next) require(n>=body.start && n<body.start+body.bytes.size() && n%4==0, "branch/fallthrough outside body");
                function_pcs[body.start].push_back(pc); successors[pc]=next; instructions.emplace(pc,std::move(inst));
            }
            std::set<uint64_t> reachable;
            std::vector<uint64_t> work{body.start};
            while (!work.empty()) { auto p=work.back(); work.pop_back(); if (!reachable.insert(p).second) continue; for(auto n:successors.at(p)) work.push_back(n); }
            require(reachable.size()==body.bytes.size()/4, "unreachable instruction");
            std::set<uint64_t> can_return;
            for(auto pc:function_pcs[body.start]) if(successors[pc].empty()) can_return.insert(pc);
            bool changed=true;
            while(changed) { changed=false; for(auto pc:function_pcs[body.start]) for(auto n:successors[pc]) if(can_return.count(n)) changed|=can_return.insert(pc).second; }
            require(can_return.size()==reachable.size(), "block has no path to return");
        }
        std::map<uint64_t,llvm::Function*> functions;
        for(auto &p:bodies) functions[p.first]=arch->DeclareLiftedFunction("proof_fn_"+std::to_string(p.first),module.get());
        auto ptr=llvm::PointerType::getUnqual(context); auto i64=llvm::Type::getInt64Ty(context);
        auto step=module->getOrInsertFunction("proof_step",llvm::FunctionType::get(llvm::Type::getVoidTy(context),{ptr,i64},false));
        auto bad=module->getOrInsertFunction("proof_bad_return",llvm::FunctionType::get(llvm::Type::getVoidTy(context),{ptr,i64,i64},false));
        std::vector<std::string> accepted;
        for(auto &pair:functions) {
            const uint64_t entry=pair.first;
            auto *fn=pair.second; arch->InitializeEmptyLiftedFunction(fn);
            auto *state=remill::LoadStatePointer(fn); auto *memory=remill::LoadMemoryPointerArg(fn);
            auto *prologue=&fn->front(); llvm::IRBuilder<> b(prologue);
            auto *initial_lr=b.CreateLoad(i64,arch->RegisterByName("X30")->AddressOf(state,b));
            auto next_ref=remill::FindVarInFunction(fn,"NEXT_PC").first;
            b.CreateStore(remill::LoadProgramCounterArg(fn),next_ref);
            std::map<uint64_t,llvm::BasicBlock*> blocks;
            for(auto pc:function_pcs[entry]) blocks[pc]=llvm::BasicBlock::Create(context,"guest_"+std::to_string(pc),fn);
            b.CreateBr(blocks.at(entry));
            for(auto pc:function_pcs[entry]) {
                auto *bb=blocks.at(pc); llvm::IRBuilder<> ir(bb);
                ir.CreateCall(step,{memory,ir.getInt64(pc)});
                auto &inst=*instructions.at(pc);
                require(inst.GetLifter()->LiftIntoBlock(inst,bb,state)==remill::kLiftedInstruction,"unsupported/mismatched ISEL at "+std::to_string(pc));
                accepted.push_back(std::to_string(pc)+" "+inst.function);
                ir.SetInsertPoint(bb);
                auto next=successors.at(pc);
                using I=remill::Instruction;
                if(inst.category==I::kCategoryDirectFunctionCall) {
                    auto memref=remill::FindVarInFunction(fn,"MEMORY").first;
                    auto *callee=functions.at(inst.branch_taken_pc);
                    auto *call=ir.CreateCall(callee,{state,ir.getInt64(inst.branch_taken_pc),ir.CreateLoad(ptr,memref)});
                    call->setCallingConv(callee->getCallingConv()); ir.CreateStore(call,memref);
                    auto *actual=ir.CreateLoad(i64,arch->RegisterByName("PC")->AddressOf(state,ir));
                    auto *error=llvm::BasicBlock::Create(context,"bad_call_return",fn);
                    auto *ok=llvm::BasicBlock::Create(context,"call_continuation",fn);
                    ir.CreateCondBr(ir.CreateICmpEQ(actual,ir.getInt64(pc+4)),ok,error);
                    llvm::IRBuilder<> error_ir(error);error_ir.CreateCall(bad,{memory,actual,error_ir.getInt64(pc+4)});error_ir.CreateUnreachable();
                    llvm::IRBuilder<> ok_ir(ok);ok_ir.CreateStore(ok_ir.getInt64(pc+4),next_ref);ok_ir.CreateBr(blocks.at(pc+4));
                } else if(inst.category==I::kCategoryFunctionReturn) {
                    auto *actual=ir.CreateLoad(i64,next_ref);
                    auto *ret=llvm::BasicBlock::Create(context,"checked_ret",fn);
                    auto *error=llvm::BasicBlock::Create(context,"bad_ret",fn);
                    ir.SetInsertPoint(bb);ir.CreateCondBr(ir.CreateICmpEQ(actual,initial_lr),ret,error);
                    llvm::IRBuilder<> er(error);er.CreateCall(bad,{memory,actual,initial_lr});er.CreateUnreachable();
                    llvm::IRBuilder<> ri(ret);ri.CreateRet(ri.CreateLoad(ptr,remill::FindVarInFunction(fn,"MEMORY").first));
                } else if(inst.category==I::kCategoryConditionalBranch) {
                    ir.CreateCondBr(remill::LoadBranchTaken(bb),blocks.at(inst.branch_taken_pc),blocks.at(pc+4));
                } else ir.CreateBr(blocks.at(next.at(0)));
            }
        }
        // Check all named state fields used by this integer-only experiment.
        const auto old_layout=module->getDataLayout();
        llvm::DataLayout host_layout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128");
        for(auto *ty:module->getIdentifiedStructTypes()) if(ty->isSized()) {
            auto *a=old_layout.getStructLayout(ty), *z=host_layout.getStructLayout(ty);
            require(a->getSizeInBytes()==z->getSizeInBytes(),"host state/struct size differs");
            for(unsigned n=0;n<ty->getNumElements();++n) require(a->getElementOffset(n)==z->getElementOffset(n),"host state/struct field offset differs");
        }
        require(host_layout.getTypeAllocSize(arch->StateStructType()).getFixedValue()==1200,"unexpected private state size");
        module->setTargetTriple(llvm::Triple("x86_64-pc-linux-gnu"));module->setDataLayout(host_layout);
        auto *wrapper=llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(context),{ptr,ptr},false),llvm::GlobalValue::ExternalLinkage,"proof_run",module.get());
        auto *entry=llvm::BasicBlock::Create(context,"entry",wrapper);llvm::IRBuilder<> out(entry);
        auto args=wrapper->arg_begin();llvm::Value *public_state=&*args++;llvm::Value *mem=&*args;
        auto *private_state=out.CreateAlloca(arch->StateStructType());private_state->setAlignment(llvm::Align(16));
        out.CreateMemSet(private_state,out.getInt8(0),1200,llvm::Align(16));
        for(unsigned r=0;r!=32;++r) {
            const auto *reg=arch->RegisterByName(r==31?"SP":"X"+std::to_string(r));require(reg && reg->type==i64,"bad register descriptor");
            out.CreateStore(out.CreateLoad(i64,byte_at(out,public_state,r*8)),reg->AddressOf(private_state,out));
        }
        auto *call=out.CreateCall(functions.at(0x26f81c),{private_state,out.getInt64(0x26f81c),mem});call->setCallingConv(functions.at(0x26f81c)->getCallingConv());
        for(unsigned r=0;r!=32;++r) {
            const auto *reg=arch->RegisterByName(r==31?"SP":"X"+std::to_string(r));
            out.CreateStore(out.CreateLoad(i64,reg->AddressOf(private_state,out)),byte_at(out,public_state,r*8));
        }
        out.CreateRetVoid();
        // Remove upstream retention roots and internalize unused semantics.
        for(const char *name:{"llvm.used","llvm.compiler.used"}) if(auto *g=module->getGlobalVariable(name)) g->eraseFromParent();
        for(auto &f:*module) {
            if(!f.isDeclaration() && &f!=wrapper) f.setLinkage(llvm::GlobalValue::InternalLinkage);
            if(f.isDeclaration() && !f.isIntrinsic()) f.setAttributes(llvm::AttributeList());
        }
        for(auto &g:module->globals()) if(!g.isDeclaration()) g.setLinkage(llvm::GlobalValue::InternalLinkage);
        strip_unwind_claims(*module);
        require(!llvm::verifyModule(*module,&llvm::errs()),"invalid preoptimization IR");
        llvm::LoopAnalysisManager lam;llvm::FunctionAnalysisManager fam;llvm::CGSCCAnalysisManager cgam;llvm::ModuleAnalysisManager mam;
        llvm::PassBuilder pb;pb.registerModuleAnalyses(mam);pb.registerCGSCCAnalyses(cgam);pb.registerFunctionAnalyses(fam);pb.registerLoopAnalyses(lam);pb.crossRegisterProxies(lam,fam,cgam,mam);
        auto pipeline=pb.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O2);pipeline.run(*module,mam);
        strip_unwind_claims(*module);
        require(!llvm::verifyModule(*module,&llvm::errs()),"invalid optimized IR");
        const std::set<std::string> allowed_external={"proof_step","proof_bad_return","__remill_read_memory_64","__remill_write_memory_64"};
        for(auto &f:*module) {
            if(f.isDeclaration() && !f.use_empty() && !f.isIntrinsic()) require(allowed_external.count(f.getName().str()),"unexpected external helper "+f.getName().str());
            for(auto &bb:f) for(auto &i:bb) {
                require(!llvm::isa<llvm::IntToPtrInst>(i),"raw integer-to-pointer operation in artifact");
                if(auto *c=llvm::dyn_cast<llvm::CallBase>(&i)) require(!c->isInlineAsm() && c->getCalledFunction(),"inline asm or indirect host call in artifact");
            }
        }
        const std::filesystem::path destination(argv[2]);
        std::filesystem::create_directories(destination);
        std::error_code ec;llvm::raw_fd_ostream file((destination/"proof.ll.tmp").string(),ec);require(!ec,"cannot create staged IR");
        module->print(file,nullptr);file.close();require(!file.has_error(),"IR write failed");
        std::ofstream report(destination/"acceptance.txt.tmp");
        for(const auto &line:accepted) report<<line<<'\n';report.close();require(bool(report),"acceptance write failed");
        std::filesystem::rename(destination/"proof.ll.tmp",destination/"proof.ll");
        std::filesystem::rename(destination/"acceptance.txt.tmp",destination/"acceptance.txt");
        std::cout<<"Accepted and lifted all "<<accepted.size()<<" instructions; host layout checked; artifact audited\n";
        return 0;
    } catch(const std::exception &e) {std::cerr<<"Proof generation rejected: "<<e.what()<<'\n';return 1;}
}
