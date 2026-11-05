#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/Util.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <iostream>
#include <memory>
#include <string>

int main() {
    llvm::LLVMContext context;
    auto arch = remill::Arch::Get(context, "linux", "aarch64");
    std::unique_ptr<llvm::Module> semantics(remill::LoadArchSemantics(arch.get()));
    if (!semantics) return 1;
    const std::string synthetic_ret("\xc0\x03\x5f\xd6", 4);
    remill::Instruction instruction;
    if (!arch->DecodeInstruction(0x1000, synthetic_ret, instruction,
                                 arch->CreateInitialContext())) return 2;
    if (instruction.category != remill::Instruction::kCategoryFunctionReturn) return 3;
    std::cout << "Installed consumer: AArch64 semantics loaded; synthetic RET decoded\n";
    return 0;
}
