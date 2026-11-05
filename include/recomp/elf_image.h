#pragma once

#include "recomp/runtime.h"
#include <string>
#include <vector>

namespace recomp {

struct ImageSegment {
    uint64_t address; // p_vaddr + explicit load bias, never a host pointer
    uint64_t virtual_address;
    uint64_t file_offset;
    uint64_t file_size;
    uint64_t memory_size;
    uint64_t alignment;
    uint32_t flags;
};

struct ImageImport {
    std::string name;
    uint32_t symbol_index;
    uint8_t binding;
    uint8_t type;
};

struct ImageRelocation {
    uint64_t address;
    uint32_t type;
    uint32_t symbol_index;
    std::string symbol;
    uint64_t addend_bits; // raw two's-complement ELF64 signed addend
    bool has_addend;
};

// Data loading only. No relocations, import bridges, initializer calls, entry
// dispatch, dlopen, host executable mappings or ARM64 execution are provided.
class ElfImage {
public:
    static ElfImage load(const std::string& path, const std::string& expected_sha256,
                         uint64_t load_bias, uint64_t memory_limit = UINT64_C(536870912));
    Memory& memory() { return memory_; }
    const Memory& memory() const { return memory_; }
    const std::vector<ImageSegment>& segments() const { return segments_; }
    const std::vector<ImageImport>& unresolved_imports() const { return imports_; }
    const std::vector<ImageRelocation>& unresolved_relocations() const { return relocations_; }
    const std::vector<std::string>& needed_libraries() const { return needed_; }
    const std::string& sha256() const { return sha256_; }
    uint64_t load_bias() const { return bias_; }
    // Even an image with empty inventories has no runtime startup support yet.
    bool ready_to_execute() const { return false; }
private:
    ElfImage() : memory_(0, 0), bias_(0) {}
    Memory memory_;
    uint64_t bias_;
    std::string sha256_;
    std::vector<ImageSegment> segments_;
    std::vector<ImageImport> imports_;
    std::vector<ImageRelocation> relocations_;
    std::vector<std::string> needed_;
};

} // namespace recomp
