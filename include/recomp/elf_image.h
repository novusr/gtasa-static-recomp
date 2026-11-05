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

struct ImageSymbol {
    std::string name;
    uint32_t table_section; // identity is (section index, symbol index), never name
    uint32_t table_type;
    uint32_t index;
    uint64_t value;
    uint64_t size;
    uint16_t section_index;
    uint8_t binding;
    uint8_t type;
    uint8_t visibility;
    uint8_t other;
    std::string resolution_reason; // empty only for supported internal definitions
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
    ImageSymbol definition;
    std::string unresolved_reason;
};

// Data loading and explicit bounded RELA guest-address fixups only. No import bridges,
// initializer calls, entry dispatch, dlopen, host executable mappings or ARM64
// execution are provided.
class ElfImage {
public:
    static ElfImage load(const std::string& path, const std::string& expected_sha256,
                         uint64_t load_bias, uint64_t memory_limit = UINT64_C(536870912));
    // Validate the complete batch, then write only to existing PF_W mappings.
    // Each successful phase is idempotent; REL/unsupported forms stay unresolved.
    void apply_relative_relocations();
    void apply_symbol_relocations();
    // One transaction for both phases, including validation/allocation.
    void apply_relocations();
    // Explicit guest page geometry, never inferred from p_align or host pages.
    // Atomic permission-only transaction; no relocation/import completion implied.
    void seal_relro(uint64_t guest_page_size);
    bool relro_sealed() const { return relro_sealed_; }
    uint64_t relro_page_size() const { return relro_page_size_; }
    const std::vector<ImageSegment>& relro_segments() const { return relro_; }
    const std::vector<GuestRange>& sealed_relro_ranges() const { return memory_.read_only_; }
    const std::vector<ImageSymbol>& symbols() const { return symbols_; }
    const std::vector<ImageRelocation>& applied_relocations() const { return applied_; }
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
    ElfImage() : memory_(0, 0), bias_(0), relative_applied_(false), symbols_applied_(false),
                 relro_sealed_(false), relro_page_size_(0) {}
    void apply_relocation_batch(bool relative, bool symbols);
    Memory memory_;
    uint64_t bias_;
    bool relative_applied_;
    bool symbols_applied_;
    bool relro_sealed_;
    uint64_t relro_page_size_;
    std::vector<ImageSegment> relro_;
    std::vector<ImageSymbol> symbols_;
    std::string sha256_;
    std::vector<ImageSegment> segments_;
    std::vector<ImageImport> imports_;
    std::vector<ImageRelocation> relocations_;
    std::vector<ImageRelocation> applied_;
    std::vector<std::string> needed_;
};

} // namespace recomp
