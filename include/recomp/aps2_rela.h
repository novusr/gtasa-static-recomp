#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace recomp {

// Pure decoded data, deliberately distinct from ImageRelocation. All addends
// are explicit RELA addends, including groups that omit addend encoding.
struct Aps2RelaRecord {
    uint64_t offset;
    uint64_t info;
    int64_t addend;
    uint64_t ordinal;
    uint64_t group_ordinal;
    uint64_t group_begin;
    uint64_t group_header_end;
    uint64_t group_end;
    uint64_t entry_begin;
    uint64_t entry_end;
    uint64_t flags;
    uint32_t symbol_index() const { return static_cast<uint32_t>(info >> 32); }
    uint32_t type() const { return static_cast<uint32_t>(info); }
};
static_assert(sizeof(Aps2RelaRecord) == 88, "APS2 record storage accounting");
static_assert(offsetof(Aps2RelaRecord, offset) == 0, "APS2 offset layout");
static_assert(offsetof(Aps2RelaRecord, info) == 8, "APS2 info layout");
static_assert(offsetof(Aps2RelaRecord, addend) == 16, "APS2 addend layout");
static_assert(offsetof(Aps2RelaRecord, ordinal) == 24, "APS2 ordinal layout");
static_assert(offsetof(Aps2RelaRecord, group_ordinal) == 32, "APS2 group layout");
static_assert(offsetof(Aps2RelaRecord, group_begin) == 40, "APS2 group begin layout");
static_assert(offsetof(Aps2RelaRecord, group_header_end) == 48, "APS2 header layout");
static_assert(offsetof(Aps2RelaRecord, group_end) == 56, "APS2 group end layout");
static_assert(offsetof(Aps2RelaRecord, entry_begin) == 64, "APS2 entry begin layout");
static_assert(offsetof(Aps2RelaRecord, entry_end) == 72, "APS2 entry end layout");
static_assert(offsetof(Aps2RelaRecord, flags) == 80, "APS2 flags layout");

struct Aps2RelaResult {
    std::vector<Aps2RelaRecord> records;
    uint64_t initial_offset;
    uint64_t encoded_size;
    uint64_t group_count;
    Aps2RelaResult() : initial_offset(0), encoded_size(0), group_count(0) {}
};

struct Aps2RelaLimits {
    uint64_t max_records;
    uint64_t max_storage_bytes;
    Aps2RelaLimits() : max_records(1000000), max_storage_bytes(268435456) {}
};

class Aps2DecodeError : public std::runtime_error {
public:
    Aps2DecodeError(std::size_t byte_offset, const char* reason);
    std::size_t byte_offset() const { return byte_offset_; }
private:
    std::size_t byte_offset_;
};

// data must name length readable bytes. No ELF binding, target reads, bias,
// memory access, symbol resolution or application. Byte spans are [begin,end)
// relative to data, including shared group headers. On ANY exception output
// (including its capacity/metadata) is unchanged. Allocation errors propagate.
void decode_android_aps2_rela(const uint8_t* data, std::size_t length,
                              Aps2RelaResult& output,
                              const Aps2RelaLimits& limits = Aps2RelaLimits());

} // namespace recomp
