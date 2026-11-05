#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace recomp {

enum class RelrEncoding : uint64_t { Android = 1, Standard = 2 };
enum class RelrSource : uint64_t { Anchor = 1, Bitmap = 2 };
enum class RelrAddend : uint64_t { ImplicitTarget = 1 };

// Pure data, deliberately unrelated to ImageRelocation and fixup APIs.
struct RelrRecord {
    uint64_t offset;
    uint64_t ordinal;
    uint64_t word_index;
    uint64_t byte_offset;
    RelrEncoding encoding;
    RelrSource source;
    uint64_t bitmap_bit; // 0 for anchors, 1..63 for bitmap targets.
    RelrAddend addend_kind;
};
static_assert(sizeof(RelrRecord) == 64, "RELR storage accounting");
static_assert(offsetof(RelrRecord, offset) == 0, "RELR offset layout");
static_assert(offsetof(RelrRecord, ordinal) == 8, "RELR ordinal layout");
static_assert(offsetof(RelrRecord, word_index) == 16, "RELR word layout");
static_assert(offsetof(RelrRecord, byte_offset) == 24, "RELR byte layout");
static_assert(offsetof(RelrRecord, encoding) == 32, "RELR encoding layout");
static_assert(offsetof(RelrRecord, source) == 40, "RELR source layout");
static_assert(offsetof(RelrRecord, bitmap_bit) == 48, "RELR bit layout");
static_assert(offsetof(RelrRecord, addend_kind) == 56, "RELR addend layout");

struct RelrResult {
    std::vector<RelrRecord> records;
    RelrEncoding encoding;
    uint64_t encoded_size;
    uint64_t encoded_word_count;
    uint64_t decoded_target_count;
    RelrResult() : encoding(RelrEncoding::Standard), encoded_size(0),
        encoded_word_count(0), decoded_target_count(0) {}
};
struct RelrLimits {
    uint64_t max_records;
    uint64_t max_storage_bytes;
    RelrLimits() : max_records(1000000), max_storage_bytes(268435456) {}
};
class RelrDecodeError : public std::runtime_error {
public:
    RelrDecodeError(std::size_t byte_offset, const char* reason);
    std::size_t byte_offset() const { return byte_offset_; }
private:
    std::size_t byte_offset_;
};

// data names length immutable readable bytes throughout the call (NULL allowed
// for zero length). ELF64 little-endian only, aligned unique target profile.
// No target reads, bias, ELF binding or application. On every exception output,
// including its capacity and metadata, is unchanged. Allocation errors propagate.
void decode_relr(const uint8_t* data, std::size_t length, RelrEncoding encoding,
                 RelrResult& output, const RelrLimits& limits = RelrLimits());

} // namespace recomp
