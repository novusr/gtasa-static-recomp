#include "recomp/relr.h"

#include <algorithm>
#include <limits>
#include <string>

namespace recomp {
RelrDecodeError::RelrDecodeError(std::size_t offset, const char* reason)
    : std::runtime_error(std::string("RELR byte ") + std::to_string(offset) + ": " + reason),
      byte_offset_(offset) {}

namespace {
uint64_t sum(uint64_t a, uint64_t b, std::size_t position, const char* reason) {
    if (a > UINT64_MAX - b) throw RelrDecodeError(position, reason);
    return a + b;
}

// First pass validates arithmetic and counts without allocation. Second pass
// fills exact-sized storage; no exponential reservation from encoded size.
uint64_t walk(const uint8_t* data, std::size_t length, RelrEncoding encoding,
              const RelrLimits& limits, RelrResult* pending, std::vector<uint64_t>* targets) {
    uint64_t cursor = 0, count = 0;
    bool anchored = false;
    for (std::size_t position = 0; position < length; position += 8) {
        uint64_t word = 0;
        for (unsigned i = 0; i < 8; ++i)
            word |= static_cast<uint64_t>(data[position + i]) << (8 * i);
        const bool bitmap = (word & 1) != 0;
        if (bitmap && !anchored) throw RelrDecodeError(position, "bitmap before anchor");
        if (!bitmap && word % 8) throw RelrDecodeError(position, "unaligned target");
        for (unsigned bit = bitmap ? 1 : 0; bit <= (bitmap ? 63u : 0u); ++bit) {
            if (bitmap && !(word & (UINT64_C(1) << bit))) continue;
            const uint64_t target = bitmap
                ? sum(cursor, 8 * static_cast<uint64_t>(bit - 1), position, "bitmap target overflow")
                : word;
            if (count == UINT64_MAX || count >= limits.max_records)
                throw RelrDecodeError(position, "record limit exceeded");
            if (pending) {
                const std::size_t index = static_cast<std::size_t>(count);
                const RelrRecord record = {target, count, position / 8, position, encoding,
                    bitmap ? RelrSource::Bitmap : RelrSource::Anchor, bit, RelrAddend::ImplicitTarget};
                pending->records[index] = record;
                (*targets)[index] = target;
            }
            ++count;
        }
        cursor = bitmap ? sum(cursor, 504, position, "bitmap cursor overflow")
                        : sum(word, 8, position, "anchor cursor overflow");
        anchored = true;
    }
    return count;
}
} // namespace

void decode_relr(const uint8_t* data, std::size_t length, RelrEncoding encoding,
                 RelrResult& output, const RelrLimits& limits) {
    if (encoding != RelrEncoding::Android && encoding != RelrEncoding::Standard)
        throw RelrDecodeError(0, "unknown encoding identity");
    if (length % 8) throw RelrDecodeError(length - length % 8, "partial encoded word");
    if (length && !data) throw RelrDecodeError(0, "null byte range");
    if (length > UINT64_MAX) throw RelrDecodeError(0, "input size exceeds uint64");
    const uint64_t count = walk(data, length, encoding, limits, NULL, NULL);
    // Include the temporary vector object and every address used for duplicate
    // validation, as well as tuples/provenance and result metadata. Division
    // guards precede multiplication, size_t conversion and either allocation.
    const uint64_t fixed = sizeof(RelrResult) + sizeof(std::vector<uint64_t>);
    const uint64_t stride = sizeof(RelrRecord) + sizeof(uint64_t);
    if (limits.max_storage_bytes < fixed || count > (limits.max_storage_bytes - fixed) / stride ||
        count > std::numeric_limits<std::size_t>::max() / sizeof(RelrRecord) ||
        count > std::numeric_limits<std::size_t>::max() / sizeof(uint64_t))
        throw RelrDecodeError(0, "storage limit exceeded");
    RelrResult pending;
    std::vector<uint64_t> targets;
    if (count > pending.records.max_size() || count > targets.max_size())
        throw RelrDecodeError(0, "host vector limit exceeded");
    pending.records.resize(static_cast<std::size_t>(count));
    targets.resize(static_cast<std::size_t>(count));
    walk(data, length, encoding, limits, &pending, &targets);
    std::sort(targets.begin(), targets.end());
    for (std::size_t i = 1; i < targets.size(); ++i)
        if (targets[i] == targets[i - 1])
            throw RelrDecodeError(0, "duplicate or overlapping target");
    pending.encoding = encoding;
    pending.encoded_size = static_cast<uint64_t>(length);
    pending.encoded_word_count = static_cast<uint64_t>(length / 8);
    pending.decoded_target_count = count;
    // All validation/allocation complete; publication cannot throw.
    output.records.swap(pending.records);
    output.encoding = pending.encoding;
    output.encoded_size = pending.encoded_size;
    output.encoded_word_count = pending.encoded_word_count;
    output.decoded_target_count = pending.decoded_target_count;
}
} // namespace recomp
