#include "recomp/aps2_rela.h"

#include <limits>
#include <string>

namespace recomp {

Aps2DecodeError::Aps2DecodeError(std::size_t offset, const char* reason)
    : std::runtime_error(std::string("APS2 byte ") + std::to_string(offset) + ": " + reason),
      byte_offset_(offset) {}

namespace {

// Interpret a two's-complement bit pattern without an implementation-defined
// unsigned-to-signed conversion, signed shifts or negating INT64_MIN.
int64_t signed_bits(uint64_t bits) {
    if (bits <= static_cast<uint64_t>(INT64_MAX)) return static_cast<int64_t>(bits);
    return -1 - static_cast<int64_t>(~bits);
}

struct Reader {
    const uint8_t* data;
    std::size_t length;
    std::size_t cursor;
    uint64_t sleb() {
        const std::size_t begin = cursor;
        uint64_t bits = 0;
        for (unsigned i = 0; i < 10; ++i) {
            if (cursor == length) throw Aps2DecodeError(cursor, "truncated SLEB128");
            const uint8_t byte = data[cursor++];
            const uint8_t payload = byte & 0x7f;
            if (i == 9) {
                // Only bit 63 remains. All six excess bits must extend it.
                if ((byte & 0x80) || (payload != 0 && payload != 0x7f))
                    throw Aps2DecodeError(begin, "SLEB128 exceeds signed 64 bits");
                bits |= static_cast<uint64_t>(payload & 1) << 63;
                return bits;
            }
            const unsigned shift = i * 7;
            bits |= static_cast<uint64_t>(payload) << shift;
            if (!(byte & 0x80)) {
                if (byte & 0x40) bits |= UINT64_MAX << (shift + 7);
                return bits;
            }
        }
        throw Aps2DecodeError(begin, "invalid SLEB128");
    }
    uint64_t nonnegative(const char* reason) {
        const std::size_t begin = cursor;
        const uint64_t bits = sleb();
        if (bits > static_cast<uint64_t>(INT64_MAX)) throw Aps2DecodeError(begin, reason);
        return bits;
    }
};

uint64_t offset_sum(uint64_t offset, int64_t delta, std::size_t position) {
    if (delta >= 0) {
        const uint64_t magnitude = static_cast<uint64_t>(delta);
        if (offset > UINT64_MAX - magnitude)
            throw Aps2DecodeError(position, "offset overflow");
        return offset + magnitude;
    }
    const uint64_t magnitude = UINT64_C(0) - static_cast<uint64_t>(delta);
    if (offset < magnitude) throw Aps2DecodeError(position, "offset underflow");
    return offset - magnitude;
}

int64_t addend_sum(int64_t addend, int64_t delta, std::size_t position) {
    if ((delta > 0 && addend > INT64_MAX - delta) ||
        (delta < 0 && addend < INT64_MIN - delta))
        throw Aps2DecodeError(position, "addend overflow");
    return addend + delta;
}

} // namespace

void decode_android_aps2_rela(const uint8_t* data, std::size_t length,
                              Aps2RelaResult& output, const Aps2RelaLimits& limits) {
    if (!data || length < 4) throw Aps2DecodeError(0, "missing APS2 signature");
    if (data[0] != 'A' || data[1] != 'P' || data[2] != 'S' || data[3] != '2')
        throw Aps2DecodeError(0, "wrong APS2 signature");
    Reader reader = {data, length, 4};
    const uint64_t count = reader.nonnegative("negative record count");
    // Division checks precede multiplication, conversion and allocation. One
    // exact-sized vector stores both tuples and provenance; no per-group heap.
    if (count > limits.max_records)
        throw Aps2DecodeError(4, "record limit exceeded");
    if (limits.max_storage_bytes < sizeof(Aps2RelaResult) ||
        count > (limits.max_storage_bytes - sizeof(Aps2RelaResult)) / sizeof(Aps2RelaRecord) ||
        count > std::numeric_limits<std::size_t>::max() / sizeof(Aps2RelaRecord))
        throw Aps2DecodeError(4, "storage limit exceeded");
    Aps2RelaResult pending;
    if (count > pending.records.max_size()) throw Aps2DecodeError(4, "host vector limit exceeded");
    pending.initial_offset = reader.nonnegative("negative initial offset");
    pending.encoded_size = length;
    pending.records.resize(static_cast<std::size_t>(count));
    uint64_t offset = pending.initial_offset;
    int64_t addend = 0;
    uint64_t ordinal = 0;
    while (ordinal < count) {
        const std::size_t group_begin = reader.cursor;
        const uint64_t size = reader.nonnegative("negative group size");
        if (!size || size > count - ordinal)
            throw Aps2DecodeError(group_begin, "group size exceeds remaining count or is zero");
        const std::size_t flags_begin = reader.cursor;
        const uint64_t flags = reader.nonnegative("negative group flags");
        if ((flags & ~UINT64_C(15)) || ((flags & 4) && !(flags & 8)))
            throw Aps2DecodeError(flags_begin, "invalid group flags");
        int64_t grouped_delta = 0;
        uint64_t grouped_info = 0;
        if (flags & 2) grouped_delta = signed_bits(reader.sleb());
        if (flags & 1) grouped_info = reader.sleb();
        if (!(flags & 8)) addend = 0;
        else if (flags & 4) {
            const std::size_t position = reader.cursor;
            addend = addend_sum(addend, signed_bits(reader.sleb()), position);
        }
        const std::size_t header_end = reader.cursor;
        const uint64_t first = ordinal;
        for (uint64_t i = 0; i < size; ++i, ++ordinal) {
            const std::size_t entry_begin = reader.cursor;
            const int64_t delta = (flags & 2) ? grouped_delta : signed_bits(reader.sleb());
            offset = offset_sum(offset, delta, (flags & 2) ? group_begin : entry_begin);
            const uint64_t info = (flags & 1) ? grouped_info : reader.sleb();
            if ((flags & 12) == 8) {
                const std::size_t position = reader.cursor;
                addend = addend_sum(addend, signed_bits(reader.sleb()), position);
            }
            Aps2RelaRecord record = {offset, info, addend, ordinal, pending.group_count,
                group_begin, header_end, 0, entry_begin, reader.cursor, flags};
            pending.records[static_cast<std::size_t>(ordinal)] = record;
        }
        for (uint64_t i = first; i < ordinal; ++i)
            pending.records[static_cast<std::size_t>(i)].group_end = reader.cursor;
        ++pending.group_count;
    }
    if (reader.cursor != length) throw Aps2DecodeError(reader.cursor, "trailing bytes");
    // All validation and allocation is complete. Default-allocator vector swap
    // and scalar assignments cannot throw; previous output is destroyed locally.
    output.records.swap(pending.records);
    output.initial_offset = pending.initial_offset;
    output.encoded_size = pending.encoded_size;
    output.group_count = pending.group_count;
}

} // namespace recomp
