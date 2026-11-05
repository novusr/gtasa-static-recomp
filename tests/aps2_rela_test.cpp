#include "recomp/aps2_rela.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <new>
#include <string>

// Exercise the real default allocator without adding a production test hook.
static long allocation_budget = -1;
void* operator new(std::size_t size) {
    if (allocation_budget == 0) throw std::bad_alloc();
    if (allocation_budget > 0) --allocation_budget;
    void* pointer = std::malloc(size ? size : 1);
    if (!pointer) throw std::bad_alloc();
    return pointer;
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete[](void* pointer) noexcept { std::free(pointer); }

namespace {
using recomp::Aps2RelaResult;
using recomp::Aps2RelaLimits;
typedef std::vector<uint8_t> Bytes;
unsigned checks = 0;
void check(bool condition) {
    ++checks;
    if (!condition) throw std::runtime_error("APS2 test check " + std::to_string(checks));
}
Bytes stream(std::initializer_list<uint8_t> body) {
    Bytes bytes = {'A', 'P', 'S', '2'};
    bytes.insert(bytes.end(), body);
    return bytes;
}
Aps2RelaResult decode(const Bytes& bytes, const Aps2RelaLimits& limits = Aps2RelaLimits()) {
    Aps2RelaResult result;
    recomp::decode_android_aps2_rela(bytes.data(), bytes.size(), result, limits);
    return result;
}
void tuple(const Aps2RelaResult& result, std::size_t index,
           uint64_t offset, uint64_t info, int64_t addend) {
    check(index < result.records.size());
    const recomp::Aps2RelaRecord& r = result.records[index];
    check(r.offset == offset && r.info == info && r.addend == addend);
    check(r.symbol_index() == (info >> 32) && r.type() == (info & UINT32_MAX));
    check(r.ordinal == index);
}
void equal(const Aps2RelaResult& a, const Aps2RelaResult& b) {
    check(a.initial_offset == b.initial_offset && a.encoded_size == b.encoded_size &&
          a.group_count == b.group_count && a.records.size() == b.records.size());
    for (std::size_t i = 0; i < a.records.size(); ++i)
        check(std::memcmp(&a.records[i], &b.records[i], sizeof(a.records[i])) == 0);
}
Aps2RelaResult sentinel() { return decode(stream({1, 9, 1, 0, 2, 3})); }
void reject(const Bytes& bytes, const Aps2RelaLimits& limits = Aps2RelaLimits(),
            const char* reason = NULL) {
    Aps2RelaResult output = sentinel();
    const Aps2RelaResult saved = output;
    const recomp::Aps2RelaRecord* address = output.records.data();
    const std::size_t capacity = output.records.capacity();
    bool failed = false;
    try { recomp::decode_android_aps2_rela(bytes.data(), bytes.size(), output, limits); }
    catch (const recomp::Aps2DecodeError& error) {
        failed = true;
        check(error.byte_offset() <= bytes.size());
        if (reason) check(std::string(error.what()).find(reason) != std::string::npos);
    }
    check(failed);
    equal(output, saved);
    check(output.records.data() == address && output.records.capacity() == capacity);
    Aps2RelaResult absent;
    try { recomp::decode_android_aps2_rela(bytes.data(), bytes.size(), absent, limits); }
    catch (const recomp::Aps2DecodeError&) {}
    check(absent.records.empty() && absent.encoded_size == 0 && absent.initial_offset == 0 &&
          absent.group_count == 0);
}

void flags_and_provenance() {
    // All 12 valid flags. Literal field order is independent of the decoder;
    // every stream expands to offsets 12,14 and infos 3,3. No encoder is used.
    const Bytes cases[] = {
        stream({2,10, 2,0, 2,3, 2,3}),
        stream({2,10, 2,1, 3, 2,2}),
        stream({2,10, 2,2, 2, 3,3}),
        stream({2,10, 2,3, 2,3}),
        stream({2,10, 2,8, 2,3,5, 2,3,0}),
        stream({2,10, 2,9, 3, 2,5, 2,0}),
        stream({2,10, 2,10, 2, 3,5, 3,0}),
        stream({2,10, 2,11, 2,3, 5,0}),
        stream({2,10, 2,12, 5, 2,3, 2,3}),
        stream({2,10, 2,13, 3,5, 2,2}),
        stream({2,10, 2,14, 2,5, 3,3}),
        stream({2,10, 2,15, 2,3,5})
    };
    const unsigned flags[] = {0,1,2,3,8,9,10,11,12,13,14,15};
    const uint64_t header_end[] = {8,9,9,10,8,9,9,10,9,10,10,11};
    const uint64_t stride[] = {2,1,1,0,3,2,2,1,2,1,1,0};
    for (unsigned i = 0; i < 12; ++i) {
        const Aps2RelaResult r = decode(cases[i]);
        check(r.initial_offset == 10 && r.encoded_size == cases[i].size() && r.group_count == 1);
        check(r.records.size() == 2);
        tuple(r, 0, 12, 3, i < 4 ? 0 : 5);
        tuple(r, 1, 14, 3, i < 4 ? 0 : 5);
        for (unsigned j = 0; j < 2; ++j) {
            const recomp::Aps2RelaRecord& row = r.records[j];
            check(row.flags == flags[i] && row.group_ordinal == 0 && row.group_begin == 6 &&
                  row.group_header_end == header_end[i] && row.group_end == cases[i].size());
            check(row.entry_begin == header_end[i] + j * stride[i] &&
                  row.entry_end == header_end[i] + (j + 1) * stride[i]);
        }
    }
    // Addend carries across groups; grouped +3 applied once to previous 7;
    // missing addends reset to zero; subsequent ungrouped -2 starts from zero.
    const Aps2RelaResult r = decode(stream({7,20,
        2,8, 4,1,5, 0x7e,2,2,
        2,15, 0x7f,3,3,
        2,3, 2,4,
        1,11, 0x7c,5,0x7e}));
    check(r.records.size() == 7 && r.group_count == 4);
    tuple(r,0,24,1,5); tuple(r,1,22,2,7);
    tuple(r,2,21,3,10); tuple(r,3,20,3,10);
    tuple(r,4,22,4,0); tuple(r,5,24,4,0); tuple(r,6,20,5,-2);
    check(r.records[2].group_begin == 14 && r.records[2].group_header_end == 19 &&
          r.records[2].group_end == 19 && r.records[2].group_ordinal == 1);
    check(r.records[6].group_begin == 23 && r.records[6].group_end == 28 &&
          r.records[6].group_ordinal == 3);
    // Explicit encoded zero addend and omitted addend both mean RELA zero.
    tuple(decode(stream({1,0,1,8,0,0,0})),0,0,0,0);
}

void integers_and_empty() {
    const Aps2RelaResult empty = decode(stream({0,0}));
    check(empty.records.empty() && empty.group_count == 0 && empty.encoded_size == 6);
    check(decode(stream({0,7})).initial_offset == 7); // Pure stream, no orphan-section policy.
    // Valid nonminimal values, including ten-byte 0 and -1 in raw info.
    tuple(decode(stream({0x81,0,0x80,0,0x81,0,0x80,0,0x80,0,0xff,0x7f})),
          0,0,UINT64_MAX,0);
    tuple(decode(stream({1,0,1,0, 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f})),0,0,UINT64_MAX,0);
    tuple(decode(stream({1,0,1,15,0,0x7f,0})),0,0,UINT64_MAX,0);
    check(decode(stream({0,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0})).initial_offset == INT64_MAX);
    // INT64_MIN raw info must keep bit 63; no signed cast loses it.
    tuple(decode(stream({1,0,1,0,0,
        0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x7f})),
        0,0,UINT64_C(0x8000000000000000),0);
    tuple(decode(stream({1,0,1,0,0,0xc5,0x80,0x80,0x80,0x20})),
          0,0,UINT64_C(0x200000045),0);
    // Offset reaches UINT64_MAX, then moves back by INT64_MIN's magnitude.
    const Aps2RelaResult r = decode(stream({4,0,
        2,3, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0, 1,
        1,3, 1,2,
        1,3, 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x7f,3}));
    tuple(r,0,INT64_MAX,1,0); tuple(r,1,UINT64_MAX-1,1,0);
    tuple(r,2,UINT64_MAX,2,0); tuple(r,3,INT64_MAX,3,0);
    // Signed addend limits and safe crossing via -INT64_MAX / +INT64_MAX.
    const Aps2RelaResult a = decode(stream({4,0,4,11,0,1,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0,
        0x81,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x7f,
        0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x7f,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0}));
    tuple(a,0,0,1,INT64_MAX); tuple(a,1,0,1,0);
    tuple(a,2,0,1,INT64_MIN); tuple(a,3,0,1,-1);
}

void malformed() {
    reject(Bytes()); reject(Bytes({'A','P','S'}));
    Bytes wrong = stream({0,0}); wrong[3] = '1'; reject(wrong);
    wrong[0] = 'X'; reject(wrong);
    // Every truncation of a nonempty stream must fail, including after a
    // complete earlier group, and leave a populated sentinel unchanged.
    const Bytes complete = stream({3,10, 1,15,2,3,5, 2,8,1,2,1,1,3,0});
    for (std::size_t n = 0; n < complete.size(); ++n)
        reject(Bytes(complete.begin(), complete.begin() + n));
    check(decode(complete).records.size() == 3);
    reject(stream({0x7f,0})); reject(stream({0,0x7f}));
    reject(stream({1,0,0,0})); reject(stream({1,0,0x7f,0}));
    reject(stream({1,0,2,3,0,0})); reject(stream({2,0,1,3,0,0}));
    for (uint8_t flag : {4,5,6,7,16,64,127}) reject(stream({1,0,1,flag}));
    reject(stream({0,0,0}), Aps2RelaLimits(), "trailing bytes");
    reject(stream({1,0,1,3,0,0,0}), Aps2RelaLimits(), "trailing bytes");
    reject(stream({1,0,1,0,0x7f,0}), Aps2RelaLimits(), "offset underflow");
    reject(stream({3,1,3,3,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0,0}),
        Aps2RelaLimits(), "offset overflow");
    reject(stream({2,0,2,11,0,0,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0,1}),
        Aps2RelaLimits(), "addend overflow");
    reject(stream({2,0,2,11,0,0,
        0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x7f,0x7f}),
        Aps2RelaLimits(), "addend overflow");
    // Overflow on entry to the second grouped-addend group.
    reject(stream({2,0,1,15,0,0,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0, 1,15,0,0,1}),
        Aps2RelaLimits(), "addend overflow");
    // Invalid terminal bits: positive or negative outside signed 64 bits.
    for (uint8_t terminal : {1,2,0x7e,0x40,0x80,0xff}) {
        Bytes bad = stream({1,0,1,0,0});
        bad.insert(bad.end(),9,0x80); bad.push_back(terminal);
        reject(bad, Aps2RelaLimits(), "SLEB128 exceeds signed 64 bits");
    }
    Bytes long_value = stream({1,0,1,0,0});
    long_value.insert(long_value.end(),10,0x80); long_value.push_back(0);
    reject(long_value);
    Bytes truncated = stream({1,0,1,0,0});
    truncated.insert(truncated.end(),9,0x80); reject(truncated);
    Aps2RelaResult output = sentinel(); const Aps2RelaResult saved = output;
    try { recomp::decode_android_aps2_rela(NULL, 6, output); check(false); }
    catch (const recomp::Aps2DecodeError&) {}
    equal(output,saved);
}

void limits_and_allocations() {
    const Bytes two = stream({2,0,2,3,0,0});
    Aps2RelaLimits limits;
    limits.max_records = 2;
    limits.max_storage_bytes = sizeof(Aps2RelaResult) + 2 * sizeof(recomp::Aps2RelaRecord);
    check(decode(two,limits).records.size() == 2);
    --limits.max_storage_bytes; reject(two,limits,"storage limit exceeded");
    ++limits.max_storage_bytes; limits.max_records = 1; reject(two,limits,"record limit exceeded");
    limits.max_records = 0;
    check(decode(stream({0,0}),limits).records.empty());
    limits.max_storage_bytes = sizeof(Aps2RelaResult)-1;
    reject(stream({0,0}),limits,"storage limit exceeded");
    // A tiny fully grouped stream expands to a million zero tuples. One over
    // the default ceiling must reject before allocation, not silently clamp.
    const Bytes million = stream({0xc0,0x84,0x3d,0,0xc0,0x84,0x3d,3,0,0});
    const Aps2RelaResult expanded = decode(million);
    check(expanded.records.size() == 1000000);
    tuple(expanded,999999,0,0,0);
    reject(stream({0xc1,0x84,0x3d,0,0xc1,0x84,0x3d,3,0,0}),
           Aps2RelaLimits(),"record limit exceeded");
    // Raised count ceiling still cannot overflow storage multiplication or
    // size_t. This count would overflow count*sizeof(record) at 64 bits.
    limits.max_records = UINT64_MAX; limits.max_storage_bytes = UINT64_MAX;
    reject(stream({0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0,0}),
           limits,"storage limit exceeded");
    Aps2RelaResult output = sentinel(); const Aps2RelaResult saved = output;
    const recomp::Aps2RelaRecord* address = output.records.data();
    const std::size_t capacity = output.records.capacity();
    unsigned failures = 0;
    for (long budget = 0; budget < 10; ++budget) {
        bool failed = false;
        allocation_budget = budget;
        try { recomp::decode_android_aps2_rela(two.data(),two.size(),output); }
        catch (const std::bad_alloc&) { failed = true; }
        allocation_budget = -1;
        if (!failed) break;
        ++failures; equal(output,saved);
        check(output.records.data() == address && output.records.capacity() == capacity);
    }
    check(failures > 0 && output.records.size() == 2 && output.initial_offset == 0);
    // An allocation failure while constructing a late validation error must
    // also preserve output (not only the record allocation itself).
    Bytes late = two; late.push_back(0);
    output = sentinel(); const Aps2RelaResult late_saved = output;
    unsigned oom = 0; bool validation = false;
    for (long budget = 0; budget < 16; ++budget) {
        allocation_budget = budget;
        try { recomp::decode_android_aps2_rela(late.data(),late.size(),output); }
        catch (const std::bad_alloc&) { ++oom; }
        catch (const recomp::Aps2DecodeError&) { validation = true; }
        allocation_budget = -1;
        equal(output,late_saved);
        if (validation) break;
    }
    check(oom > 1 && validation);
    // Successful empty decode replaces previous output and metadata.
    const Bytes empty = stream({0,0});
    recomp::decode_android_aps2_rela(empty.data(),empty.size(),output);
    check(output.records.empty() && output.initial_offset == 0 &&
          output.group_count == 0 && output.encoded_size == 6);
}
} // namespace

int main() {
    try {
        flags_and_provenance(); integers_and_empty(); malformed(); limits_and_allocations();
        std::cout << "APS2 RELA data-only checks passed: " << checks << '\n';
        return 0;
    } catch (const std::exception& error) {
        allocation_budget = -1;
        std::cerr << error.what() << '\n';
        return 1;
    }
}
