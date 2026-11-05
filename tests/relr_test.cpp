#include "recomp/relr.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <new>
#include <string>

static long allocation_budget = -1;
void* operator new(std::size_t size) {
    if (allocation_budget == 0) throw std::bad_alloc();
    if (allocation_budget > 0) --allocation_budget;
    void* p = std::malloc(size ? size : 1);
    if (!p) throw std::bad_alloc();
    return p;
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }

namespace {
using namespace recomp;
typedef std::vector<uint8_t> Bytes;
unsigned checks = 0;
void check(bool condition) {
    ++checks;
    if (!condition) throw std::runtime_error("RELR test check " + std::to_string(checks));
}
// Byte serialization only; expected targets below are specified independently.
Bytes words(std::initializer_list<uint64_t> values) {
    Bytes b;
    for (uint64_t value : values)
        for (unsigned i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>(value >> (8*i)));
    return b;
}
RelrResult decode(const Bytes& b, const RelrLimits& limits = RelrLimits(),
                  RelrEncoding encoding = RelrEncoding::Standard) {
    RelrResult r; decode_relr(b.data(),b.size(),encoding,r,limits); return r;
}
void equal(const RelrResult& a, const RelrResult& b) {
    check(a.encoding == b.encoding && a.encoded_size == b.encoded_size &&
          a.encoded_word_count == b.encoded_word_count &&
          a.decoded_target_count == b.decoded_target_count && a.records.size() == b.records.size());
    for (std::size_t i = 0; i < a.records.size(); ++i)
        check(std::memcmp(&a.records[i], &b.records[i], sizeof(RelrRecord)) == 0);
}
void expected(const Bytes& b, std::initializer_list<uint64_t> targets) {
    const RelrResult r = decode(b);
    check(r.records.size() == targets.size() && r.decoded_target_count == targets.size());
    check(r.encoded_size == b.size() && r.encoded_word_count == b.size()/8);
    std::size_t i = 0;
    for (uint64_t address : targets) {
        const RelrRecord& row = r.records[i];
        check(row.offset == address && row.ordinal == i &&
              row.encoding == RelrEncoding::Standard && row.addend_kind == RelrAddend::ImplicitTarget);
        ++i;
    }
}
RelrResult sentinel() { return decode(words({0x800,3}),RelrLimits(),RelrEncoding::Android); }
void reject(const Bytes& b, const char* reason, const RelrLimits& limits = RelrLimits()) {
    for (unsigned empty = 0; empty < 2; ++empty) {
        RelrResult out = empty ? RelrResult() : sentinel();
        const RelrResult saved = out;
        const RelrRecord* address = out.records.data();
        const std::size_t capacity = out.records.capacity();
        bool failed = false;
        try { decode_relr(b.data(), b.size(), RelrEncoding::Standard, out, limits); }
        catch (const RelrDecodeError& e) {
            failed = true;
            check(e.byte_offset() <= b.size());
            check(std::string(e.what()).find(reason) != std::string::npos);
        }
        check(failed); equal(out,saved);
        check(out.records.data() == address && out.records.capacity() == capacity);
    }
}
void positives() {
    expected(Bytes(),{}); expected(words({0}),{0});
    expected(words({0x1000}),{0x1000});
    expected(words({0x1000,3}),{0x1000,0x1008});
    expected(words({0x1000,UINT64_C(0x8000000000000001)}),{0x1000,0x11f8});
    expected(words({0x1000,UINT64_C(0x800000000000000b)}),{0x1000,0x1008,0x1018,0x11f8});
    expected(words({0x1000,1,3}),{0x1000,0x1200});
    expected(words({0x1000,3,3,0x800,5}),{0x1000,0x1008,0x1200,0x800,0x810});
    expected(words({0x1000,1,1}),{0x1000});
    expected(words({0x1000,0x800,0}),{0x1000,0x800,0}); // Backward anchors allowed.
    const Bytes dense = words({0x1000,UINT64_MAX});
    const RelrResult r = decode(dense);
    check(r.records.size() == 64);
    for (unsigned i = 0; i < 64; ++i) {
        check(r.records[i].offset == 0x1000 + 8*i);
        check(r.records[i].ordinal == i);
        check(r.records[i].word_index == (i ? 1u : 0u));
        check(r.records[i].byte_offset == (i ? 8u : 0u));
        check(r.records[i].bitmap_bit == i);
        check(r.records[i].source == (i ? RelrSource::Bitmap : RelrSource::Anchor));
    }
    const RelrResult android = decode(dense,RelrLimits(),RelrEncoding::Android);
    check(android.encoding == RelrEncoding::Android && r.encoding == RelrEncoding::Standard);
    for (unsigned i = 0; i < 64; ++i) {
        check(android.records[i].offset == r.records[i].offset);
        check(android.records[i].encoding == RelrEncoding::Android);
    }
    const RelrResult provenance = decode(words({0x1000,1,3,0x800,5}));
    check(provenance.records[1].word_index == 2 && provenance.records[1].byte_offset == 16 &&
          provenance.records[1].bitmap_bit == 1 && provenance.records[1].ordinal == 1);
    check(provenance.records[2].word_index == 3 && provenance.records[2].source == RelrSource::Anchor &&
          provenance.records[2].bitmap_bit == 0);
    check(provenance.records[3].word_index == 4 && provenance.records[3].bitmap_bit == 2);
    // Explicit little endian bytes; unaligned host byte buffer is allowed.
    Bytes bytes = {0xff,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01};
    RelrResult unaligned;
    decode_relr(bytes.data()+1,8,RelrEncoding::Android,unaligned);
    check(unaligned.records[0].offset == UINT64_C(0x0102030405060708));
    expected(words({UINT64_MAX-15}),{UINT64_MAX-15});
    expected(words({UINT64_MAX-519,UINT64_C(0x8000000000000001)}),
             {UINT64_MAX-519,UINT64_MAX-15}); // Cursor reaches last aligned VA.
    expected(words({UINT64_MAX-519,1}),{UINT64_MAX-519});
    RelrResult out = sentinel();
    decode_relr(NULL,0,RelrEncoding::Android,out);
    check(out.records.empty() && out.encoding == RelrEncoding::Android && !out.encoded_size &&
          !out.encoded_word_count && !out.decoded_target_count);
}
void malformed() {
    reject(words({1}),"bitmap before anchor"); reject(words({3,0x1000}),"bitmap before anchor");
    for (unsigned i = 1; i < 8; ++i) reject(Bytes(i,0),"partial encoded word");
    for (uint64_t address : {2,4,6}) reject(words({address}),"unaligned");
    reject(words({0x1000,0x1000}),"duplicate");
    reject(words({0x1000,3,0x1008}),"duplicate");
    reject(words({0x1000,3,0x1000,3}),"duplicate");
    reject(words({0x1000,0x1002}),"unaligned"); // Partial slot overlap fails alignment.
    reject(words({UINT64_MAX-7}),"anchor cursor overflow");
    reject(words({UINT64_MAX-15,UINT64_C(0x8000000000000001)}),"bitmap target overflow");
    reject(words({UINT64_MAX-15,3}),"bitmap cursor overflow");
    reject(words({UINT64_MAX-15,1}),"bitmap cursor overflow");
    reject(words({UINT64_MAX-519,1,1}),"bitmap cursor overflow");
    reject(words({0x1000,3,0x2002}),"unaligned");
    RelrResult out = sentinel(); const RelrResult saved = out;
    try { decode_relr(NULL,8,RelrEncoding::Standard,out); check(false); }
    catch (const RelrDecodeError&) {} equal(out,saved);
    try { decode_relr(NULL,0,static_cast<RelrEncoding>(99),out); check(false); }
    catch (const RelrDecodeError&) {} equal(out,saved);
}
void limits_and_allocations() {
    const Bytes dense = words({0x1000,UINT64_MAX});
    RelrLimits limits;
    limits.max_records = 64;
    limits.max_storage_bytes = sizeof(RelrResult)+sizeof(std::vector<uint64_t>)+64*(sizeof(RelrRecord)+8);
    check(decode(dense,limits).records.size() == 64);
    --limits.max_storage_bytes; reject(dense,"storage limit",limits);
    ++limits.max_storage_bytes; limits.max_records = 63; reject(dense,"record limit",limits);
    limits.max_records = 0;
    check(decode(Bytes(),limits).records.empty()); reject(words({0}),"record limit",limits);
    limits.max_storage_bytes = sizeof(RelrResult)+sizeof(std::vector<uint64_t>)-1;
    reject(Bytes(),"storage limit",limits);
    limits.max_records = UINT64_MAX; limits.max_storage_bytes = UINT64_MAX;
    check(decode(dense,limits).records.size() == 64);
    // Small encoded payload exceeds the default record ceiling by expansion.
    Bytes bomb = words({0});
    const Bytes bitmap = words({UINT64_MAX});
    for (unsigned i = 0; i < 15874; ++i) bomb.insert(bomb.end(),bitmap.begin(),bitmap.end());
    reject(bomb,"record limit");
    // Exhaust every allocation on success and late duplicate-error paths,
    // starting with both populated and absent outputs. Production has no hook.
    for (unsigned empty = 0; empty < 2; ++empty) {
        for (unsigned late = 0; late < 2; ++late) {
            const Bytes input = late ? words({0x1000,3,0x1008}) : dense;
            RelrResult out = empty ? RelrResult() : sentinel();
            const RelrResult saved = out;
            const RelrRecord* pointer = out.records.data();
            const std::size_t capacity = out.records.capacity();
            bool completed = false; unsigned failures = 0;
            for (long budget = 0; budget < 20; ++budget) {
                bool oom = false, invalid = false;
                allocation_budget = budget;
                try { decode_relr(input.data(),input.size(),RelrEncoding::Standard,out); }
                catch (const std::bad_alloc&) { oom = true; }
                catch (const RelrDecodeError&) { invalid = true; }
                allocation_budget = -1;
                if (oom || invalid) {
                    equal(out,saved);
                    check(out.records.data() == pointer && out.records.capacity() == capacity);
                }
                if (oom) ++failures;
                else { check(invalid == (late != 0)); completed = true; break; }
            }
            check(completed && failures >= (late ? 3u : 2u));
        }
    }
}
}
int main() {
    try {
        positives(); malformed(); limits_and_allocations();
        std::cout << "RELR data-only checks passed: " << checks << '\n';
    } catch (const std::exception& error) {
        allocation_budget = -1; std::cerr << error.what() << '\n'; return 1;
    }
}
