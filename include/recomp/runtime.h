#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace recomp {

// Scalar leaf subset only: s[] contains the low 32 bits of each FP register.
// Full SIMD lanes, FPCR/FPSR, flags and control flow require an extended backend.
struct State {
    uint64_t x[31];
    uint64_t sp;
    uint32_t s[32];
};
static_assert(sizeof(State) == 0x180, "Invalid State size");
static_assert(offsetof(State, x) == 0, "Invalid State::x offset");
static_assert(offsetof(State, sp) == 0xF8, "Invalid State::sp offset");
static_assert(offsetof(State, s) == 0x100, "Invalid State::s offset");
static_assert(sizeof(float) == 4 && std::numeric_limits<float>::is_iec559,
              "The scalar runtime requires IEEE-754 binary32");

struct GuestRange {
    uint64_t address;
    uint64_t size;
};
static_assert(sizeof(GuestRange) == 16, "Invalid GuestRange size");
static_assert(offsetof(GuestRange, address) == 0, "Invalid GuestRange::address offset");
static_assert(offsetof(GuestRange, size) == 8, "Invalid GuestRange::size offset");

// Checked guest storage. The sandbox constructor retains its original flat range.
// ELF mappings remain separate; gaps and segment permissions are enforced.
class Memory {
public:
    Memory(uint64_t base, std::size_t size);
    // Full accesses must remain within one original mapping. RELRO only removes W.
    uint32_t permissions(uint64_t address, std::size_t size = 1) const;
    uint8_t load8(uint64_t address) const;
    uint16_t load16(uint64_t address) const;
    uint32_t load32(uint64_t address) const;
    uint64_t load64(uint64_t address) const;
    void store8(uint64_t address, uint8_t value);
    void store16(uint64_t address, uint16_t value);
    void store32(uint64_t address, uint32_t value);
    void store64(uint64_t address, uint64_t value);
private:
    friend class ElfImage;
    struct Region {
        uint64_t base;
        uint32_t flags;
        std::vector<uint8_t> bytes;
    };
    void map(uint64_t base, std::size_t size, uint32_t flags,
             const uint8_t* file_data, std::size_t file_size);
    const Region& region(uint64_t address, std::size_t size, uint32_t required) const;
    uint64_t load(uint64_t address, std::size_t size) const;
    void store(uint64_t address, uint64_t value, std::size_t size);
    std::vector<Region> regions_;
    std::vector<GuestRange> read_only_;
};

uint32_t float_bits(float value);
float bits_float(uint32_t value);
uint32_t fp_mul(uint32_t a, uint32_t b);
uint32_t fp_madd(uint32_t a, uint32_t b, uint32_t c);
uint32_t fp_nmsub(uint32_t a, uint32_t b, uint32_t c);

} // namespace recomp
