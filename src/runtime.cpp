#include "recomp/runtime.h"

#include <algorithm>
#include <utility>
#include <cmath>
#include <cstring>
#include <stdexcept>

namespace recomp {

Memory::Memory(uint64_t base, std::size_t size) {
    map(base, size, 6, NULL, 0);
}

void Memory::map(uint64_t base, std::size_t size, uint32_t flags,
                 const uint8_t* file_data, std::size_t file_size) {
    if (file_size > size ||
        (size != 0 && size - 1 > std::numeric_limits<uint64_t>::max() - base)) {
        throw std::invalid_argument("guest memory range overflows");
    }
    if (size == 0) return;
    for (const Region& r : regions_) {
        if (base <= r.base ? r.base - base < size : base - r.base < r.bytes.size()) {
            throw std::invalid_argument("overlapping guest mappings");
        }
    }
    Region r;
    r.base = base;
    r.flags = flags;
    r.bytes.resize(size, 0);
    if (file_size) std::copy(file_data, file_data + file_size, r.bytes.begin());
    regions_.push_back(std::move(r));
}

uint32_t Memory::permissions(uint64_t address, std::size_t size) const {
    if (size && size - 1 <= UINT64_MAX - address) {
        for (const Region& r : regions_) {
            if (address < r.base || size > r.bytes.size() ||
                address - r.base > r.bytes.size() - size) continue;
            uint32_t flags = r.flags;
            for (const GuestRange& range : read_only_) {
                if (address <= range.address ? range.address - address < size :
                    address - range.address < range.size) flags &= ~2U;
            }
            return flags;
        }
    }
    throw std::out_of_range("unmapped guest memory access");
}

const Memory::Region& Memory::region(uint64_t address, std::size_t size, uint32_t required) const {
    // Validate the entire access before touching any byte. Subtractions avoid
    // overflowing either the guest address or the host size calculation.
    if (size != 0 && size - 1 <= std::numeric_limits<uint64_t>::max() - address) {
        for (const Region& r : regions_) {
            if (address >= r.base && r.bytes.size() >= size &&
                address - r.base <= r.bytes.size() - size) {
                if ((permissions(address, size) & required) != required) {
                    throw std::out_of_range("guest mapping permission denied");
                }
                return r;
            }
        }
    }
    throw std::out_of_range("unmapped guest memory access");
}

uint64_t Memory::load(uint64_t address, std::size_t size) const {
    const Region& r = region(address, size, 4);
    const std::size_t at = static_cast<std::size_t>(address - r.base);
    uint64_t value = 0;
    for (std::size_t i = 0; i < size; ++i) {
        value |= uint64_t(r.bytes[at + i]) << (i * 8);
    }
    return value;
}

void Memory::store(uint64_t address, uint64_t value, std::size_t size) {
    const Region& checked = region(address, size, 2);
    const std::size_t at = static_cast<std::size_t>(address - checked.base);
    // region() completed bounds and permission validation before any mutation.
    Region& r = regions_[static_cast<std::size_t>(&checked - regions_.data())];
    for (std::size_t i = 0; i < size; ++i) {
        r.bytes[at + i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

uint8_t Memory::load8(uint64_t address) const { return static_cast<uint8_t>(load(address, 1)); }
uint16_t Memory::load16(uint64_t address) const { return static_cast<uint16_t>(load(address, 2)); }
uint32_t Memory::load32(uint64_t address) const { return static_cast<uint32_t>(load(address, 4)); }
uint64_t Memory::load64(uint64_t address) const { return load(address, 8); }
void Memory::store8(uint64_t address, uint8_t value) { store(address, value, 1); }
void Memory::store16(uint64_t address, uint16_t value) { store(address, value, 2); }
void Memory::store32(uint64_t address, uint32_t value) { store(address, value, 4); }
void Memory::store64(uint64_t address, uint64_t value) { store(address, value, 8); }

uint32_t float_bits(float value) {
    uint32_t result;
    std::memcpy(&result, &value, sizeof(result));
    return result;
}

float bits_float(uint32_t value) {
    float result;
    std::memcpy(&result, &value, sizeof(result));
    return result;
}

uint32_t fp_mul(uint32_t a, uint32_t b) {
    return float_bits(bits_float(a) * bits_float(b));
}

uint32_t fp_madd(uint32_t a, uint32_t b, uint32_t c) {
    return float_bits(std::fma(bits_float(a), bits_float(b), bits_float(c)));
}

uint32_t fp_nmsub(uint32_t a, uint32_t b, uint32_t c) {
    return float_bits(std::fma(bits_float(a), bits_float(b), -bits_float(c)));
}

template <typename UInt>
static uint32_t subtraction_flags(UInt a, UInt b) {
    const UInt result = static_cast<UInt>(a - b);
    const UInt sign = UInt(1) << (sizeof(UInt) * 8 - 1);
    return ((result & sign) ? UINT32_C(0x80000000) : 0) |
           (result == 0 ? UINT32_C(0x40000000) : 0) |
           (a >= b ? UINT32_C(0x20000000) : 0) |
           (((a ^ b) & (a ^ result) & sign) ? UINT32_C(0x10000000) : 0);
}

uint32_t cmp_flags32(uint32_t a, uint32_t b) { return subtraction_flags(a, b); }
uint32_t cmp_flags64(uint64_t a, uint64_t b) { return subtraction_flags(a, b); }

bool condition_holds(uint32_t nzcv, uint32_t condition) {
    const bool n = (nzcv & UINT32_C(0x80000000)) != 0;
    const bool z = (nzcv & UINT32_C(0x40000000)) != 0;
    const bool c = (nzcv & UINT32_C(0x20000000)) != 0;
    const bool v = (nzcv & UINT32_C(0x10000000)) != 0;
    bool result;
    switch (condition >> 1) {
    case 0: result = z; break;
    case 1: result = c; break;
    case 2: result = n; break;
    case 3: result = v; break;
    case 4: result = c && !z; break;
    case 5: result = n == v; break;
    case 6: result = n == v && !z; break;
    default: throw std::invalid_argument("condition must be EQ through LE");
    }
    return (condition & 1) ? !result : result;
}

uint64_t sign_extend_halfword(uint16_t value, bool to_x) {
    const uint64_t extended = uint64_t(value) |
        ((value & UINT16_C(0x8000)) ? UINT64_C(0xFFFFFFFFFFFF0000) : UINT64_C(0));
    return to_x ? extended : static_cast<uint32_t>(extended);
}

} // namespace recomp
