#include "recomp/runtime.h"

#include <cmath>
#include <cstring>
#include <stdexcept>

namespace recomp {

Memory::Memory(uint64_t base, std::size_t size) : base_(base) {
    if (size != 0 && size - 1 > std::numeric_limits<uint64_t>::max() - base) {
        throw std::invalid_argument("guest memory range overflows");
    }
    bytes_.resize(size, 0);
}

std::size_t Memory::offset(uint64_t address, std::size_t size) const {
    // Validate the entire access before touching any byte. Subtractions avoid
    // overflowing either the guest address or the host size calculation.
    if (size == 0 || size - 1 > std::numeric_limits<uint64_t>::max() - address ||
        address < base_ || bytes_.size() < size || address - base_ > bytes_.size() - size) {
        throw std::out_of_range("unmapped guest memory access");
    }
    return static_cast<std::size_t>(address - base_);
}

uint64_t Memory::load(uint64_t address, std::size_t size) const {
    const std::size_t at = offset(address, size);
    uint64_t value = 0;
    for (std::size_t i = 0; i < size; ++i) {
        value |= uint64_t(bytes_[at + i]) << (i * 8);
    }
    return value;
}

void Memory::store(uint64_t address, uint64_t value, std::size_t size) {
    const std::size_t at = offset(address, size);
    for (std::size_t i = 0; i < size; ++i) {
        bytes_[at + i] = static_cast<uint8_t>(value >> (i * 8));
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

} // namespace recomp
