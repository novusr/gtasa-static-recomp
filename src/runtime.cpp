#include "recomp/runtime.h"

#include <cmath>
#include <cstring>
#include <stdexcept>

namespace recomp {

Memory::Memory(uint64_t base, std::size_t size) : base_(base), bytes_(size, 0) {
    if (size > std::numeric_limits<uint64_t>::max() - base) {
        throw std::invalid_argument("guest memory range overflows");
    }
}

std::size_t Memory::offset(uint64_t address) const {
    if (address < base_ || bytes_.size() < 4 || address - base_ > bytes_.size() - 4) {
        throw std::out_of_range("unmapped guest memory access");
    }
    return static_cast<std::size_t>(address - base_);
}

uint32_t Memory::load32(uint64_t address) const {
    const std::size_t at = offset(address);
    return uint32_t(bytes_[at]) | (uint32_t(bytes_[at + 1]) << 8)
         | (uint32_t(bytes_[at + 2]) << 16) | (uint32_t(bytes_[at + 3]) << 24);
}

void Memory::store32(uint64_t address, uint32_t value) {
    const std::size_t at = offset(address);
    for (uint32_t i = 0; i < 4; ++i) {
        bytes_[at + i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

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
