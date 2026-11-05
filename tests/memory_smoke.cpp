#include "recomp/runtime.h"

#include <iostream>
#include <stdexcept>

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

uint64_t load(const recomp::Memory& memory, uint64_t at, unsigned size) {
    switch (size) {
    case 1: return memory.load8(at);
    case 2: return memory.load16(at);
    case 4: return memory.load32(at);
    case 8: return memory.load64(at);
    default: throw std::invalid_argument("invalid test width");
    }
}

void store(recomp::Memory& memory, uint64_t at, uint64_t value, unsigned size) {
    switch (size) {
    case 1: memory.store8(at, static_cast<uint8_t>(value)); break;
    case 2: memory.store16(at, static_cast<uint16_t>(value)); break;
    case 4: memory.store32(at, static_cast<uint32_t>(value)); break;
    case 8: memory.store64(at, value); break;
    default: throw std::invalid_argument("invalid test width");
    }
}

void check(uint64_t base, std::size_t length) {
    recomp::Memory memory(base, length);
    const unsigned sizes[] = {1, 2, 4, 8};
    for (unsigned size : sizes) {
        for (std::size_t offset = 0; offset < length + 1; ++offset) {
            const uint64_t address = base + offset;
            for (std::size_t i = 0; i < length; ++i) memory.store8(base + i, 0xA5);
            const bool valid = offset <= length && size <= length - offset;
            bool trapped = false;
            try { store(memory, address, UINT64_C(0xFEDCBA9876543210), size); }
            catch (const std::out_of_range&) { trapped = true; }
            require(trapped != valid, "store bounds check failed");
            // Byte checks are independent of the wider load/store helpers.
            for (std::size_t i = 0; i < length; ++i) {
                const uint8_t expected = valid && i >= offset && i - offset < size
                    ? static_cast<uint8_t>(UINT64_C(0xFEDCBA9876543210) >> ((i - offset) * 8)) : 0xA5;
                require(memory.load8(base + i) == expected, "store endian/atomic bounds check failed");
            }
            trapped = false;
            try {
                const uint64_t value = load(memory, address, size);
                const uint64_t mask = size == 8 ? UINT64_MAX : (UINT64_C(1) << (size * 8)) - 1;
                require(value == (UINT64_C(0xFEDCBA9876543210) & mask), "load little-endian check failed");
            } catch (const std::out_of_range&) { trapped = true; }
            require(trapped != valid, "load bounds check failed");
        }
        bool trapped = false;
        try { load(memory, base - 1, size); }
        catch (const std::out_of_range&) { trapped = true; }
        require(trapped, "below-base load accepted");
        trapped = false;
        try { store(memory, base - 1, 0, size); }
        catch (const std::out_of_range&) { trapped = true; }
        require(trapped, "below-base store accepted");
    }
}
} // namespace

int main() {
    try {
        for (std::size_t size = 0; size <= 17; ++size) check(4096, size);
        check(UINT64_MAX - 31, 31);
        // A one-byte mapping of the final guest address is valid; a multi-byte
        // access there overflows and must fail without changing that byte.
        recomp::Memory top(UINT64_MAX, 1);
        top.store8(UINT64_MAX, 0xA5);
        for (unsigned size : {2U, 4U, 8U}) {
            bool trapped = false;
            try { store(top, UINT64_MAX, 0, size); }
            catch (const std::out_of_range&) { trapped = true; }
            require(trapped && top.load8(UINT64_MAX) == 0xA5, "overflowing store changed memory");
            trapped = false;
            try { load(top, UINT64_MAX, size); }
            catch (const std::out_of_range&) { trapped = true; }
            require(trapped, "overflowing load accepted");
        }
        recomp::Memory last_word(UINT64_MAX - 7, 8);
        last_word.store64(UINT64_MAX - 7, UINT64_C(0xFEDCBA9876543210));
        require(last_word.load64(UINT64_MAX - 7) == UINT64_C(0xFEDCBA9876543210),
                "access ending at the final guest byte failed");
        require(last_word.load8(UINT64_MAX) == 0xFE, "final guest byte endian check failed");
        bool trapped = false;
        try { recomp::Memory invalid(UINT64_MAX - 2, 4); }
        catch (const std::invalid_argument&) { trapped = true; }
        require(trapped, "overflowing mapping accepted");
        std::cout << "8/16/32/64-bit bounds, unaligned, endian and store atomicity checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
