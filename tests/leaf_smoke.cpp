#include "lifted.h"

#include <cfenv>
#include <cmath>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void put(recomp::Memory& memory, uint64_t at, float value) {
    memory.store32(at, recomp::float_bits(value));
}

// Deterministic integer-valued binary32 inputs, shared with the ARM oracle test.
float sample(uint32_t& seed) {
    seed = seed * UINT32_C(1664525) + UINT32_C(1013904223);
    return static_cast<float>(static_cast<int32_t>((seed >> 16) % 201) - 100);
}

void check_memory() {
    recomp::Memory memory(4096, 8);
    memory.store32(4097, UINT32_C(0x12345678));
    require(memory.load32(4097) == UINT32_C(0x12345678), "unaligned guest memory roundtrip failed");
    const uint64_t bad[] = {4095, 4101, UINT64_MAX};
    for (uint64_t at : bad) {
        bool trapped = false;
        try { memory.load32(at); } catch (const std::out_of_range&) { trapped = true; }
        require(trapped, "out-of-bounds guest read did not trap");
        trapped = false;
        try { memory.store32(at, 0); } catch (const std::out_of_range&) { trapped = true; }
        require(trapped, "out-of-bounds guest write did not trap");
    }
    bool trapped = false;
    try { recomp::Memory invalid(UINT64_MAX - 2, 8); }
    catch (const std::invalid_argument&) { trapped = true; }
    require(trapped, "overflowing guest memory range was accepted");
}

} // namespace

int main(int argc, char** argv) {
    try {
        const bool vectors = argc == 2 && std::string(argv[1]) == "--vectors";
        if (argc != 1 && !vectors) {
            throw std::invalid_argument("usage: recomp_leaf_smoke [--vectors]");
        }
        require(std::fegetround() == FE_TONEAREST, "leaf demo requires round-to-nearest FP mode");
        check_memory();
        uint32_t seed = 1;
        for (uint32_t trial = 0; trial < 1024; ++trial) {
            recomp::Memory memory(4096, 256);
            float a[3], b[3], matrix[9];
            for (uint32_t i = 0; i < 3; ++i) {
                a[i] = sample(seed);
                b[i] = sample(seed);
                put(memory, 4096 + i * 4, a[i]);
                put(memory, 4128 + i * 4, b[i]);
            }
            recomp::State state = {};
            state.x[0] = 4096;
            state.x[1] = 4128;
            recomp::cross_product(state, memory);
            const float expected[3] = {
                std::fma(a[1], b[2], -(a[2] * b[1])),
                std::fma(a[2], b[0], -(a[0] * b[2])),
                std::fma(a[0], b[1], -(a[1] * b[0]))
            };
            for (uint32_t i = 0; i < 3; ++i) {
                require(state.s[i] == recomp::float_bits(expected[i]), "cross product semantics failed");
                if (vectors) { std::cout << state.s[i] << ' '; }
            }
            for (uint32_t i = 0; i < 9; ++i) {
                matrix[i] = sample(seed);
                put(memory, 4160 + (i / 3) * 16 + (i % 3) * 4, matrix[i]);
            }
            state = recomp::State{};
            state.x[0] = 4160;
            state.x[1] = 4128;
            recomp::multiply3x3(state, memory);
            for (uint32_t i = 0; i < 3; ++i) {
                const float result = std::fma(matrix[6 + i], b[2],
                    std::fma(matrix[i], b[0], matrix[3 + i] * b[1]));
                require(state.s[i] == recomp::float_bits(result), "matrix multiply semantics failed");
                if (vectors) { std::cout << state.s[i] << (i == 2 ? '\n' : ' '); }
            }
        }
        if (!vectors) { std::cout << "2048 lifted leaf calls passed; guest memory bounds passed\n"; }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
