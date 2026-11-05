#include "lifted.h"

#include <iostream>
#include <stdexcept>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_cluster_attributes() {
    recomp::Memory memory(4096, 256);
    recomp::State state = {};

    // 1. cluster_get_attributes with null pointer -> returns -1 (0xFFFFFFFF in W0)
    state.x[0] = 0;
    recomp::cluster_get_attributes(state, memory);
    require(static_cast<uint32_t>(state.x[0]) == UINT32_MAX, "null cluster_get_attributes must return -1");

    // 2. cluster_get_attributes with valid pointer -> loads attr from [x0, #8]
    memory.store32(4096 + 8, UINT32_C(0xCAFE1234));
    state.x[0] = 4096;
    recomp::cluster_get_attributes(state, memory);
    require(static_cast<uint32_t>(state.x[0]) == UINT32_C(0xCAFE1234), "valid cluster_get_attributes must load attr");

    // 3. cluster_set_attributes with null pointer -> skips store
    state.x[0] = 0;
    state.x[1] = UINT32_C(0xDEADBEEF);
    recomp::cluster_set_attributes(state, memory);
    require(memory.load32(4096 + 8) == UINT32_C(0xCAFE1234), "null cluster_set_attributes must not modify memory");

    // 4. cluster_set_attributes with valid pointer -> stores attr
    state.x[0] = 4096;
    state.x[1] = UINT32_C(0xDEADBEEF);
    recomp::cluster_set_attributes(state, memory);
    require(memory.load32(4096 + 8) == UINT32_C(0xDEADBEEF), "valid cluster_set_attributes must modify memory");
}

void test_ped_atomic_visibility() {
    recomp::Memory memory(4096, 256);
    recomp::State state = {};
    memory.store8(4096 + 2, 0xFF);

    // 1. w1 != 0 -> fallthrough to ret, memory untouched
    state.x[0] = 4096;
    state.x[1] = 1;
    recomp::ped_atomic_visibility(state, memory);
    require(memory.load8(4096 + 2) == 0xFF, "ped_atomic_visibility with w1 != 0 must not clear visibility");

    // 2. w1 with dirty upper bits but low 32 bits == 0 -> CBZ taken, stores 0
    state.x[0] = 4096;
    state.x[1] = UINT64_C(0x1234567800000000);
    recomp::ped_atomic_visibility(state, memory);
    require(memory.load8(4096 + 2) == 0, "ped_atomic_visibility with dirty upper bits must take branch and clear byte");
}

void test_reduce_horn_counter() {
    recomp::Memory memory(4096, 2048);
    recomp::State state = {};
    const uint64_t counter_addr = 4096 + 1700;

    // 1. Counter is 0 -> unchanged
    memory.store32(counter_addr, 0);
    state.x[0] = 4096;
    recomp::reduce_horn_counter(state, memory);
    require(memory.load32(counter_addr) == 0, "zero horn counter must remain 0");

    // 2. Counter is 10 -> decremented to 9
    memory.store32(counter_addr, 10);
    state.x[0] = 4096;
    recomp::reduce_horn_counter(state, memory);
    require(memory.load32(counter_addr) == 9, "horn counter must decrement by 1");
}

void test_get_active_task() {
    recomp::Memory memory(4096, 256);
    recomp::State state = {};

    // Tasks at offsets 0, 8, 16, 24, 32
    memory.store64(4096 + 0, 0);
    memory.store64(4096 + 8, 0);
    memory.store64(4096 + 16, UINT64_C(0xAAAA0000));
    memory.store64(4096 + 24, UINT64_C(0xBBBB0000));
    memory.store64(4096 + 32, UINT64_C(0xCCCC0000));

    // First non-null is task 2 (at offset 16)
    state.x[0] = 4096;
    recomp::get_active_task(state, memory);
    require(state.x[0] == UINT64_C(0xAAAA0000), "get_active_task must return first active task");

    // All null except task 4 (offset 32)
    memory.store64(4096 + 16, 0);
    memory.store64(4096 + 24, 0);
    state.x[0] = 4096;
    recomp::get_active_task(state, memory);
    require(state.x[0] == UINT64_C(0xCCCC0000), "get_active_task must fall back to default task");
}

} // namespace

int main() {
    try {
        test_cluster_attributes();
        test_ped_atomic_visibility();
        test_reduce_horn_counter();
        test_get_active_task();
        std::cout << "All lifted control-flow smoke tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "control_flow_smoke error: " << error.what() << '\n';
        return 1;
    }
}
