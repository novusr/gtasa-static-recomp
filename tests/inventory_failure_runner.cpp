// Test-only allocator around the actual native CLI, including serialization.
#include <cstdlib>
#include <new>
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
#define main inventory_cli_main
#include "../tools/inventory_image.cpp"
#undef main
int main(int argc, char** argv) {
    const char* value = std::getenv("RECOMP_TEST_ALLOCATION_BUDGET");
    if (value) allocation_budget = std::strtol(value, NULL, 10);
    return inventory_cli_main(argc, argv);
}
