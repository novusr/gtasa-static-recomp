#include "recomp/elf_image.h"
#include <cstdlib>
#include <iostream>
#include <memory>
#include <new>
#include <stdexcept>

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

static void check(bool condition) {
    if (!condition) throw std::runtime_error("inventory atomicity check failed");
}
int main(int argc, char** argv) {
    try {
        if (argc != 5) return 1;
        const std::string path(argv[1]), hash(argv[2]);
        recomp::ElfImage sentinel = recomp::ElfImage::load_inventory_only(path, hash, 0);
        const recomp::InventoryTable* address = sentinel.relocation_inventory().tables.data();
        const std::size_t capacity = sentinel.relocation_inventory().tables.capacity();
        const uint64_t storage = sentinel.relocation_inventory().accounted_storage_bytes;
        // No permissions on targets: successful inventory proves no implicit read.
        // Snapshot readable source mapping and metadata to check guard atomicity.
        const uint64_t bytes = sentinel.memory().load64(0x4000);
        const uint32_t permissions = sentinel.memory().permissions(0x8000, 8);
        for (unsigned api = 0; api < 4; ++api) {
            bool rejected = false;
            try {
                if (api == 0) sentinel.apply_relative_relocations();
                if (api == 1) sentinel.apply_symbol_relocations();
                if (api == 2) sentinel.apply_relocations();
                if (api == 3) sentinel.seal_relro(4096);
            } catch (const std::invalid_argument&) { rejected = true; }
            check(rejected && sentinel.applied_relocations().empty() &&
                sentinel.unresolved_relocations().empty() && !sentinel.relro_sealed() &&
                sentinel.sealed_relro_ranges().empty() && !sentinel.ready_to_execute() &&
                sentinel.memory().permissions(0x8000, 8) == permissions &&
                sentinel.memory().load64(0x4000) == bytes);
        }
        unsigned failures = 0;
        for (unsigned absent = 0; absent < 2; ++absent) {
            bool completed = false;
            for (long budget = 0; budget < 1024; ++budget) {
                std::unique_ptr<recomp::ElfImage> result;
                if (!absent) result.reset(new recomp::ElfImage(sentinel));
                const recomp::ElfImage* previous = result.get();
                const recomp::InventoryTable* old_tables = result ? result->relocation_inventory().tables.data() : NULL;
                allocation_budget = budget;
                bool failed = false;
                try {
                    std::unique_ptr<recomp::ElfImage> pending(new recomp::ElfImage(
                        recomp::ElfImage::load_inventory_only(path, hash, 0)));
                    result.swap(pending);
                } catch (const std::exception&) { failed = true; }
                allocation_budget = -1;
                if (!failed) { completed = true; break; }
                ++failures;
                check(result.get() == previous);
                if (result) check(result->relocation_inventory().tables.data() == old_tables &&
                    result->relocation_inventory().decoded_count == 4 && !result->relro_sealed());
                check(sentinel.relocation_inventory().tables.data() == address &&
                    sentinel.relocation_inventory().tables.capacity() == capacity &&
                    sentinel.relocation_inventory().accounted_storage_bytes == storage &&
                    sentinel.memory().load64(0x4000) == bytes);
            }
            check(completed);
        }
        // Repeat allocation injection while the last ordinary table is invalid.
        // Neither a previous object nor an absent destination can be published.
        const std::string bad_path(argv[3]), bad_hash(argv[4]);
        for (unsigned absent = 0; absent < 2; ++absent) {
            bool reached_late_error = false;
            for (long budget = 0; budget < 1024; ++budget) {
                std::unique_ptr<recomp::ElfImage> result;
                if (!absent) result.reset(new recomp::ElfImage(sentinel));
                const recomp::ElfImage* previous = result.get();
                allocation_budget = budget;
                bool failed = false;
                try {
                    std::unique_ptr<recomp::ElfImage> pending(new recomp::ElfImage(
                        recomp::ElfImage::load_inventory_only(bad_path, bad_hash, 0)));
                    result.swap(pending);
                } catch (const std::exception& e) {
                    allocation_budget = -1;
                    failed = true;
                    reached_late_error = std::string(e.what()).find("ordinary symbol index") != std::string::npos;
                }
                allocation_budget = -1;
                check(failed && result.get() == previous);
                if (result) check(result->relocation_inventory().decoded_count == 4 &&
                    !result->relro_sealed() && result->memory().load64(0x4000) == bytes);
                if (reached_late_error) break;
            }
            check(reached_late_error);
        }
        check(failures > 10);
        std::cout << "inventory application guards and " << failures << " injected allocation failures passed\n";
        return 0;
    } catch (const std::exception& e) {
        allocation_budget = -1;
        std::cerr << e.what() << '\n'; return 1;
    }
}
