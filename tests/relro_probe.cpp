#include "recomp/elf_image.h"
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <iostream>

// Fail each allocation in sealing, without changing production allocation paths.
static long allocation_budget = -1;
void* operator new(std::size_t size) {
    if (allocation_budget == 0) throw std::bad_alloc();
    if (allocation_budget > 0) --allocation_budget;
    void* result = std::malloc(size ? size : 1);
    if (!result) throw std::bad_alloc();
    return result;
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete[](void* pointer) noexcept { std::free(pointer); }

static void check(bool value) {
    if (!value) throw std::runtime_error("RELRO probe assertion failed");
}
struct Byte { uint64_t address; uint32_t flags; uint8_t value; };
static std::vector<Byte> snapshot(const recomp::ElfImage& image) {
    std::vector<Byte> result;
    for (const recomp::ImageSegment& segment : image.segments())
        for (uint64_t i = 0; i < segment.memory_size; ++i) {
            Byte b = {segment.address + i, image.memory().permissions(segment.address + i), 0};
            if (b.flags & 4) b.value = image.memory().load8(b.address);
            result.push_back(b);
        }
    return result;
}
static void unchanged(const recomp::ElfImage& image, const std::vector<Byte>& bytes) {
    for (const Byte& b : bytes) {
        check(image.memory().permissions(b.address) == b.flags);
        if (b.flags & 4) check(image.memory().load8(b.address) == b.value);
    }
}
static void store(recomp::Memory& m, uint64_t a, unsigned width, uint64_t v) {
    if (width == 1) m.store8(a, static_cast<uint8_t>(v));
    else if (width == 2) m.store16(a, static_cast<uint16_t>(v));
    else if (width == 4) m.store32(a, static_cast<uint32_t>(v));
    else m.store64(a, v);
}
int main(int argc, char** argv) {
    try {
        if (argc != 6) return 1;
        recomp::ElfImage image = recomp::ElfImage::load(argv[1], argv[2], std::stoull(argv[3], NULL, 0));
        const uint64_t page = std::stoull(argv[4], NULL, 0);
        const std::string mode = argv[5];
        check(!image.relro_sealed() && image.relro_page_size() == 0);
        if (mode == "after") image.apply_relocations();
        if (mode == "relative-first") image.apply_relative_relocations();
        const std::vector<Byte> before = snapshot(image);
        const std::size_t pending = image.unresolved_relocations().size();
        const std::size_t applied = image.applied_relocations().size();
        const std::size_t imports = image.unresolved_imports().size();
        if (mode == "failure") {
            for (unsigned retry = 0; retry < 2; ++retry) {
                bool failed = false;
                try { image.seal_relro(page); }
                catch (const std::exception&) { failed = true; }
                check(failed && !image.relro_sealed() && image.relro_page_size() == 0 &&
                      image.sealed_relro_ranges().empty());
                unchanged(image, before);
                check(image.unresolved_relocations().size() == pending &&
                      image.applied_relocations().size() == applied);
            }
            return 0;
        }
        if (mode == "oom") {
            unsigned failures = 0;
            for (long budget = 0; ; ++budget) {
                bool failed = false;
                allocation_budget = budget;
                try { image.seal_relro(page); }
                catch (const std::bad_alloc&) { failed = true; }
                allocation_budget = -1;
                if (!failed) break;
                ++failures;
                check(!image.relro_sealed() && image.relro_page_size() == 0 &&
                      image.sealed_relro_ranges().empty());
                unchanged(image, before);
                check(image.unresolved_relocations().size() == pending &&
                      image.applied_relocations().size() == applied);
            }
            check(failures > 0);
        } else image.seal_relro(page);
        check(image.relro_sealed() && image.relro_page_size() == page);
        image.seal_relro(page);
        check(image.unresolved_relocations().size() == pending &&
              image.applied_relocations().size() == applied && image.unresolved_imports().size() == imports);
        // Independently compute rounded protection for every mapped byte.
        for (const Byte& b : before) {
            uint32_t expected = b.flags;
            for (const recomp::ImageSegment& r : image.relro_segments()) {
                const uint64_t lo = r.virtual_address / page * page + image.load_bias();
                const uint64_t hi = ((r.virtual_address + r.memory_size - 1) / page + 1) * page + image.load_bias();
                if (b.address >= lo && b.address < hi) expected &= ~2U;
            }
            check(image.memory().permissions(b.address) == expected);
            if (b.flags & 4) check(image.memory().load8(b.address) == b.value);
            else {
                bool denied = false;
                try { image.memory().load8(b.address); }
                catch (const std::out_of_range&) { denied = true; }
                check(denied);
            }
        }
        if (mode == "relative-first") image.apply_relative_relocations();
        const std::vector<Byte> sealed = snapshot(image);
        // Check every width/offset, both sides of every permission boundary and
        // original mapping boundary. Failed writes preserve every readable byte.
        for (const Byte& b : sealed) {
            for (unsigned width : {1U, 2U, 4U, 8U}) {
                bool expected = false;
                try { expected = (image.memory().permissions(b.address, width) & 2) != 0; }
                catch (const std::out_of_range&) {}
                // Reads crossing an overlay edge remain valid inside the same
                // original readable mapping; adjacent mappings still reject.
                bool readable = false;
                try { readable = (image.memory().permissions(b.address, width) & 4) != 0; }
                catch (const std::out_of_range&) {}
                bool read_denied = false;
                uint64_t read_value = 0;
                try {
                    if (width == 1) read_value = image.memory().load8(b.address);
                    else if (width == 2) read_value = image.memory().load16(b.address);
                    else if (width == 4) read_value = image.memory().load32(b.address);
                    else read_value = image.memory().load64(b.address);
                } catch (const std::out_of_range&) { read_denied = true; }
                check(read_denied != readable);
                if (readable) {
                    uint64_t wanted = 0;
                    for (unsigned i = 0; i < width; ++i)
                        wanted |= uint64_t(image.memory().load8(b.address + i)) << (8 * i);
                    check(read_value == wanted);
                }
                uint64_t old = 0;
                if (expected && (b.flags & 4))
                    for (unsigned i = 0; i < width; ++i)
                        old |= uint64_t(image.memory().load8(b.address + i)) << (8 * i);
                bool denied = false;
                try { store(image.memory(), b.address, width, UINT64_MAX); }
                catch (const std::out_of_range&) { denied = true; }
                check(denied != expected);
                if (expected && (b.flags & 4)) store(image.memory(), b.address, width, old);
                unchanged(image, sealed);
            }
        }
        bool should_fail = false;
        for (const recomp::ImageRelocation& r : image.unresolved_relocations())
            if (r.unresolved_reason == "relative_not_applied" ||
                r.unresolved_reason == "internal_symbol_not_applied")
                if (!(image.memory().permissions(r.address, 8) & 2)) should_fail = true;
        bool failed = false;
        try { image.apply_relocations(); }
        catch (const std::exception&) { failed = true; }
        check(failed == should_fail);
        if (failed) {
            unchanged(image, sealed);
            check(image.unresolved_relocations().size() == pending &&
                  image.applied_relocations().size() == applied);
            bool retried = false;
            try { image.apply_relocations(); }
            catch (const std::exception&) { retried = true; }
            check(retried);
        } else image.apply_relocations();
        // Different geometry must not silently replace an already committed seal.
        const std::vector<Byte> committed = snapshot(image);
        bool denied = false;
        try { image.seal_relro(page == 1 ? 2 : 1); }
        catch (const std::invalid_argument&) { denied = true; }
        check(denied && image.relro_page_size() == page && !image.ready_to_execute());
        unchanged(image, committed);
        return 0;
    } catch (const std::exception& error) {
        allocation_budget = -1;
        std::cerr << error.what() << '\n';
        return 1;
    }
}
