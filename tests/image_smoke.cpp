#include "recomp/elf_image.h"
#include <fstream>
#include <vector>
#include <utility>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
std::string quote(const std::string& s) {
    const char* hex = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { result += '\\'; result += char(c); }
        else if (c < 32 || c >= 127) {
            result += "\\u00"; result += hex[c >> 4]; result += hex[c & 15];
        } else result += char(c);
    }
    return result + '"';
}
void symbol_json(const recomp::ImageSymbol& s) {
    std::cout << "{\"name\":" << quote(s.name) << ",\"table_section\":" << s.table_section
              << ",\"table_type\":" << s.table_type << ",\"index\":" << s.index
              << ",\"value\":" << s.value << ",\"size\":" << s.size
              << ",\"section_index\":" << s.section_index << ",\"binding\":" << unsigned(s.binding)
              << ",\"type\":" << unsigned(s.type) << ",\"visibility\":" << unsigned(s.visibility)
              << ",\"other\":" << unsigned(s.other) << ",\"resolution_reason\":"
              << quote(s.resolution_reason) << '}';
}
void fault(recomp::Memory& memory, uint64_t address) {
    try { memory.load8(address); }
    catch (const std::out_of_range&) { return; }
    throw std::runtime_error("unmapped guest read succeeded");
}
void apply_checked(recomp::ElfImage& image, unsigned phase) {
    std::vector<std::pair<uint64_t, std::vector<uint8_t> > > before;
    for (const recomp::ImageSegment& segment : image.segments()) {
        if (!(segment.flags & 4)) continue;
        std::vector<uint8_t> bytes;
        for (uint64_t i = 0; i < segment.memory_size; ++i)
            bytes.push_back(image.memory().load8(segment.address + i));
        before.push_back(std::make_pair(segment.address, bytes));
    }
    const std::vector<recomp::ImageRelocation> applied = image.applied_relocations();
    const std::vector<recomp::ImageRelocation> pending = image.unresolved_relocations();
    try {
        if (phase == 0) image.apply_relative_relocations();
        else if (phase == 1) image.apply_symbol_relocations();
        else image.apply_relocations();
    } catch (...) {
        for (const auto& snapshot : before)
            for (std::size_t i = 0; i < snapshot.second.size(); ++i)
                check(image.memory().load8(snapshot.first + i) == snapshot.second[i],
                      "partial relocation mutation");
        check(image.applied_relocations().size() == applied.size() &&
              image.unresolved_relocations().size() == pending.size(), "partial relocation status change");
        for (std::size_t i = 0; i < pending.size(); ++i)
            check(image.unresolved_relocations()[i].address == pending[i].address &&
                  image.unresolved_relocations()[i].unresolved_reason == pending[i].unresolved_reason,
                  "partial unresolved inventory change");
        for (std::size_t i = 0; i < applied.size(); ++i)
            check(image.applied_relocations()[i].address == applied[i].address &&
                  image.applied_relocations()[i].type == applied[i].type,
                  "partial applied inventory change");
        // A failed transaction must not mark its phase complete: retry must fail
        // again on unchanged input, rather than silently skipping pending work.
        bool rejected_again = false;
        try {
            if (phase == 0) image.apply_relative_relocations();
            else if (phase == 1) image.apply_symbol_relocations();
            else image.apply_relocations();
        } catch (const std::exception&) { rejected_again = true; }
        check(rejected_again, "failed relocation phase incorrectly completed");
        throw;
    }
}
void relocate(recomp::ElfImage& image, const std::string& mode) {
    struct Snapshot { uint64_t base; std::vector<uint8_t> bytes; };
    std::vector<Snapshot> before;
    for (const recomp::ImageSegment& s : image.segments()) {
        if (!(s.flags & 4)) continue;
        Snapshot snapshot;
        snapshot.base = s.address;
        for (uint64_t i = 0; i < s.memory_size; ++i)
            snapshot.bytes.push_back(image.memory().load8(s.address + i));
        before.push_back(snapshot);
    }
    if (mode == "--relocate") apply_checked(image, 0);
    else if (mode == "--symbols") apply_checked(image, 1);
    else if (mode == "--relative-symbols") {
        apply_checked(image, 0);
        apply_checked(image, 1);
    } else if (mode == "--symbols-relative") {
        apply_checked(image, 1);
        apply_checked(image, 0);
    } else apply_checked(image, 2);
    // Independent sign/magnitude arithmetic, rather than the loader's raw-bit sum.
    for (const recomp::ImageRelocation& r : image.applied_relocations()) {
        const uint64_t base = r.type == 1027 ? image.load_bias() :
            r.definition.value + (r.definition.section_index == 0xfff1 ? 0 : image.load_bias());
        const uint64_t expected = (r.addend_bits >> 63) ?
            base - (~r.addend_bits + 1) : base + r.addend_bits;
        check(image.memory().load64(r.address) == expected, "relocated pointer mismatch");
        for (unsigned i = 0; i < 8; ++i) {
            check(image.memory().load8(r.address + i) == uint8_t(expected >> (8 * i)),
                  "relocated little-endian byte mismatch");
            for (Snapshot& snapshot : before)
                if (r.address + i >= snapshot.base &&
                    r.address + i - snapshot.base < snapshot.bytes.size())
                    snapshot.bytes[static_cast<std::size_t>(r.address + i - snapshot.base)] =
                        uint8_t(expected >> (8 * i));
        }
    }
    const std::size_t applied = image.applied_relocations().size();
    const std::size_t unresolved = image.unresolved_relocations().size();
    if (mode == "--relocate") image.apply_relative_relocations();
    else if (mode == "--symbols") image.apply_symbol_relocations();
    else {
        image.apply_relocations();
        image.apply_symbol_relocations();
        image.apply_relative_relocations();
    }
    check(image.applied_relocations().size() == applied &&
          image.unresolved_relocations().size() == unresolved, "reapplication changed status");
    // Check all readable bytes after both applications, including untouched data.
    for (const Snapshot& s : before)
        for (std::size_t i = 0; i < s.bytes.size(); ++i)
            check(image.memory().load8(s.base + i) == s.bytes[i], "unexpected relocation mutation");
    check(!image.ready_to_execute(), "relocated image reported executable readiness");
}

}

int main(int argc, char** argv) {
    try {
        check(argc == 4 || argc == 5 || argc == 6, "usage: recomp_image_smoke INPUT SHA256 LOAD_BIAS [MEMORY_LIMIT [--relocate|--symbols|--all]]");
        std::size_t used = 0;
        const std::string bias_text = argv[3];
        const uint64_t bias = std::stoull(bias_text, &used, 0);
        check(used == bias_text.size() && bias_text[0] != '-', "invalid explicit load bias");
        uint64_t limit = UINT64_C(536870912);
        if (argc >= 5) limit = std::stoull(argv[4]);
        recomp::ElfImage image = recomp::ElfImage::load(argv[1], argv[2], bias, limit);
        check(!image.ready_to_execute(), "data image reported executable readiness");
        std::ifstream file(argv[1], std::ios::binary);
        uint64_t copied = 0, bss = 0;
        for (const recomp::ImageSegment& s : image.segments()) {
            if (!(s.flags & 4)) continue;
            file.seekg(static_cast<std::streamoff>(s.file_offset));
            for (uint64_t i = 0; i < s.file_size; ++i) {
                const int byte = file.get();
                check(byte >= 0 && image.memory().load8(s.address + i) == byte, "file-backed byte mismatch");
                ++copied;
            }
            for (uint64_t i = s.file_size; i < s.memory_size; ++i) {
                check(image.memory().load8(s.address + i) == 0, "nonzero BSS byte");
                ++bss;
            }
            if (s.memory_size) {
                if (s.flags & 2) {
                    const uint8_t before = image.memory().load8(s.address);
                    image.memory().store8(s.address, uint8_t(before ^ 255));
                    check(image.memory().load8(s.address) == uint8_t(before ^ 255), "guest store failed");
                    image.memory().store8(s.address, before);
                } else {
                    bool denied = false;
                    try { image.memory().store8(s.address, 0); }
                    catch (const std::out_of_range&) { denied = true; }
                    check(denied, "write to read-only ELF mapping succeeded");
                }
                // A full-width store crossing a boundary must leave its first byte intact.
                const uint64_t last = s.address + s.memory_size - 1;
                const uint8_t before = image.memory().load8(last);
                bool denied = false;
                try { image.memory().store16(last, 0x1234); }
                catch (const std::out_of_range&) { denied = true; }
                check(denied && image.memory().load8(last) == before, "boundary store was not atomic");
            }
        }
        // Probe exact holes, below mappings, and immediately beyond mappings.
        for (const recomp::ImageSegment& s : image.segments()) {
            const uint64_t candidates[] = {s.address ? s.address - 1 : UINT64_MAX,
                                           s.address + s.memory_size};
            for (uint64_t address : candidates) {
                bool mapped = false;
                for (const recomp::ImageSegment& other : image.segments())
                    if (address >= other.address && address - other.address < other.memory_size) mapped = true;
                if (!mapped) fault(image.memory(), address);
            }
        }
        if (argc == 6) {
            const std::string mode = argv[5];
            check(mode == "--relocate" || mode == "--symbols" || mode == "--all" ||
                  mode == "--relative-symbols" || mode == "--symbols-relative", "unknown image operation");
            relocate(image, mode);
        }
        std::cout << "{\"sha256\":" << quote(image.sha256()) << ",\"load_bias\":" << bias
                  << ",\"ready_to_execute\":false,\"file_bytes_checked\":" << copied
                  << ",\"bss_bytes_checked\":" << bss << ",\"segments\":" << image.segments().size()
                  << ",\"needed_libraries\":[";
        bool first = true;
        for (const std::string& name : image.needed_libraries()) {
            if (!first) std::cout << ',';
            first = false;
            std::cout << quote(name);
        }
        std::cout << "],\"imports\":[";
        first = true;
        for (const recomp::ImageImport& i : image.unresolved_imports()) {
            if (!first) std::cout << ',';
            first = false;
            std::cout << "{\"symbol\":" << quote(i.name) << ",\"symbol_index\":" << i.symbol_index
                      << ",\"binding\":" << unsigned(i.binding) << ",\"type\":" << unsigned(i.type)
                      << ",\"status\":\"unresolved\"}";
        }
        std::cout << "],\"relocations\":[";
        first = true;
        for (const recomp::ImageRelocation& r : image.unresolved_relocations()) {
            if (!first) std::cout << ',';
            first = false;
            std::cout << "{\"address\":" << r.address << ",\"type\":" << r.type
                      << ",\"symbol_index\":" << r.symbol_index << ",\"symbol\":" << quote(r.symbol)
                      << ",\"addend_bits\":" << r.addend_bits << ",\"has_addend\":"
                      << (r.has_addend ? "true" : "false") << ",\"status\":\"unresolved\",\"reason\":"
                      << quote(r.unresolved_reason) << ",\"definition\":";
            symbol_json(r.definition);
            std::cout << '}';
        }
        std::cout << "],\"applied_relocations\":[";
        first = true;
        for (const recomp::ImageRelocation& r : image.applied_relocations()) {
            if (!first) std::cout << ',';
            first = false;
            std::cout << "{\"address\":" << r.address << ",\"type\":" << r.type
                      << ",\"addend_bits\":" << r.addend_bits
                      << ",\"value\":" << image.memory().load64(r.address)
                      << ",\"status\":\"applied\",\"bytes\":[";
            for (unsigned i = 0; i < 8; ++i) {
                if (i) std::cout << ',';
                std::cout << unsigned(image.memory().load8(r.address + i));
            }
            std::cout << "],\"definition\":";
            symbol_json(r.definition);
            std::cout << '}';
        }
        std::cout << "]}\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
