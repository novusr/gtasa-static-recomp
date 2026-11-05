#include "recomp/elf_image.h"
#include <fstream>
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
void fault(recomp::Memory& memory, uint64_t address) {
    try { memory.load8(address); }
    catch (const std::out_of_range&) { return; }
    throw std::runtime_error("unmapped guest read succeeded");
}
}

int main(int argc, char** argv) {
    try {
        check(argc == 4 || argc == 5, "usage: recomp_image_smoke INPUT SHA256 LOAD_BIAS [MEMORY_LIMIT]");
        std::size_t used = 0;
        const std::string bias_text = argv[3];
        const uint64_t bias = std::stoull(bias_text, &used, 0);
        check(used == bias_text.size() && bias_text[0] != '-', "invalid explicit load bias");
        uint64_t limit = UINT64_C(536870912);
        if (argc == 5) limit = std::stoull(argv[4]);
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
                      << (r.has_addend ? "true" : "false") << ",\"status\":\"unresolved\"}";
        }
        std::cout << "]}\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
