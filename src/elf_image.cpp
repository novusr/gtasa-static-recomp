#include "recomp/elf_image.h"

#include <openssl/evp.h>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <utility>
#include <sstream>
#include <stdexcept>

namespace recomp {
namespace {

void require(bool valid, const char* message) {
    if (!valid) throw std::invalid_argument(message);
}

uint64_t add(uint64_t a, uint64_t b) {
    require(b <= UINT64_MAX - a, "ELF address/size overflow");
    return a + b;
}

struct Reader {
    std::vector<uint8_t> bytes;
    void range(uint64_t offset, uint64_t size) const {
        require(offset <= bytes.size() && size <= bytes.size() - offset, "truncated ELF range");
    }
    uint64_t word(uint64_t offset, unsigned size) const {
        range(offset, size);
        uint64_t result = 0;
        for (unsigned i = 0; i < size; ++i) result |= uint64_t(bytes[offset + i]) << (8 * i);
        return result;
    }
};

struct Section {
    uint32_t type;
    uint64_t address;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint64_t entry_size;
};

std::string string_at(const Reader& r, const Section& s, uint64_t offset) {
    require(s.type == 3 && offset < s.size, "invalid ELF string reference");
    const uint64_t start = s.offset + offset;
    uint64_t end = start;
    while (end - s.offset < s.size && r.bytes[end]) ++end;
    require(end - s.offset < s.size, "unterminated ELF string");
    return std::string(r.bytes.begin() + start, r.bytes.begin() + end);
}

const Section& linked(const std::vector<Section>& sections, const Section& s) {
    require(s.link < sections.size(), "invalid ELF section link");
    return sections[s.link];
}

void entries(const Section& s, uint64_t size) {
    require(s.entry_size == size && s.size % size == 0, "invalid ELF table entry size");
}

std::string symbol_name(const Reader& r, const std::vector<Section>& sections,
                        const Section& symbols, uint32_t index) {
    require(symbols.type == 2 || symbols.type == 11, "invalid ELF symbol table");
    entries(symbols, 24);
    require(index < symbols.size / 24, "invalid ELF relocation symbol index");
    return string_at(r, linked(sections, symbols), r.word(symbols.offset + uint64_t(index) * 24, 4));
}

} // namespace

ElfImage ElfImage::load(const std::string& path, const std::string& expected_sha256,
                        uint64_t load_bias, uint64_t memory_limit) {
    require(expected_sha256.size() == 64 &&
            expected_sha256.find_first_not_of("0123456789abcdef") == std::string::npos,
            "expected SHA-256 must be 64 lowercase hexadecimal characters");
    std::ifstream input(path.c_str(), std::ios::binary | std::ios::ate);
    require(bool(input), "cannot open ELF input");
    const std::streamoff length = input.tellg();
    // Bound file ingestion as well as total guest allocation, including sparse images.
    require(length >= 64 && uint64_t(length) <= UINT64_C(536870912) &&
            uint64_t(length) <= std::numeric_limits<std::size_t>::max(), "invalid ELF input size");
    Reader r;
    r.bytes.resize(static_cast<std::size_t>(length));
    input.seekg(0);
    input.read(reinterpret_cast<char*>(r.bytes.data()), length);
    require(bool(input), "cannot read complete ELF input");
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned digest_size = 0;
    require(EVP_Digest(r.bytes.data(), r.bytes.size(), digest, &digest_size, EVP_sha256(), NULL) == 1 &&
            digest_size == 32, "SHA-256 failed");
    std::ostringstream hash;
    for (unsigned i = 0; i < digest_size; ++i)
        hash << std::hex << std::setfill('0') << std::setw(2) << unsigned(digest[i]);
    require(hash.str() == expected_sha256, "ELF SHA-256 mismatch");

    require(r.word(0, 4) == 0x464c457f && r.word(4, 1) == 2 &&
            r.word(5, 1) == 1 && r.word(6, 1) == 1 && r.word(16, 2) == 3 &&
            r.word(18, 2) == 183 && r.word(20, 4) == 1 && r.word(52, 2) == 64,
            "input must be a little-endian AArch64 ELF64 ET_DYN");
    const uint64_t phoff = r.word(32, 8), shoff = r.word(40, 8);
    const uint64_t phnum = r.word(56, 2), shnum = r.word(60, 2);
    require(phnum && phnum != 65535 && r.word(54, 2) == 56, "unsupported ELF program header table");
    r.range(phoff, phnum * 56);
    // Section inventories are mandatory for this bounded loader. Stripped or
    // extended-numbering files must not silently produce empty import reports.
    require(shoff && shnum && r.word(58, 2) == 64, "ELF section inventory required");
    r.range(shoff, shnum * 64);

    ElfImage image;
    image.bias_ = load_bias;
    image.sha256_ = hash.str();
    uint64_t allocated = 0;
    std::vector<std::pair<uint64_t, uint64_t> > dynamic_ranges;
    for (uint64_t i = 0; i < phnum; ++i) {
        const uint64_t p = phoff + i * 56;
        const uint64_t kind = r.word(p, 4);
        if (kind == 2) { // PT_DYNAMIC must have a complete section inventory.
            const uint64_t offset = r.word(p + 8, 8), size = r.word(p + 32, 8);
            r.range(offset, size);
            dynamic_ranges.push_back(std::make_pair(offset, size));
        }
        if (kind != 1) continue;
        ImageSegment s;
        s.flags = static_cast<uint32_t>(r.word(p + 4, 4));
        s.file_offset = r.word(p + 8, 8);
        s.virtual_address = r.word(p + 16, 8);
        s.file_size = r.word(p + 32, 8);
        s.memory_size = r.word(p + 40, 8);
        s.alignment = r.word(p + 48, 8);
        require(s.file_size <= s.memory_size, "ELF filesz exceeds memsz");
        r.range(s.file_offset, s.file_size);
        require(s.alignment <= 1 ||
                ((s.alignment & (s.alignment - 1)) == 0 &&
                 s.virtual_address % s.alignment == s.file_offset % s.alignment &&
                 load_bias % s.alignment == 0), "invalid ELF segment alignment or load bias");
        require((s.flags & ~7U) == 0, "unsupported ELF segment flags");
        // Reject overflowing exclusive ends, even for empty segments.
        add(s.virtual_address, s.memory_size);
        s.address = add(s.virtual_address, load_bias);
        add(s.address, s.memory_size);
        allocated = add(allocated, s.memory_size);
        require(allocated <= memory_limit && s.memory_size <= std::numeric_limits<std::size_t>::max(),
                "ELF guest allocation limit exceeded");
        for (const ImageSegment& old : image.segments_) {
            require(!s.memory_size || !old.memory_size ||
                    s.address >= old.address + old.memory_size ||
                    old.address >= s.address + s.memory_size, "overlapping ELF PT_LOAD ranges");
        }
        image.segments_.push_back(s);
    }
    require(!image.segments_.empty() && allocated, "ELF has no nonempty PT_LOAD");

    std::vector<Section> sections;
    for (uint64_t i = 0; i < shnum; ++i) {
        const uint64_t p = shoff + i * 64;
        Section s;
        s.type = static_cast<uint32_t>(r.word(p + 4, 4));
        s.address = r.word(p + 16, 8);
        s.offset = r.word(p + 24, 8);
        s.size = r.word(p + 32, 8);
        s.link = static_cast<uint32_t>(r.word(p + 40, 4));
        s.entry_size = r.word(p + 56, 8);
        if (s.type != 8) r.range(s.offset, s.size); // SHT_NOBITS has no file bytes.
        sections.push_back(s);
    }
    require(sections[0].type == 0, "invalid ELF null section");
    for (const std::pair<uint64_t, uint64_t>& range : dynamic_ranges) {
        bool found = false;
        for (const Section& s : sections)
            if (s.type == 6 && s.offset == range.first && s.size == range.second) found = true;
        require(found, "PT_DYNAMIC missing matching section inventory");
    }
    for (const Section& s : sections) {
        if (s.type == 11) { // SHT_DYNSYM: every named undefined symbol stays unresolved.
            entries(s, 24);
            for (uint64_t i = 0; i < s.size / 24; ++i) {
                const uint64_t p = s.offset + i * 24;
                const std::string name = symbol_name(r, sections, s, static_cast<uint32_t>(i));
                if (r.word(p + 6, 2) == 0 && !name.empty()) {
                    ImageImport entry;
                    entry.name = name;
                    entry.symbol_index = static_cast<uint32_t>(i);
                    const uint8_t info = static_cast<uint8_t>(r.word(p + 4, 1));
                    entry.binding = info >> 4;
                    entry.type = info & 15;
                    image.imports_.push_back(entry);
                }
            }
        } else if (s.type == 4 || s.type == 9) { // SHT_RELA / SHT_REL, initially unresolved.
            const uint64_t stride = s.type == 4 ? 24 : 16;
            entries(s, stride);
            const Section& symbols = linked(sections, s);
            for (uint64_t p = s.offset; p < s.offset + s.size; p += stride) {
                ImageRelocation entry;
                entry.address = add(r.word(p, 8), load_bias);
                const uint64_t info = r.word(p + 8, 8);
                entry.type = static_cast<uint32_t>(info);
                entry.symbol_index = static_cast<uint32_t>(info >> 32);
                entry.symbol = symbol_name(r, sections, symbols, entry.symbol_index);
                entry.has_addend = s.type == 4;
                entry.addend_bits = entry.has_addend ? r.word(p + 16, 8) : 0;
                image.relocations_.push_back(entry);
            }
        } else if (s.type == 6) { // SHT_DYNAMIC: DT_NEEDED only, no initialization.
            entries(s, 16);
            bool terminated = false;
            std::map<uint64_t, uint64_t> tags;
            for (uint64_t p = s.offset; p < s.offset + s.size; p += 16) {
                const uint64_t tag = r.word(p, 8), value = r.word(p + 8, 8);
                if (!tag) { terminated = true; break; }
                if (tag != 1) require(tags.insert(std::make_pair(tag, value)).second,
                                      "duplicate ELF dynamic tag");
                if (tag == 1) image.needed_.push_back(string_at(r, linked(sections, s), value));
                // Packed Android/RELR tables need a separate decoder; never hide them.
                require(tag != 0x6000000f && tag != 0x60000010 && tag != 0x60000011 &&
                        tag != 0x60000012 && tag != 35 && tag != 36 && tag != 37 &&
                        tag != 0x6fffe000 && tag != 0x6fffe001 && tag != 0x6fffe003,
                        "unsupported packed ELF relocation inventory");
            }
            require(terminated, "unterminated ELF dynamic table");
            // Dynamic table pointers must describe inventoried sections; a missing
            // relocation/symbol section cannot silently remove unresolved work.
            const uint64_t pointer_tags[] = {5, 6, 7, 17, 23};
            for (uint64_t tag : pointer_tags) {
                if (!tags.count(tag)) continue;
                const uint32_t type = tag == 5 ? 3 : tag == 6 ? 11 : tag == 17 ? 9 :
                    tag == 23 && tags.count(20) && tags.at(20) == 17 ? 9 : 4;
                if (tag == 23) require(tags.count(20) && (tags.at(20) == 7 || tags.at(20) == 17),
                                       "invalid DT_PLTREL");
                const uint64_t size_tag = tag == 5 ? 10 : tag == 7 ? 8 : tag == 17 ? 18 :
                    tag == 23 ? 2 : 0;
                if (size_tag) require(tags.count(size_tag), "missing ELF dynamic table size");
                bool found = false;
                for (const Section& table : sections) {
                    if (table.type == type && table.address == tags.at(tag) &&
                        (!size_tag || table.size == tags.at(size_tag))) found = true;
                }
                require(found, "dynamic table missing matching section inventory");
            }
            const uint64_t sizes[] = {8, 18, 2, 10};
            const uint64_t pointers[] = {7, 17, 23, 5};
            for (unsigned i = 0; i < 4; ++i)
                require(!tags.count(sizes[i]) || !tags.at(sizes[i]) || tags.count(pointers[i]),
                        "ELF dynamic size without table address");
            require(!tags.count(9) || tags.at(9) == 24, "invalid DT_RELAENT");
            require(!tags.count(19) || tags.at(19) == 16, "invalid DT_RELENT");
            require(!tags.count(11) || tags.at(11) == 24, "invalid DT_SYMENT");
        }
        require(s.type != 19 && s.type != 0x60000001 && s.type != 0x60000002,
                "unsupported packed ELF relocation section");
    }
    // Publish mappings only after validating headers and the entire inventory.
    for (const ImageSegment& s : image.segments_) {
        image.memory_.map(s.address, static_cast<std::size_t>(s.memory_size), s.flags,
                          r.bytes.data() + s.file_offset, static_cast<std::size_t>(s.file_size));
    }
    return image;
}

void ElfImage::apply_relative_relocations() {
    if (relative_applied_) return;
    std::vector<ImageRelocation> applied, unresolved;
    std::map<uint64_t, uint64_t> writes;
    std::map<uint64_t, std::size_t> target_counts;
    for (const ImageRelocation& r : relocations_) ++target_counts[r.address];
    // Allocate reports and validate every write before touching guest bytes.
    for (const ImageRelocation& r : relocations_) {
        if (r.type != 1027 || !r.has_addend) {
            unresolved.push_back(r);
            continue;
        }
        require(r.symbol_index == 0, "RELA RELATIVE requires symbol index zero");
        require(r.address % 8 == 0, "RELA RELATIVE target must be 8-byte aligned");
        require(target_counts.at(r.address) == 1,
                "duplicate RELA RELATIVE target (composition unsupported)");
        memory_.region(r.address, 8, true); // checked complete range and PF_W
        // AAELF64: Delta + signed A, reduced to the 64-bit target field.
        // Unsigned addition of the two's-complement bits implements this exactly
        // without signed overflow or implementation-defined signed conversions.
        writes.insert(std::make_pair(r.address, bias_ + r.addend_bits));
        applied.push_back(r);
    }
    // No allocation or permission changes occur during commit. With exclusive
    // access to this image, every checked store is now guaranteed to succeed.
    for (const std::pair<const uint64_t, uint64_t>& write : writes)
        memory_.store64(write.first, write.second);
    applied_.swap(applied);
    relocations_.swap(unresolved);
    relative_applied_ = true;
}

} // namespace recomp
