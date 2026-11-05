#include "recomp/elf_image.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {
uint64_t number(const char* text) {
    const std::string s(text);
    std::size_t end = 0;
    if (s.empty() || s[0] == '-') throw std::invalid_argument("invalid unsigned number");
    const uint64_t value = std::stoull(s, &end, 0);
    if (end != s.size()) throw std::invalid_argument("invalid unsigned number");
    return value;
}
const char* encoding(recomp::InventoryEncoding e) {
    switch (e) {
        case recomp::InventoryEncoding::Rela: return "RELA";
        case recomp::InventoryEncoding::Rel: return "REL";
        case recomp::InventoryEncoding::AndroidAps2Rela: return "ANDROID_APS2_RELA";
        case recomp::InventoryEncoding::AndroidRelr: return "ANDROID_RELR";
        case recomp::InventoryEncoding::StandardRelr: return "RELR";
    }
    throw std::logic_error("unknown inventory encoding");
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 4 && argc != 6) throw std::invalid_argument("usage: inventory-image ELF SHA256 BIAS [MAX_RECORDS MAX_STORAGE]");
        recomp::InventoryLimits limits;
        if (argc == 6) { limits.max_records = number(argv[4]); limits.max_storage_bytes = number(argv[5]); }
        const recomp::ElfImage image = recomp::ElfImage::load_inventory_only(argv[1], argv[2], number(argv[3]), limits);
        const recomp::RelocationInventory& inventory = image.relocation_inventory();
        std::ostringstream out;
        out.exceptions(std::ios::badbit | std::ios::failbit);
        out << "{\"profile\":\"native-relocation-inventory-only-v1\",\"application_status\":\"application-not-supported\","
            << "\"ready_to_execute\":false,\"relro_sealed\":false,\"sha256\":\"" << image.sha256()
            << "\",\"load_bias\":" << image.load_bias() << ",\"decoded_count\":" << inventory.decoded_count
            << ",\"accounted_storage_bytes\":" << inventory.accounted_storage_bytes << ",\"segments\":[";
        bool segment_comma = false;
        for (const recomp::ImageSegment& s : image.segments()) {
            if (segment_comma) out << ',';
            segment_comma = true;
            out << "{\"address\":" << s.address << ",\"virtual_address\":" << s.virtual_address
                << ",\"file_offset\":" << s.file_offset << ",\"file_size\":" << s.file_size
                << ",\"memory_size\":" << s.memory_size << ",\"flags\":" << s.flags << '}';
        }
        out << "],\"tables\":[";
        bool comma = false;
        for (const recomp::InventoryTable& t : inventory.tables) {
            if (comma) out << ',';
            comma = true;
            out << "{\"encoding\":\"" << encoding(t.encoding) << "\",\"section\":" << t.section
                << ",\"section_type\":" << t.section_type << ",\"virtual_address\":" << t.address
                << ",\"load_segment\":" << t.load_segment
                << ",\"load_program_header\":" << t.load_program_header << ",\"file_offset\":" << t.file_offset << ",\"encoded_size\":" << t.encoded_size
                << ",\"entry_size\":" << t.entry_size << ",\"encoded_count\":" << t.encoded_count
                << ",\"decoded_count\":" << t.decoded_count << ",\"symbol_table\":";
            if (t.encoding == recomp::InventoryEncoding::AndroidRelr || t.encoding == recomp::InventoryEncoding::StandardRelr) out << "null";
            else out << t.symbol_table;
            out << ",\"dynamic_associations\":[";
            for (uint64_t i = 0; i < t.association_count; ++i) {
                if (i) out << ',';
                const recomp::InventoryDynamicAssociation& a = t.associations[i];
                out << "{\"section\":" << a.section << ",\"index\":" << a.index
                    << ",\"tag\":" << a.tag << ",\"value\":" << a.value << '}';
            }
            out << ']';
            if (t.encoding == recomp::InventoryEncoding::AndroidAps2Rela)
                out << ",\"aps2_initial_offset\":" << t.aps2.initial_offset
                    << ",\"aps2_group_count\":" << t.aps2.group_count;
            out << ",\"records\":[";
            bool record_comma = false;
            for (const recomp::Aps2RelaRecord& a : t.aps2.records) {
                if (record_comma) out << ',';
                record_comma = true;
                out << "{\"offset\":" << a.offset << ",\"address\":" << a.offset + image.load_bias()
                    << ",\"info\":" << a.info << ",\"addend\":" << a.addend
                    << ",\"addend_kind\":\"explicit\",\"symbol_index\":" << a.symbol_index()
                    << ",\"ordinal\":" << a.ordinal << ",\"group_ordinal\":" << a.group_ordinal
                    << ",\"group_begin\":" << a.group_begin << ",\"group_header_end\":" << a.group_header_end
                    << ",\"group_end\":" << a.group_end << ",\"entry_begin\":" << a.entry_begin
                    << ",\"entry_end\":" << a.entry_end << ",\"flags\":" << a.flags << '}';
            }
            for (const recomp::RelrRecord& a : t.relr.records) {
                if (record_comma) out << ',';
                record_comma = true;
                out << "{\"offset\":" << a.offset << ",\"address\":" << a.offset + image.load_bias()
                    << ",\"ordinal\":" << a.ordinal << ",\"word_index\":" << a.word_index
                    << ",\"byte_offset\":" << a.byte_offset << ",\"source\":" << static_cast<uint64_t>(a.source)
                    << ",\"bitmap_bit\":" << a.bitmap_bit << ",\"addend_kind\":\"implicit-target\"}";
            }
            for (const recomp::InventoryOrdinaryRecord& a : t.ordinary) {
                if (record_comma) out << ',';
                record_comma = true;
                out << "{\"offset\":" << a.offset << ",\"address\":" << a.offset + image.load_bias()
                    << ",\"ordinal\":" << a.ordinal << ",\"byte_offset\":" << a.byte_offset
                    << ",\"info\":" << a.info << ",\"symbol_index\":" << (a.info >> 32);
                if (t.encoding == recomp::InventoryEncoding::Rela)
                    out << ",\"addend_kind\":\"explicit\",\"addend_bits\":" << a.addend_bits;
                else out << ",\"addend_kind\":\"implicit-target\"";
                out << '}';
            }
            out << "]}";
        }
        out << "]}\n";
        std::cout << out.str();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
