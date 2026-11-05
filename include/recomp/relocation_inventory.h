#pragma once
#include "recomp/aps2_rela.h"
#include "recomp/relr.h"

namespace recomp {
enum class InventoryEncoding : uint64_t {
    Rela = 1, Rel = 2, AndroidAps2Rela = 3, AndroidRelr = 4, StandardRelr = 5
};
struct InventoryLimits {
    uint64_t max_records;
    uint64_t max_storage_bytes;
    InventoryLimits() : max_records(1000000), max_storage_bytes(268435456) {}
};
struct InventoryDynamicAssociation {
    uint64_t section, index, tag, value;
};
static_assert(sizeof(InventoryDynamicAssociation) == 32, "dynamic association storage");
static_assert(offsetof(InventoryDynamicAssociation, section) == 0, "dynamic section layout");
static_assert(offsetof(InventoryDynamicAssociation, index) == 8, "dynamic index layout");
static_assert(offsetof(InventoryDynamicAssociation, tag) == 16, "dynamic tag layout");
static_assert(offsetof(InventoryDynamicAssociation, value) == 24, "dynamic value layout");
struct InventoryOrdinaryRecord {
    uint64_t offset, info, addend_bits, ordinal, byte_offset;
};
static_assert(sizeof(InventoryOrdinaryRecord) == 40, "ordinary inventory storage");
static_assert(offsetof(InventoryOrdinaryRecord, offset) == 0, "ordinary offset layout");
static_assert(offsetof(InventoryOrdinaryRecord, info) == 8, "ordinary info layout");
static_assert(offsetof(InventoryOrdinaryRecord, addend_bits) == 16, "ordinary addend layout");
static_assert(offsetof(InventoryOrdinaryRecord, ordinal) == 24, "ordinary ordinal layout");
static_assert(offsetof(InventoryOrdinaryRecord, byte_offset) == 32, "ordinary provenance layout");
// Exactly one record vector is populated. Section index is the object-local
// table identity; object identity is supplied by the caller/report envelope.
struct InventoryTable {
    InventoryEncoding encoding;
    uint64_t section, section_type, address, file_offset, encoded_size, entry_size;
    uint64_t symbol_table, load_segment, load_program_header, decoded_count, encoded_count, association_count;
    InventoryDynamicAssociation associations[6];
    Aps2RelaResult aps2;
    RelrResult relr;
    std::vector<InventoryOrdinaryRecord> ordinary;
};
struct RelocationInventory {
    std::vector<InventoryTable> tables;
    uint64_t decoded_count, accounted_storage_bytes;
    RelocationInventory() : decoded_count(0), accounted_storage_bytes(0) {}
};
} // namespace recomp
