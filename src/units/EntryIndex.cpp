struct EntryIndex {
    int field_0;
    int field_4;
    static int sort(void const* a, void const* b);
};

int EntryIndex::sort(void const* a, void const* b) {
    return static_cast<const EntryIndex*>(a)->field_4 - static_cast<const EntryIndex*>(b)->field_4;
}
