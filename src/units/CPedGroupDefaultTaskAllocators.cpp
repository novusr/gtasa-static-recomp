class CPedGroupDefaultTaskAllocator;

class CPedGroupDefaultTaskAllocators {
public:
    static CPedGroupDefaultTaskAllocator* ms_allocators[6];
    static CPedGroupDefaultTaskAllocator* Get(int id);
};

CPedGroupDefaultTaskAllocator* CPedGroupDefaultTaskAllocators::ms_allocators[6];


CPedGroupDefaultTaskAllocator* CPedGroupDefaultTaskAllocators::Get(int id) {
    if (static_cast<unsigned int>(id) > 5)
        return nullptr;
    return ms_allocators[id];
}
