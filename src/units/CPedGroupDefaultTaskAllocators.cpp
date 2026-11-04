class CPedGroupDefaultTaskAllocator;

class CPedGroupDefaultTaskAllocators {
public:
    static CPedGroupDefaultTaskAllocator* ms_allocators[6];
    static CPedGroupDefaultTaskAllocator* Get(int id);
};
