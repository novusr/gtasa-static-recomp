class CPedGroupIntelligence;

struct TaskAllocatorObject {
    char pad[0x30];
};

struct CPool {
    TaskAllocatorObject* m_pObjects;
    unsigned char* m_pFlags;
    int m_nSize;
    int m_nFirstFree;
};

class CTaskAllocator {
public:
    static CPool* ms_pPool;
    virtual ~CTaskAllocator() {}
    static void operator delete(void* ptr) {
        CPool* pool = ms_pPool;
        int idx = (TaskAllocatorObject*)ptr - pool->m_pObjects;
        pool->m_pFlags[idx] |= 0x80;
        if (pool->m_nFirstFree > idx) {
            pool->m_nFirstFree = idx;
        }
    }
};

class CTaskAllocatorPlayerCommandRetreat : public CTaskAllocator {
public:
    virtual void DummyKeyFunction();
    virtual ~CTaskAllocatorPlayerCommandRetreat();
    virtual void AllocateTasks(CPedGroupIntelligence*);
};

void CTaskAllocatorPlayerCommandRetreat::AllocateTasks(CPedGroupIntelligence*) {
}

CTaskAllocatorPlayerCommandRetreat::~CTaskAllocatorPlayerCommandRetreat() {
}

