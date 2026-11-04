typedef unsigned long size_t;

class CPedGroupIntelligence;

class CTaskAllocator {
public:
    virtual ~CTaskAllocator() {}
    char pad[40];
};

template <class A, class B = A>
class CPool {
public:
    A* m_pObjects;
    char* m_pByteMap;
    int m_nSize;
    int m_nFirstFree;
    bool m_bAllocatedBuffers;

    void Delete(A* pObject) {
        int index = pObject - m_pObjects;
        m_pByteMap[index] |= 0x80;
        if (index < m_nFirstFree)
            m_nFirstFree = index;
    }
};

class CPools {
public:
    static CPool<CTaskAllocator>* ms_pTaskAllocatorPool;
};

class CTaskAllocatorRetreat : public CTaskAllocator {
public:
    virtual int GetType() const;
    virtual ~CTaskAllocatorRetreat();
    virtual void AllocateTasks(CPedGroupIntelligence*);

    void operator delete(void* ptr) {
        CPools::ms_pTaskAllocatorPool->Delete(static_cast<CTaskAllocator*>(ptr));
    }
};

CTaskAllocatorRetreat::~CTaskAllocatorRetreat() {
}

void CTaskAllocatorRetreat::AllocateTasks(CPedGroupIntelligence*) {
}
