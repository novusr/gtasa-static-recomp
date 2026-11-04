class CPedGroupIntelligence;

class CTaskAllocator {
public:
    virtual ~CTaskAllocator();
    void operator delete(void* ptr);
};

class CTaskAllocatorPlayerCommandRetreat : public CTaskAllocator {
public:
    virtual void DummyKeyFunction();
    virtual ~CTaskAllocatorPlayerCommandRetreat();
    virtual void AllocateTasks(CPedGroupIntelligence*);
};

void CTaskAllocatorPlayerCommandRetreat::AllocateTasks(CPedGroupIntelligence*) {
}
