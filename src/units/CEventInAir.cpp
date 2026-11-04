struct EventPoolObject {
    char pad[88];
};

struct CPool {
    EventPoolObject* m_pObjects;
    unsigned char* m_pFlags;
    int m_nSize;
    int m_nFirstFree;
};

class CPools {
public:
    static CPool* ms_pEventPool;
};

class CEvent {
public:
    int m_iAccumulatedTime;
    bool m_bIsPersistent;

    CEvent() : m_iAccumulatedTime(0), m_bIsPersistent(false) {}
    virtual ~CEvent() {}
    static void operator delete(void* ptr) {
        CPool* pool = CPools::ms_pEventPool;
        int idx = (EventPoolObject*)ptr - pool->m_pObjects;
        pool->m_pFlags[idx] |= 0x80;
        if (pool->m_nFirstFree > idx) {
            pool->m_nFirstFree = idx;
        }
    }
};

class CEventInAir : public CEvent {
public:
    CEventInAir();
    virtual ~CEventInAir();
};
