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

class CPtrNodeDoubleLink {
public:
    void* m_item;
    CPtrNodeDoubleLink* m_next;
    CPtrNodeDoubleLink* m_prev;
};

class CPools {
public:
    static CPool<CPtrNodeDoubleLink>* ms_pPtrNodeDoubleLinkPool;
};

class CPtrListDoubleLink {
public:
    CPtrNodeDoubleLink* m_node;

    ~CPtrListDoubleLink();
    void Flush();
};

CPtrListDoubleLink::~CPtrListDoubleLink() {
    Flush();
}
