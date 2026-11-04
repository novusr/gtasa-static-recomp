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
    __attribute__((noinline)) void Flush();
};

CPtrListDoubleLink::~CPtrListDoubleLink() {
    Flush();
}

void CPtrListDoubleLink::Flush() {
    CPtrNodeDoubleLink* node = m_node;
    while (node) {
        CPtrNodeDoubleLink* next = node->m_next;
        if (m_node == node)
            m_node = node->m_next;
        if (node->m_prev)
            node->m_prev->m_next = node->m_next;
        if (node->m_next)
            node->m_next->m_prev = node->m_prev;
        CPools::ms_pPtrNodeDoubleLinkPool->Delete(node);
        node = next;
    }
}

