struct COctTree {};

template <class A, class B = A>
class CPool {
public:
    A* m_pObjects;
    char* m_pByteMap;
    int m_nSize;
    int m_nFirstFree;
    bool m_bAllocatedBuffers;

    ~CPool();
};
