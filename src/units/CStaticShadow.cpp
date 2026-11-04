struct CPolyBunch {
    char pad[0x58];
    CPolyBunch* m_pNext;
};

class CShadows {
public:
    static CPolyBunch* pEmptyBunchList;
};

class CStaticShadow {
public:
    unsigned long long m_nId;
    CPolyBunch* m_pPolyBunch;

    void Free();
};
