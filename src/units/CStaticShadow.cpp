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

void CStaticShadow::Free() {
    if (m_pPolyBunch) {
        CPolyBunch* oldEmpty = CShadows::pEmptyBunchList;
        CShadows::pEmptyBunchList = m_pPolyBunch;
        CPolyBunch* bunch = m_pPolyBunch;
        while (bunch->m_pNext) {
            bunch = bunch->m_pNext;
        }
        bunch->m_pNext = oldEmpty;
    }
    m_nId = 0;
    m_pPolyBunch = nullptr;
}
