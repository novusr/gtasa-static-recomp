struct CMatrixLink {
    char pad[0x58];
    CMatrixLink* m_pPrev;
    CMatrixLink* m_pNext;

    void Remove();
    void Insert(CMatrixLink* pLink);
};

void CMatrixLink::Remove() {
    m_pNext->m_pPrev = m_pPrev;
    m_pPrev->m_pNext = m_pNext;
}
