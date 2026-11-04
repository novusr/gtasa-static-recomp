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

void CMatrixLink::Insert(CMatrixLink* pLink) {
    pLink->m_pNext = m_pNext;
    m_pNext->m_pPrev = pLink;
    pLink->m_pPrev = this;
    m_pNext = pLink;
}

