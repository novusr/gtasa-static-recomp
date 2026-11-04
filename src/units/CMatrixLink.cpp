struct CMatrixLink {
    char pad[0x58];
    CMatrixLink* m_pPrev;
    CMatrixLink* m_pNext;

    void Remove();
    void Insert(CMatrixLink* pLink);
};
