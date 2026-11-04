class CMoveStateStrings {
public:
    const char* m_p0;
    const char* m_p1;
    const char* m_p2;
    const char* m_p3;
    const char* m_p6;
    const char* m_p4;
    const char* m_p5;

    const char* GetMoveStateString(int state);
};

const char* CMoveStateStrings::GetMoveStateString(int state) {
    switch (state) {
    default:
    case 0:
    case 7:
        return m_p0;
    case 1:
        return m_p1;
    case 2:
        return m_p2;
    case 3:
        return m_p3;
    case 4:
        return m_p4;
    case 5:
        return m_p5;
    case 6:
        return m_p6;
    }
}
