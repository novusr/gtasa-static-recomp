class CPedStuckChecker {
public:
    char pad[0xc];
    int m_state;

    CPedStuckChecker();
};

CPedStuckChecker::CPedStuckChecker() : m_state(0) {
}
