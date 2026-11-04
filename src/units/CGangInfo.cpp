class CGangInfo {
public:
    signed char m_nAttackBias;
    int m_nWeapons[3];

    CGangInfo();
    ~CGangInfo();
};

CGangInfo::CGangInfo() {
    m_nWeapons[0] = 0;
    m_nWeapons[1] = 0;
    m_nAttackBias = -1;
    m_nWeapons[2] = 0;
}

CGangInfo::~CGangInfo() {
}
