class CTimer {
public:
    static unsigned int m_snTimeInMilliseconds;
};

class CBulletTrace {
public:
    char pad[0x18];
    bool m_bExist;
    char pad2[3];
    unsigned int m_nCreationTime;
    unsigned int m_nLifeTime;

    void Update();
};

void CBulletTrace::Update() {
    if (CTimer::m_snTimeInMilliseconds - m_nCreationTime >= m_nLifeTime) {
        m_bExist = false;
    }
}
