class CVector {
public:
    float x, y, z;
};

class CSphere {
public:
    CVector m_vecCenter;
    float m_fRadius;

    void Set(float radius, const CVector& center);
};
