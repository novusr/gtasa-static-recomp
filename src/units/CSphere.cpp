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

void CSphere::Set(float radius, const CVector& center) {
    m_fRadius = radius;
    m_vecCenter = center;
}
