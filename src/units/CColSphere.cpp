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

class CColSphere : public CSphere {
public:
    unsigned char m_nMaterial;
    unsigned char m_nFlags;
    unsigned char m_nLighting;
    unsigned char m_nLight;

    void Set(float radius, const CVector& center, unsigned char material, unsigned char flags, unsigned char lighting);
};

void CColSphere::Set(float radius, const CVector& center, unsigned char material, unsigned char flags, unsigned char lighting) {
    m_fRadius = radius;
    m_vecCenter = center;
    m_nMaterial = material;
    m_nFlags = flags;
    m_nLighting = lighting;
}
