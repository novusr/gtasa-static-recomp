class CVector {
public:
    float x, y, z;
};

class CColDisk {
public:
    CVector m_vecStart;
    float m_fRadius;
    unsigned char m_nMaterial;
    unsigned char m_nPiece;
    unsigned char m_nLighting;
    CVector m_vecEnd;
    float m_fThickness;

    void Set(float radius, const CVector& start, const CVector& end, float thickness, unsigned char material, unsigned char piece, unsigned char lighting);
};
