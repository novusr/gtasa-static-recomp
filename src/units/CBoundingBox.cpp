class CVector {
public:
    float x, y, z;
};

class CSphere {
public:
    CVector m_vecCenter;
    float m_fRadius;
};

class CBox {
public:
    CVector m_vecMin;
    CVector m_vecMax;
};

class CBoundingBox : public CBox {
public:
    CSphere m_sphereBound;

    CBoundingBox();
};
