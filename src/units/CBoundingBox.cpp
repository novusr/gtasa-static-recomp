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

CBoundingBox::CBoundingBox() {
    m_vecMin = {1.0f, 1.0f, 1.0f};
    m_vecMax = {-1.0f, -1.0f, -1.0f};
}
