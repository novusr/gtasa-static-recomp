extern "C" float cosf(float);
extern "C" float sinf(float);

class CVector {
public:
    float x, y, z;
};

class CSimpleTransform {
public:
    CVector m_vPos;
    float m_fHeading;

    void Invert(const CSimpleTransform& src);
};
