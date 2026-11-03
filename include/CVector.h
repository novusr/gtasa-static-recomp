extern "C" float sqrtf(float);

struct CVector {
    float x;
    float y;
    float z;

    CVector() = default;
    constexpr CVector(float _x, float _y, float _z) : x(_x), y(_y), z(_z) {}

    void Normalise();
    float NormaliseAndMag();
};

CVector CrossProduct(const CVector& v1, const CVector& v2);
