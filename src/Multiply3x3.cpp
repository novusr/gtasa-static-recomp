#include "CMatrix.h"

CVector Multiply3x3(const CMatrix& m, const CVector& v) {
    return CVector(
        m.right.x * v.x + m.up.x * v.y + m.at.x * v.z,
        m.right.y * v.x + m.up.y * v.y + m.at.y * v.z,
        m.right.z * v.x + m.up.z * v.y + m.at.z * v.z
    );
}
