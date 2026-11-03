#include "CVector.h"

void CVector::Normalise() {
    float magSq = x * x + y * y + z * z;
    if (magSq > 0.0f) {
        float invSqrt = 1.0f / sqrtf(magSq);
        x *= invSqrt;
        y *= invSqrt;
        z *= invSqrt;
    } else {
        x = 1.0f;
    }
}
