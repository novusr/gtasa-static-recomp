#pragma once
#include "CVector.h"

struct alignas(16) CMatrix {
    CVector right;
    unsigned int flags;
    CVector up;
    unsigned int pad1;
    CVector at;
    unsigned int pad2;
    CVector pos;
    unsigned int pad3;
};

CVector Multiply3x3(const CMatrix& m, const CVector& v);
