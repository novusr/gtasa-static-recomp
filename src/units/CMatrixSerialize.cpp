#include "CMatrix.h"

struct CMatrixSerialize : public CMatrix {
    unsigned int unk;
    CMatrixSerialize& operator=(const CMatrix& other);
};

CMatrixSerialize& CMatrixSerialize::operator=(const CMatrix& other) {
    __builtin_memcpy(this, &other, sizeof(CMatrix));
    unk = 0;
    return *this;
}
