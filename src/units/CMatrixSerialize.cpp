#include "CMatrix.h"

struct CMatrixSerialize : public CMatrix {
    unsigned int unk;
    CMatrixSerialize& operator=(const CMatrix& other);
};
