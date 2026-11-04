#include "CVector.h"

class CBoundBox {
public:
    CVector m_vecMin;
    CVector m_vecMax;

    bool IsPointWithin(const CVector& point);
};
