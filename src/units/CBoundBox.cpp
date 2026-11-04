#include "CVector.h"

class CBoundBox {
public:
    CVector m_vecMin;
    CVector m_vecMax;

    bool IsPointWithin(const CVector& point);
};

bool CBoundBox::IsPointWithin(const CVector& point) {
    if (!(point.x >= m_vecMin.x))
        goto ret_false;
    if (!(point.y >= m_vecMin.y))
        goto ret_false;
    if (!(point.z >= m_vecMin.z))
        goto ret_false;
    if (point.x > m_vecMax.x)
        goto ret_false;
    if (point.y > m_vecMax.y)
        goto ret_false;
    if (!(point.z > m_vecMax.z))
        return true;
ret_false:
    return false;
}
