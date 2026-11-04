#include "CVector.h"

struct ColData {
    unsigned char m_nSurfaceType;
    unsigned char m_nPieceType;
    unsigned char m_nLighting;
};

class CColPoint {
public:
    CVector m_vecPosition;
    float pad;
    CVector m_vecNormal;
    float pad2;
    ColData m_dataA;
    ColData m_dataB;
    float m_fDepth;

    CColPoint& operator=(const CColPoint& other);
};

CColPoint& CColPoint::operator=(const CColPoint& other) {
    m_vecPosition = other.m_vecPosition;
    m_vecNormal = other.m_vecNormal;
    m_dataA = other.m_dataA;
    m_dataB = other.m_dataB;
    m_fDepth = other.m_fDepth;
    return *this;
}
