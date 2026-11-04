#include <stdint.h>

class CColTriangle {
public:
    int32_t m_nIndex1;
    int32_t m_nIndex2;
    int32_t m_nIndex3;
    uint8_t m_nSurfaceType;
    uint8_t m_nLighting;
};

struct CSerializedColTriangle {
    uint16_t m_nIndex1;
    uint16_t m_nIndex2;
    uint16_t m_nIndex3;
    uint8_t m_nSurfaceType;
    uint8_t m_nLighting;

    static CColTriangle* Fixup(CSerializedColTriangle* src, int count);
};
