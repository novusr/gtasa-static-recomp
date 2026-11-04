typedef unsigned long long uint64_t;
typedef unsigned int uint32_t;

extern bool skipBlendRender;
extern bool emu_InternalBlendEnabled;
extern volatile bool skipNonblendRender;

void emu_ArraysDrawStoredSeparate(uint64_t, uint64_t, uint32_t, uint32_t, uint32_t);
void emu_ArraysDrawStored(uint64_t, uint32_t);

class RxOpenGLMeshInstanceData {
public:
    uint32_t m_nPrimType;
    char pad_04[0x14];
    uint64_t m_nIndexData;
    char pad_20[0x08];
    uint64_t m_nVertexData;
    uint64_t m_nSeparateData;
    uint32_t m_nNumIndices;
    uint32_t m_nNumVertices;

    void DrawStored();
};

void RxOpenGLMeshInstanceData::DrawStored() {
    if (skipBlendRender && emu_InternalBlendEnabled)
        return;
    if (skipNonblendRender && !emu_InternalBlendEnabled)
        return;

    if (m_nVertexData) {
        if (m_nSeparateData) {
            emu_ArraysDrawStoredSeparate(m_nSeparateData, m_nVertexData, m_nPrimType, m_nNumIndices, m_nNumVertices);
        } else {
            emu_ArraysDrawStored(m_nVertexData, m_nPrimType);
        }
    } else {
        emu_ArraysDrawStored(m_nIndexData, m_nPrimType);
    }
}
