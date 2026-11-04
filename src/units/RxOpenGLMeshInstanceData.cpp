typedef unsigned long long uint64_t;
typedef unsigned int uint32_t;

extern bool skipBlendRender;
extern bool emu_InternalBlendEnabled;
extern bool skipNonblendRender;

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
