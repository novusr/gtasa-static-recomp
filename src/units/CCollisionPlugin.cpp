class CClumpModelInfo;

static CClumpModelInfo* gpCollisionModelInfo;

class CCollisionPlugin {
public:
    static void SetModelInfo(CClumpModelInfo* modelInfo);
    static bool PluginAttach();
};

struct RwStream;

void* ClumpCollisionConstructor(void*, int, int);
void* ClumpCollisionDestructor(void*, int, int);
void* ClumpCollisionCopyConstructor(void*, const void*, int, int);

int RpClumpRegisterPlugin(int, unsigned int, void* (*)(void*, int, int), void* (*)(void*, int, int), void* (*)(void*, const void*, int, int));

static RwStream* ClumpCollisionStreamRead(RwStream* pStream, int len, void* pData, int offset, int size) { return pStream; }
static RwStream* ClumpCollisionStreamWrite(RwStream* pStream, int len, const void* pData, int offset, int size) { return pStream; }
static int ClumpCollisionStreamGetSize(const void* pData, int offset, int size) { return -1; }


int RpClumpRegisterPluginStream(unsigned int, RwStream* (*)(RwStream*, int, void*, int, int), RwStream* (*)(RwStream*, int, const void*, int, int), int (*)(const void*, int, int));


extern CClumpModelInfo* gpClumpModelInfo;
void CCollisionPlugin::SetModelInfo(CClumpModelInfo* modelInfo) {
    gpCollisionModelInfo = modelInfo;
}
