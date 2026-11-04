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

static RwStream* ClumpCollisionStreamRead(RwStream*, int, void*, int, int);
static RwStream* ClumpCollisionStreamWrite(RwStream*, int, const void*, int, int);
static int ClumpCollisionStreamGetSize(const void*, int, int);

int RpClumpRegisterPluginStream(unsigned int, RwStream* (*)(RwStream*, int, void*, int, int), RwStream* (*)(RwStream*, int, const void*, int, int), int (*)(const void*, int, int));


extern CClumpModelInfo* gpClumpModelInfo;
void CCollisionPlugin::SetModelInfo(CClumpModelInfo* modelInfo) {
    gpClumpModelInfo = modelInfo;
}
