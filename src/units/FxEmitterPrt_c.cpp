extern char g_fxMan[];
extern void* dummy_alloc(void*, unsigned int, int);

struct FxEmitterPrt_c {
    static void* operator new[](unsigned long size);
};
