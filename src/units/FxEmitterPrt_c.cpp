extern char g_fxMan[];
extern void* dummy_alloc(void*, unsigned int, int);

struct FxEmitterPrt_c {
    static void* operator new[](unsigned long size);
};

void* FxEmitterPrt_c::operator new[](unsigned long size) {
    return dummy_alloc(g_fxMan + 0x100, size, 4);
}
