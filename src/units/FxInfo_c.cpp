class FxInfo_c {
public:
    virtual ~FxInfo_c();
    void operator delete(void*) {
        __builtin_trap();
    }
};

FxInfo_c::~FxInfo_c() {
}
