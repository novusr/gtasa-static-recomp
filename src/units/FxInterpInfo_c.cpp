class FxInterpInfo_c {
public:
    unsigned char m_nField8;
    void* m_pField10;

    FxInterpInfo_c();
    virtual ~FxInterpInfo_c();
};

FxInterpInfo_c::~FxInterpInfo_c() {
    __builtin_trap();
}

FxInterpInfo_c::FxInterpInfo_c() {
    m_nField8 = 0;
    m_pField10 = nullptr;
}

