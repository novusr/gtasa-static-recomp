class FxInterpInfo_c {
public:
    unsigned char m_nField8;
    void* m_pField10;

    virtual void DummyKeyFunction();
    FxInterpInfo_c();
    virtual ~FxInterpInfo_c() = 0;
};

FxInterpInfo_c::~FxInterpInfo_c() {
}

FxInterpInfo_c::FxInterpInfo_c() {
    m_nField8 = 0;
    m_pField10 = nullptr;
}

