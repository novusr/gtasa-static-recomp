extern "C" int sprintf(char*, const char*, ...);

class CTheScripts {
public:
    static unsigned char ScriptSpace[];
};

class COnscreenCounterEntry {
public:
    unsigned int m_nVarId;
    unsigned int m_nMaxVarId;
    char pad[0xc];
    char m_szDisplayedText[0x2c];
    unsigned char m_nColourId;

    void SetColourID(unsigned char id);
    void ProcessForDisplayCounter(unsigned short type);
};

void COnscreenCounterEntry::SetColourID(unsigned char id) {
    m_nColourId = id;
}
