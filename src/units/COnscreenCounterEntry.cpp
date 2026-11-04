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

void COnscreenCounterEntry::ProcessForDisplayCounter(unsigned short type) {
    int val = *(int*)&CTheScripts::ScriptSpace[m_nVarId];
    if (val < 0)
        val = 0;

    switch (type) {
    case 0:
    case 1:
        sprintf(m_szDisplayedText, "%d", val);
        break;
    case 2:
        sprintf(m_szDisplayedText, "%d/%d", val, *(int*)&CTheScripts::ScriptSpace[m_nMaxVarId]);
        break;
    }
}

