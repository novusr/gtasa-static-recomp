class CText {
public:
    char* Get(const char*);
};

extern CText TheText;

class CZone {
public:
    char m_szInfoLabel[8];
    char m_szTextLabel[8];

    char* GetTranslatedName();
};

char* CZone::GetTranslatedName() {
    return TheText.Get(m_szTextLabel);
}
