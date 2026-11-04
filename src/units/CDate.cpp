class CDate {
public:
    int m_nSeconds;
    int m_nMinutes;
    int m_nHours;
    int m_nDay;
    int m_nMonth;
    int m_nYear;

    CDate();
    void PopulateDateFields(const char& sec, const char& min, const char& hour, const char& day, const char& month, short year);
};

CDate::CDate() {
    m_nSeconds = 0;
    m_nMinutes = 0;
    m_nHours = 0;
    m_nDay = 0;
    m_nMonth = 0;
    m_nYear = 0;
}
