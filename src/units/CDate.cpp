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
