class __attribute__((packed)) CCarPathLink {
public:
    char _pad[10];
    unsigned char m_nOneWayLaneOffset;
    unsigned short m_nLeftLanes : 3;
    unsigned short m_nRightLanes : 3;
    unsigned short m_nTrafficLevel : 10;

    float OneWayLaneOffset();
};

float CCarPathLink::OneWayLaneOffset() {
    if (!m_nLeftLanes)
        return m_nRightLanes * 0.5f - 0.5f;
    if (!m_nRightLanes)
        return m_nLeftLanes * 0.5f - 0.5f;
    return (float)m_nOneWayLaneOffset / 15.0f + 0.5f;
}
