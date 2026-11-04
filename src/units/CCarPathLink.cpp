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
    unsigned short left = m_nLeftLanes;
    unsigned short right = m_nRightLanes;
    if (left == 0) {
        return 0.5f - (float)right * 0.5f;
    }
    if (right == 0) {
        return 0.5f - (float)left * 0.5f;
    }
    return (float)m_nOneWayLaneOffset / 100.0f + 0.5f;
}
