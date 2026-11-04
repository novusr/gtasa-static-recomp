class __attribute__((packed)) CCarPathLink {
public:
    char _pad[10];
    unsigned char m_nOffset;
    unsigned short m_nLeftLanes : 3;
    unsigned short m_nRightLanes : 3;

    float OneWayLaneOffset();
};
