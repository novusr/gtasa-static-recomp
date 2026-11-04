struct JoyStruct {
    unsigned int wDeviceID;
    bool bJoyAttachedToPort;
    bool bZAxisPresent;
    bool bZRotPresent;
    unsigned int wVendorID;
    unsigned int wProductID;
};

class CJoySticks {
public:
    JoyStruct JoyStickNum[2];

    CJoySticks();
    void ClearJoyInfo(int);
};
