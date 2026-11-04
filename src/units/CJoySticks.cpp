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

void CJoySticks::ClearJoyInfo(int n) {
    JoyStickNum[n].wDeviceID = 0;
    JoyStickNum[n].bJoyAttachedToPort = false;
    JoyStickNum[n].bZAxisPresent = false;
    JoyStickNum[n].bZRotPresent = false;
}

CJoySticks::CJoySticks() {
    ClearJoyInfo(0);
    ClearJoyInfo(1);
}

