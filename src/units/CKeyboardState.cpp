#include <string.h>

class CKeyboardState {
public:
    short kFunc[12];
    short kAscii[256];
    short kESC;
    short kINS;
    short kDEL;
    short kHOME;
    short kEND;
    short kPGUP;
    short kPGDN;
    short kUP;
    short kDOWN;
    short kLEFT;
    short kRIGHT;
    short kSCROLL_LOCK;
    short kPAUSE_BREAK;
    short kNUMPAD_NUMLOCK;
    short kNUMPAD_DIVIDE;
    short kNUMPAD_TIMES;
    short kNUMPAD_MINUS;
    short kNUMPAD_PLUS;
    short kNUMPAD_ENTER;
    short kNUMPAD_DOT;
    short kNUMPAD_ONE;
    short kNUMPAD_TWO;
    short kNUMPAD_THREE;
    short kNUMPAD_FOUR;
    short kNUMPAD_FIVE;
    short kNUMPAD_SIX;
    short kNUMPAD_SEVEN;
    short kNUMPAD_EIGHT;
    short kNUMPAD_NINE;
    short kNUMPAD_ZERO;
    short kBACKSP;
    short kTAB;
    short kCAPSLK;
    short kENTER;
    short kLSHIFT;
    short kRSHIFT;
    short k98_SHIFT;
    short kLCTRL;
    short kRCTRL;
    short kLALT;
    short kRALT;
    short kLEFT_WINDOW_KEY;
    short kRIGHT_WINDOW_KEY;
    short kWINDOW_RIGHT_CLICK_KEY;

    void Clear();
};
