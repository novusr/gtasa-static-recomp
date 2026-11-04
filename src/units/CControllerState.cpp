#include <string.h>

class CControllerState {
public:
    short LeftStickX;
    short LeftStickY;
    short RightStickX;
    short RightStickY;
    short LeftShoulder1;
    short LeftShoulder2;
    short RightShoulder1;
    short RightShoulder2;
    short DPadUp;
    short DPadDown;
    short DPadLeft;
    short DPadRight;
    short Start;
    short Select;
    short ButtonSquare;
    short ButtonTriangle;
    short ButtonCross;
    short ButtonCircle;
    short ShockButtonL;
    short ShockButtonR;
    char pad[8];

    void Clear();
    bool CheckForInput();
};
