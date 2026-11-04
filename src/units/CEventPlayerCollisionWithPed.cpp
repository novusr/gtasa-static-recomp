class CEvent {
public:
    virtual ~CEvent();
};

class CEventPlayerCollisionWithPed : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventPlayerCollisionWithPed();
};

CEventPlayerCollisionWithPed::~CEventPlayerCollisionWithPed() {
}
