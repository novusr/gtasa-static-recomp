class CEvent {
public:
    virtual ~CEvent();
};

class CEventLeaderQuitEnteringCarAsDriver : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventLeaderQuitEnteringCarAsDriver();
};

CEventLeaderQuitEnteringCarAsDriver::~CEventLeaderQuitEnteringCarAsDriver() {
}
