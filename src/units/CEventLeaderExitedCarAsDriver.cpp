class CEvent {
public:
    virtual ~CEvent();
};

class CEventLeaderExitedCarAsDriver : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventLeaderExitedCarAsDriver();
};
