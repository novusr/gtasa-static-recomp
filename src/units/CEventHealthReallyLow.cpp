class CEvent {
public:
    virtual ~CEvent();
};

class CEventHealthReallyLow : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventHealthReallyLow();
};
