class CEvent {
public:
    virtual ~CEvent();
};

class CEventHealthLow : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventHealthLow();
};
