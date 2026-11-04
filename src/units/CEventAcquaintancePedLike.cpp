class CEvent {
public:
    virtual ~CEvent();
};

class CEventAcquaintancePedLike : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventAcquaintancePedLike();
};
