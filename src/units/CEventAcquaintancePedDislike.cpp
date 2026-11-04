class CEvent {
public:
    virtual ~CEvent();
};

class CEventAcquaintancePedDislike : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventAcquaintancePedDislike();
};

CEventAcquaintancePedDislike::~CEventAcquaintancePedDislike() {
}
