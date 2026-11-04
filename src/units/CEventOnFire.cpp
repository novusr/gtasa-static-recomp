class CEvent {
public:
    virtual ~CEvent();
};

class CEventOnFire : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventOnFire();
};

CEventOnFire::~CEventOnFire() {
}
