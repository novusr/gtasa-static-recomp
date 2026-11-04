class CEvent {
public:
    virtual ~CEvent();
};

class CEventLowAngerAtPlayer : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventLowAngerAtPlayer();
};

CEventLowAngerAtPlayer::~CEventLowAngerAtPlayer() {
}
