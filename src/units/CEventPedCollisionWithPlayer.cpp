class CEvent {
public:
    virtual ~CEvent();
};

class CEventPedCollisionWithPlayer : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventPedCollisionWithPlayer();
};

CEventPedCollisionWithPlayer::~CEventPedCollisionWithPlayer() {
}
