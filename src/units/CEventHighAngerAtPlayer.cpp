class CEvent {
public:
    virtual ~CEvent();
};

class CEventHighAngerAtPlayer : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventHighAngerAtPlayer();
};

CEventHighAngerAtPlayer::~CEventHighAngerAtPlayer() {
}
