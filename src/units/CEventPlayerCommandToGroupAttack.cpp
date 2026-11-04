class CEvent {
public:
    virtual ~CEvent();
};

class CEventPlayerCommandToGroupAttack : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventPlayerCommandToGroupAttack();
};

CEventPlayerCommandToGroupAttack::~CEventPlayerCommandToGroupAttack() {
}
