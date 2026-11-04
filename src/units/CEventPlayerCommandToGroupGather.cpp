class CEvent {
public:
    virtual ~CEvent();
};

class CEventPlayerCommandToGroupGather : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventPlayerCommandToGroupGather();
};

CEventPlayerCommandToGroupGather::~CEventPlayerCommandToGroupGather() {
}
