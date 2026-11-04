class CEvent {
public:
    virtual ~CEvent();
};

class CEventScriptedAttractor : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventScriptedAttractor();
};

CEventScriptedAttractor::~CEventScriptedAttractor() {
}
