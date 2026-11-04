class CEvent {
public:
    virtual ~CEvent();
};

class CEventInteriorUseInfo : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventInteriorUseInfo();
};

CEventInteriorUseInfo::~CEventInteriorUseInfo() {
}
