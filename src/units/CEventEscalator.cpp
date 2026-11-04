class CEvent {
public:
    virtual ~CEvent();
    void operator delete(void*);
};

class CEventEscalator : public CEvent {
public:
    virtual ~CEventEscalator();
};

CEventEscalator::~CEventEscalator() {
}
