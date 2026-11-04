class CEvent {
public:
    virtual ~CEvent();
};

class CEventVehicleDamageCollision : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventVehicleDamageCollision();
};

CEventVehicleDamageCollision::~CEventVehicleDamageCollision() {
}
