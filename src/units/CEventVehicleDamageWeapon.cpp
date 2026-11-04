class CEvent {
public:
    virtual ~CEvent();
};

class CEventVehicleDamageWeapon : public CEvent {
public:
    virtual void DummyKeyFunction();
    virtual ~CEventVehicleDamageWeapon();
};

CEventVehicleDamageWeapon::~CEventVehicleDamageWeapon() {
}
