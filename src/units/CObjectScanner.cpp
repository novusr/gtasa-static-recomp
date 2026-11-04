struct CPedFlags {
    unsigned int bIsStanding : 1;
    unsigned int bWasStanding : 1;
    unsigned int bIsLooking : 1;
    unsigned int bIsRestoringLook : 1;
    unsigned int bIsAimingGun : 1;
    unsigned int bIsRestoringGun : 1;
    unsigned int bCanPointGunAtTarget : 1;
    unsigned int bIsTalking : 1;
    unsigned int bInVehicle : 1;
};

class CVehicle;

class CPed {
public:
    char pad[0x584];
    CPedFlags m_nPedFlags;
    char pad2[0x708 - 0x584 - sizeof(CPedFlags)];
    CVehicle* m_pMyVehicle;

    bool IsAlive() const;
};

class CEntityScanner {
public:
    void ScanForEntitiesInRange(int, const CPed&);
};

class CObjectScanner : public CEntityScanner {
public:
    void ScanForObjectsInRange(const CPed&);
};
