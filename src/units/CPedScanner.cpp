class CPed {
public:
    bool IsAlive() const;
};

class CEntityScanner {
public:
    void ScanForEntitiesInRange(int, const CPed&);
};

class CPedScanner : public CEntityScanner {
public:
    void ScanForPedsInRange(const CPed&);
};
