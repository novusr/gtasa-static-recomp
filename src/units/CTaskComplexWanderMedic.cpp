class CPed;

class CTask {
public:
    virtual ~CTask();
};

class CTaskComplex : public CTask {
public:
    virtual ~CTaskComplex();
};

class CTaskComplexWander : public CTaskComplex {
public:
    virtual ~CTaskComplexWander();
};

class CTaskComplexWanderMedic : public CTaskComplexWander {
public:
    virtual void DummyKeyFunction();
    virtual ~CTaskComplexWanderMedic();
    virtual void ScanForStuff(CPed* ped);
};
