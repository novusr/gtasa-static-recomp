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

class CTaskComplexBeCop : public CTaskComplexWander {
public:
    char pad[0x30];
    CTask* m_pSubTask;
    virtual ~CTaskComplexBeCop();
};

CTaskComplexBeCop::~CTaskComplexBeCop() {
    delete m_pSubTask;
}
