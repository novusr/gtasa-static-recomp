class CTask {
public:
    virtual ~CTask();
};

class CTaskComplex : public CTask {
public:
    virtual ~CTaskComplex();
};

extern void func1();
extern void func2(void*, void*, void*);
extern void func3(void*);

class CTaskComplexUseEffectRunning : public CTaskComplex {
public:
    virtual void DummyKeyFunction();
    void* m_pSubTask; // 0x20
    void* m_field28;  // 0x28
    void* m_field30;  // 0x30
    virtual ~CTaskComplexUseEffectRunning();
};
