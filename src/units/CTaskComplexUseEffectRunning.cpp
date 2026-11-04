class CTask {
public:
    virtual ~CTask();
};

class CTaskComplex : public CTask {
public:
    virtual ~CTaskComplex();
};

extern void* func1();
extern void func2(void*, void*, void*);
extern void func3(void*, void*);

class CTaskComplexUseEffect : public CTaskComplex {
public:
    char pad[0x18];
    void* m_pSubTask; // 0x20
    void* m_field28;  // 0x28
    void* m_field30;  // 0x30
    virtual ~CTaskComplexUseEffect() {
        if (m_field30 && m_field28) {
            func2(func1(), m_field30, m_field28);
        }
        if (m_pSubTask) {
            func3(m_pSubTask, &m_pSubTask);
        }
    }
};

class CTaskComplexUseEffectRunning : public CTaskComplexUseEffect {
public:
    virtual void DummyKeyFunction();
    virtual ~CTaskComplexUseEffectRunning();
};

CTaskComplexUseEffectRunning::~CTaskComplexUseEffectRunning() {
    if (m_field30 != nullptr && m_field28 != nullptr) {
        func2(func1(), m_field30, m_field28);
    }
    if (m_pSubTask != nullptr) {
        func3(m_pSubTask, &m_pSubTask);
    }
}
