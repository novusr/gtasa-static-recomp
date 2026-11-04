class CTask {
public:
    virtual ~CTask();
};

class CPed;

class CPedTaskPair {
public:
    CPed* m_pPed;
    CTask* m_pTask;
    int m_taskType;

    void Flush();
};
