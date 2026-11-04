class CPedAttractor {
public:
    virtual ~CPedAttractor();
    virtual float GetHeadOfQueueWaitTime();
};

class CPedPizzaAttractor : public CPedAttractor {
public:
    virtual void DummyKeyFunction();
    virtual ~CPedPizzaAttractor();
    virtual float GetHeadOfQueueWaitTime();
};
