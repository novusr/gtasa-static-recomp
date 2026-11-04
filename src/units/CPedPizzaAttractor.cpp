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

extern float ms_fPizzaOrderTime;
float CPedPizzaAttractor::GetHeadOfQueueWaitTime() {
    return 12345.0f;
}
