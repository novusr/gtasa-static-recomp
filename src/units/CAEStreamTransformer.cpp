class CAEStreamTransformer {
public:
    unsigned char m_key[16];

    void Initialise();
    void TransformBuffer(void* buffer, unsigned long size, unsigned long offset);
};
