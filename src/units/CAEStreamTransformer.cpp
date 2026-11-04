class CAEStreamTransformer {
public:
    unsigned char m_key[16];

    void Initialise();
    void TransformBuffer(void* buffer, unsigned long size, unsigned long offset);
};

void CAEStreamTransformer::Initialise() {
    alignas(16) static const unsigned char key[16] = {1};
    *(CAEStreamTransformer*)this = *(const CAEStreamTransformer*)key;
}

void CAEStreamTransformer::TransformBuffer(void* buffer, unsigned long size, unsigned long offset) {
    for (unsigned long i = 0; i < size; ++i) {
        ((unsigned char*)buffer)[i] ^= m_key[(offset + i) & 0xF];
    }
}

