class ANDThreadData {
public:
    static void Destroy(void*);
};

void ANDThreadData::Destroy(void* ptr) {
    delete static_cast<ANDThreadData*>(ptr);
}
