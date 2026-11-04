struct TextureListing {
    unsigned short nameHash;
    unsigned short format;
    unsigned short width;
    unsigned short height : 15;
    unsigned short hasMipChain : 1;
};

struct TextureListingContainer {
    TextureListing listing;
    void* data;
    unsigned int dataSize;
    bool ownsData;

    ~TextureListingContainer();
};

extern "C" void free(void*);
TextureListingContainer::~TextureListingContainer() {
    void* p = data;
    if (ownsData) {
        free(p);
    }
    data = nullptr;
    dataSize = 0;
}
