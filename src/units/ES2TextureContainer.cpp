extern "C" void glDeleteTextures(int, const unsigned int*);

class ES2TextureContainer {
public:
    void DeleteResource(unsigned int id);
};
