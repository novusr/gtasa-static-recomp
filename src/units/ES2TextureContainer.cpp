extern "C" void glDeleteTextures(int, const unsigned int*);

class ES2TextureContainer {
public:
    void DeleteResource(unsigned int id);
};

void ES2TextureContainer::DeleteResource(unsigned int id) {
    glDeleteTextures(1, &id);
}
