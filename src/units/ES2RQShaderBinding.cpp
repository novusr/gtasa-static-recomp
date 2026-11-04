extern "C" int glGetUniformLocation(unsigned int, const char*);

struct ES2RQShaderBinding {
    int m_location;
    void Setup(unsigned int program, const char* name);
};
