extern "C" int glGetUniformLocation(unsigned int, const char*);

struct ES2RQShaderBinding {
    int m_location;
    int Setup(unsigned int program, const char* name);
};

int ES2RQShaderBinding::Setup(unsigned int program, const char* name) {
    return m_location = glGetUniformLocation(program, name);
}
