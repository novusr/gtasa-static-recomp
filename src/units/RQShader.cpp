extern char pixelSrc[];
extern char vertexSrc[];

void BuildPixelSource(unsigned int);
void BuildVertexSource(unsigned int);

struct RQShader {
    static bool BuildSource(unsigned int a, const char** b, const char** c);
};


bool RQShader::BuildSource(unsigned int a, const char** b, const char** c) {
    return true;
}
