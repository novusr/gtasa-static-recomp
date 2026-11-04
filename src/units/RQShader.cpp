extern __attribute__((visibility("hidden"))) char pixelSrc[];
extern __attribute__((visibility("hidden"))) char vertexSrc[];

void BuildPixelSource(unsigned int);
void BuildVertexSource(unsigned int);

struct RQShader {
    static bool BuildSource(unsigned int a, const char** b, const char** c);
};


bool RQShader::BuildSource(unsigned int a, const char** b, const char** c) {
    pixelSrc[0] = '\0';
    vertexSrc[0] = '\0';
    BuildPixelSource(a);
    BuildVertexSource(a);
    *b = pixelSrc;
    *c = vertexSrc;
    return true;
}
