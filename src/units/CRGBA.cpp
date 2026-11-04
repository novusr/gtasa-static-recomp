class CRGBA {
public:
    unsigned char r, g, b, a;
    CRGBA(unsigned char r, unsigned char g, unsigned char b, unsigned char a);
};

CRGBA::CRGBA(unsigned char r, unsigned char g, unsigned char b, unsigned char a) {
    this->r = r;
    this->g = g;
    this->b = b;
    this->a = a;
}
