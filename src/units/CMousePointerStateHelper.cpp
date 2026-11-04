struct MouseSetUp {
    int a;
    short b;
    char c;
    int d;
    int e;
    int f;
};

class CMousePointerStateHelper {
public:
    static MouseSetUp GetMouseSetUp();
};

MouseSetUp CMousePointerStateHelper::GetMouseSetUp() {
    MouseSetUp res;
    res.d = 0;
    res.e = 0;
    res.f = 0;
    res.a = 0;
    res.c = 0;
    res.b = 0;
    return res;
}
