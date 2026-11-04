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
    return {};
}
