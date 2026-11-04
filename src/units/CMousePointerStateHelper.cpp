struct MouseSetUp {
    int a;
    short b;
    char c;
    void* d;
    int e;
};

class CMousePointerStateHelper {
public:
    static MouseSetUp GetMouseSetUp();
};
