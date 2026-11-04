class ListItem_c {
public:
    ListItem_c* m_pPrev;
    ListItem_c* m_pNext;

    ListItem_c();
    ~ListItem_c();
};

ListItem_c::~ListItem_c() {
}
