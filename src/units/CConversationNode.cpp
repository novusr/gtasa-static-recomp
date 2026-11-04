class CConversationNode {
public:
    char m_Name[8];
    short m_NodeYes;
    short m_NodeNo;
    int m_Speech;
    int m_SpeechY;
    int m_SpeechN;

    void Clear();
    void ClearRecursively();
};

class CConversations {
public:
    static CConversationNode m_aNodes[];
};
