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

void CConversationNode::Clear() {
    m_Name[0] = 0;
    m_NodeYes = -1;
    m_NodeNo = -1;
    m_Speech = 0;
    m_SpeechY = 0;
    m_SpeechN = 0;
}
