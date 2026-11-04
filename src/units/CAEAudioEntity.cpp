class CAESound {
public:
    ~CAESound();
};

class CAEAudioEntity {
public:
    virtual ~CAEAudioEntity();
    void* m_pEntity;
    CAESound m_sound;
    virtual void UpdateParameters(CAESound*, short);
};

void CAEAudioEntity::UpdateParameters(CAESound*, short) {
}

CAEAudioEntity::~CAEAudioEntity() {
}

