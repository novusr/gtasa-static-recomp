class CAESound;

class CAEAudioEntity {
public:
    virtual ~CAEAudioEntity();
    virtual void UpdateParameters(CAESound*, short);
};

void CAEAudioEntity::UpdateParameters(CAESound*, short) {
}
