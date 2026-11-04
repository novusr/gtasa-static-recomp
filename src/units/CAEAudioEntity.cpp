class CAESound;

class CAEAudioEntity {
public:
    virtual ~CAEAudioEntity();
    virtual void UpdateParameters(CAESound*, short);
};
