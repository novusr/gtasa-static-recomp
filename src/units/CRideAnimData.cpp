class CRideAnimData {
public:
    int m_animGroup;
    float m_fBarSteerAngle;
    float m_fLeanAngle;
    float m_fDesiredLeanAngle;
    float m_fLeanFwd;
    float m_fAnimLeanLeft;
    float m_fAnimLeanFwd;

    CRideAnimData();
    ~CRideAnimData();
};

CRideAnimData::~CRideAnimData() {
}
