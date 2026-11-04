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

CRideAnimData::CRideAnimData()
    : m_animGroup(0),
      m_fBarSteerAngle(0.0f),
      m_fLeanAngle(0.0f),
      m_fDesiredLeanAngle(0.0f),
      m_fLeanFwd(0.0f),
      m_fAnimLeanLeft(0.0f),
      m_fAnimLeanFwd(0.0f) {
}

CRideAnimData::~CRideAnimData() {
}
