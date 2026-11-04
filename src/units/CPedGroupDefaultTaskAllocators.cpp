class CPedGroupDefaultTaskAllocator {};
class CPedGroupDefaultTaskAllocatorFollowAnyMeans : public CPedGroupDefaultTaskAllocator {};
class CPedGroupDefaultTaskAllocatorFollowLimited : public CPedGroupDefaultTaskAllocator {};
class CPedGroupDefaultTaskAllocatorStandStill : public CPedGroupDefaultTaskAllocator {};
class CPedGroupDefaultTaskAllocatorChat : public CPedGroupDefaultTaskAllocator {};
class CPedGroupDefaultTaskAllocatorSitInLeaderCar : public CPedGroupDefaultTaskAllocator {};
class CPedGroupDefaultTaskAllocatorRandom : public CPedGroupDefaultTaskAllocator {};

class CPedGroupDefaultTaskAllocators {
public:
    static CPedGroupDefaultTaskAllocatorFollowAnyMeans ms_followAnyMeansAllocator;
    static CPedGroupDefaultTaskAllocatorFollowLimited ms_followLimitedAllocator;
    static CPedGroupDefaultTaskAllocatorStandStill ms_standStillAllocator;
    static CPedGroupDefaultTaskAllocatorChat ms_chatAllocator;
    static CPedGroupDefaultTaskAllocatorSitInLeaderCar ms_sitInLeaderCarAllocator;
    static CPedGroupDefaultTaskAllocatorRandom ms_randomAllocator;

    static CPedGroupDefaultTaskAllocator* Get(int id);
};
