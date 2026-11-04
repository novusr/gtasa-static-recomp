class CPedGroupDefaultTaskAllocator;
class CPedGroupDefaultTaskAllocatorFollowAnyMeans;
class CPedGroupDefaultTaskAllocatorFollowLimited;
class CPedGroupDefaultTaskAllocatorStandStill;
class CPedGroupDefaultTaskAllocatorChat;
class CPedGroupDefaultTaskAllocatorSitInLeaderCar;
class CPedGroupDefaultTaskAllocatorRandom;

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
