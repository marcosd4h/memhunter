#pragma once

#include "common.h"

class HunterSuspiciousCallStack : public Hunter
{
public:
	bool Execute(HunterCommon::ProcessCollection &processesToAnalyze);

	HunterSuspiciousCallStack(UINT32 workerThreads) :
		Hunter(	
			CustomTypes::HunterID::HUNT_SUSPICIOUS_CALLSTACK,
			CustomTypes::HunterType::HUNT_OBSERVER, 
			workerThreads) {}

	HunterSuspiciousCallStack() :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_CALLSTACK,
			CustomTypes::HunterType::HUNT_OBSERVER, 
			CustomDefs::DEFAULT_NR_WORKING_THREADS) {}

private:

};