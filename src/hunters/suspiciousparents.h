#pragma once

#include "common.h"

class HunterSuspiciousParents : public Hunter
{
public:
	bool Execute(HunterCommon::ProcessCollection &processesToAnalyze);

	HunterSuspiciousParents(UINT32 workerThreads) :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_PARENTS,
			CustomTypes::HunterType::HUNT_OBSERVER,
			workerThreads) {}

	HunterSuspiciousParents() :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_PARENTS,
			CustomTypes::HunterType::HUNT_OBSERVER,
			CustomDefs::DEFAULT_NR_WORKING_THREADS) {}

private:

};