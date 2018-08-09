#pragma once

#include "common.h"

class HunterSuspiciousHollowedModules : public Hunter
{
public:
	bool Execute(HunterCommon::ProcessCollection &processesToAnalyze);

	HunterSuspiciousHollowedModules(UINT32 workerThreads) :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_HOLLOWS,
			CustomTypes::HunterType::HUNT_OBSERVER,
			workerThreads) {}

	HunterSuspiciousHollowedModules() :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_HOLLOWS,
			CustomTypes::HunterType::HUNT_OBSERVER,
			CustomDefs::DEFAULT_NR_WORKING_THREADS) {}

private:

};