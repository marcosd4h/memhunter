#pragma once

#include "common.h"

class HunterSuspiciousExports : public Hunter
{
public:
	bool Execute(HunterCommon::ProcessCollection &processesToAnalyze);

	HunterSuspiciousExports(UINT32 workerThreads) :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_EXPORTS,
			CustomTypes::HunterType::HUNT_OBSERVER,
			workerThreads) {}

	HunterSuspiciousExports() :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_EXPORTS,
			CustomTypes::HunterType::HUNT_OBSERVER,
			CustomDefs::DEFAULT_NR_WORKING_THREADS) {}

private:

};