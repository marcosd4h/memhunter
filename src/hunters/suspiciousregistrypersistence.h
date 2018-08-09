#pragma once

#include "common.h"


class HunterSuspiciousRegistryPersistence : public Hunter
{
public:
	bool Execute(HunterCommon::ProcessCollection &processesToAnalyze);

	HunterSuspiciousRegistryPersistence(UINT32 workerThreads) :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_REGISTRY_PERSISTENCE,
			CustomTypes::HunterType::HUNT_OBSERVER,
			workerThreads) {}

	HunterSuspiciousRegistryPersistence() :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_REGISTRY_PERSISTENCE,
			CustomTypes::HunterType::HUNT_OBSERVER,
			CustomDefs::DEFAULT_NR_WORKING_THREADS) {}

private:

};