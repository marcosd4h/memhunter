#pragma once

#include "common.h"

class HunterSuspiciousShellcode : public Hunter
{
public:
	bool Execute(HunterCommon::ProcessCollection &processesToAnalyze);

	HunterSuspiciousShellcode(UINT32 workerThreads) :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_SHELLCODE,
			CustomTypes::HunterType::HUNT_OBSERVER,
			workerThreads) {}

	HunterSuspiciousShellcode() :
		Hunter(
			CustomTypes::HunterID::HUNT_SUSPICIOUS_SHELLCODE,
			CustomTypes::HunterType::HUNT_OBSERVER,
			CustomDefs::DEFAULT_NR_WORKING_THREADS) {}

private:

};