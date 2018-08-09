#pragma once

#include "common.h"

class Hunter
{
public:
	virtual bool Execute(HunterCommon::ProcessCollection &processesToAnalyze) = 0;  //processesToAnalyze is not const arg as hunters will 
																					//cooperate to each other appending info when needed

	const wchar_t *GetName()
	{
		return HunterHelpers::HunterIDToString(m_hunterID);
	}

	const CustomTypes::HunterType GetType()
	{
		return m_hunterType;
	}

	const UINT32 GetWorkerThreads()
	{
		return m_nrWorkerThreads;
	}

	const CustomTypes::HunterID GetHunterID()
	{
		return m_hunterID;
	}

	Hunter(CustomTypes::HunterID hunterID, CustomTypes::HunterType hunterType, UINT32 workerThreads)  :
		m_hunterID(hunterID), m_hunterType(hunterType), m_nrWorkerThreads(workerThreads) {}

	Hunter() :
		m_hunterID(CustomTypes::HunterID::HUNT_NA),
		m_hunterType(CustomTypes::DEFAULT_HUNTER_TYPE),
		m_nrWorkerThreads(CustomDefs::DEFAULT_NR_WORKING_THREADS) {}

	static bool IsValidHunterID(const CustomTypes::HunterID &hunterID)
	{
		bool ret = false;

		if ((hunterID >= CustomTypes::HunterID::HUNT_SUSPICIOUS_THREADS) &&
			(hunterID < CustomTypes::HunterID::HUNT_NA))
		{
			ret = true;
		}

		return ret;
	}

private:
	CustomTypes::HunterID m_hunterID;
	CustomTypes::HunterType m_hunterType; //Not used at this point
	UINT32 m_nrWorkerThreads;
};

namespace CustomTypes
{
	typedef std::shared_ptr<Hunter> HunterPtr;
}