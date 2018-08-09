#pragma once

#include "common.h"

class HuntersManager
{
public:
	HuntersManager() {};

	template <typename T>
	void AddHunter(std::shared_ptr<T>& hunter)
	{
		m_hunters.push_back(hunter);
	}

	bool RunHunters(HunterCommon::ProcessCollection &processesToAnalyze, const UINT32 nrThreads);

private:
	HuntersManager(const HuntersManager&) {};

	std::vector<CustomTypes::HunterPtr> m_hunters;
};