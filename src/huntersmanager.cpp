#include "common.h"

//TODO: Add threading support
bool HuntersManager::RunHunters(HunterCommon::ProcessCollection &processesToAnalyze, const UINT32 nrThreads)
{
	bool ret = false;

	if ((!processesToAnalyze.empty()) && (nrThreads > 0))
	{
		for (std::vector<CustomTypes::HunterPtr>::const_iterator hunterIt = m_hunters.begin();
			hunterIt != m_hunters.end();
			++hunterIt)
		{
			if (*hunterIt != nullptr)
			{
				CustomTypes::HunterPtr hunter = *hunterIt;

				if (ConfigManager::GetInstance().IsHunterEnabled(hunter->GetHunterID()))
				{
					hunter->Execute(processesToAnalyze);
				}

				ret = true;
			}
		}
	}

	return ret;
}

