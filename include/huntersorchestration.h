#pragma once

#include "common.h"

class HuntersOrchestration
{

public:
	static HuntersOrchestration& GetInstance()
	{
		static HuntersOrchestration instance;
		return instance;
	}

	HuntersManager &GetHunterManager() { return m_hunterManager; }

	bool Run(void);

private:
	HuntersOrchestration(): m_hunterManager(){};

	HuntersOrchestration(const HuntersOrchestration&) = delete;
	HuntersOrchestration& operator = (const HuntersOrchestration&) = delete;

	HuntersManager m_hunterManager;
};