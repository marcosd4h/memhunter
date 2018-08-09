#include "common.h"

bool HuntersOrchestration::Run()
{
	bool ret = false;

	try
	{
		HunterCommon::ProcessCollection systemProcesses;
		UINT32 nrWorkerThreads = ConfigManager::GetInstance().GetWorkerOrchestrationThreads();

		//clearing report elements
		ReportManager::GetInstance().Clear();

		if ((nrWorkerThreads > 0) && HunterHelpers::GetSystemProcessesData(systemProcesses))
		{
			//Initializing hunters
			auto suspiciousModulesHunter = std::make_shared<HunterSuspiciousModules>(ConfigManager::GetInstance().GetWorkerHunterThreads());
			auto suspiciousThreadHunter = std::make_shared<HunterSuspiciousThreads>(ConfigManager::GetInstance().GetWorkerHunterThreads());
			auto suspiciousRegions = std::make_shared<HunterSuspiciousRegions>(ConfigManager::GetInstance().GetWorkerHunterThreads());
			auto suspiciousCallStack = std::make_shared<HunterSuspiciousCallStack>(ConfigManager::GetInstance().GetWorkerHunterThreads());
			auto suspiciousExports = std::make_shared<HunterSuspiciousExports>(ConfigManager::GetInstance().GetWorkerHunterThreads());
			auto suspiciousRegistryPersistence = std::make_shared<HunterSuspiciousRegistryPersistence>(ConfigManager::GetInstance().GetWorkerHunterThreads());
			auto suspiciousHollows = std::make_shared<HunterSuspiciousHollowedModules>(ConfigManager::GetInstance().GetWorkerHunterThreads());
			auto suspiciousParents = std::make_shared<HunterSuspiciousParents>(ConfigManager::GetInstance().GetWorkerHunterThreads());
			auto suspiciousShellcode = std::make_shared<HunterSuspiciousShellcode>(ConfigManager::GetInstance().GetWorkerHunterThreads());
			
			//Adding Hunters to orchestrate
			m_hunterManager.AddHunter(suspiciousModulesHunter);
			m_hunterManager.AddHunter(suspiciousThreadHunter);
			m_hunterManager.AddHunter(suspiciousRegions);
			m_hunterManager.AddHunter(suspiciousCallStack);
			m_hunterManager.AddHunter(suspiciousExports);
			m_hunterManager.AddHunter(suspiciousRegistryPersistence);
			m_hunterManager.AddHunter(suspiciousHollows);
			m_hunterManager.AddHunter(suspiciousParents);
			m_hunterManager.AddHunter(suspiciousShellcode);
			
			//Running Hunters
			if (m_hunterManager.RunHunters(systemProcesses, nrWorkerThreads))
			{
				//Reporting findings
				const CustomTypes::ReportVerbosity verbosity = ConfigManager::GetInstance().GetReportVerbosity();
				const CustomTypes::ReportOutput mode = ConfigManager::GetInstance().GetReportOutput();

				if (ReportManager::GetInstance().ReportFindings(verbosity, mode))
				{
					TraceHelpers::TraceUp("Event succesfully reported!");
				}
				else
				{
					TraceHelpers::TraceDown("There was a problem reporting the findings!");
				}			
			}

			//Cleaning up
			HunterHelpers::CleanupSystemProcessData(systemProcesses);

			ret = true;
		}
		else
		{
			TraceHelpers::TraceConsoleDown("There was a problem grabbing system processes.");
		}
	}
	catch (const std::exception& e)
	{
		TraceHelpers::TraceConsoleDown("There was a problem executing hunters: %s", e.what());
	}
	catch (...)
	{
		TraceHelpers::TraceConsoleDown("There was a problem executing hunters");
	}

	return ret;
}