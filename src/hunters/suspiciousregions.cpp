#include "common.h"

bool HunterSuspiciousRegions::Execute(HunterCommon::ProcessCollection &processesToAnalyze)
{
	bool ret = false;

	for (HunterCommon::ProcessCollection::const_iterator processElementIt = processesToAnalyze.begin();
		processElementIt != processesToAnalyze.end();
		++processElementIt)
	{
		if (processElementIt->first > 0)
		{
			HunterCommon::ProcessDataPtr procInfo = processElementIt->second;

			//Only looking active process
			if ((procInfo->handle != INVALID_HANDLE_VALUE) && 
				(procInfo->bbProcess.valid()) && 
				(!procInfo->isManaged))
			{
				//Populating list of modules to analyze
				if ((HunterHelpers::PopulateModulesIfNeededByMemorySections(procInfo)) &&
//					(HunterHelpers::PopulateModulesIfNeededByWalkingPEHeaders(procInfo)) &&
//					(procInfo->bbModulesPEHeaders.size() > 0) &&
					(procInfo->bbModulesSections.size() > 0))
				{
					//Getting found sections in memory
					const blackbone::ProcessModules::mapModules& procModules = procInfo->bbModulesSections;
					for (auto moduleIT = procModules.begin(); moduleIT != procModules.end(); ++moduleIT)
					{
						const blackbone::ModuleDataPtr modulePtr = moduleIT->second;

						//std::wstring basenameDLLToAnalyze;
						//std::wstring fullPathDLLToAnalyze(modulePtr->fullPath);

						if (modulePtr->type == blackbone::eModType::mt_unknown)
						{
							HunterCommon::SuspiciousProcessDataPtr suspiciousElement = nullptr;
							if (ReportManager::GetInstance().GetReportElement(procInfo->pid, GetHunterID(), suspiciousElement) &&
								ReportManager::GetInstance().PopulateCommonFields(procInfo->pid, 0, procInfo, suspiciousElement))
							{
								//Adding hunter specific information 										
								suspiciousElement->SetProcessName(procInfo->name);
								std::wstring wstrModule(GetName());
								suspiciousElement->AddModulesInformation((std::wstring)modulePtr->name);

								suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_NAME, wstrModule);
								suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_PATH, modulePtr->fullPath);
								suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_BASEADDR, GeneralHelpers::GetHexString((PVOID)modulePtr->baseAddress));
							}

						}
					}
				}
			}

			ret = true;
		}
	}

	return ret;
}