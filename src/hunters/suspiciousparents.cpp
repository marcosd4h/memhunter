#include "common.h"


bool IsParentSuspicious(const std::wstring &parent, const std::wstring &process)
{
	bool ret = false;

	if (GeneralHelpers::StrCompare(process, L"svchost.exe") && 
		!GeneralHelpers::StrCompare(parent, L"services.exe"))
	{
		ret = true;
	}
	else if (GeneralHelpers::StrCompare(process, L"services.exe") &&
			 !GeneralHelpers::StrCompare(parent, L"wininit.exe"))
	{
		ret = true;
	}
	else if (GeneralHelpers::StrCompare(process, L"services.exe") &&
		!GeneralHelpers::StrCompare(parent, L"wininit.exe"))
	{
		ret = true;
	}

	return ret;
}


bool HunterSuspiciousParents::Execute(HunterCommon::ProcessCollection &processesToAnalyze)
{
	bool ret = false;

	//Building parents list
	std::unordered_map<DWORD, std::wstring> parentsCollection;
	for (HunterCommon::ProcessCollection::const_iterator processElementIt = processesToAnalyze.begin();
		processElementIt != processesToAnalyze.end();
		++processElementIt)
	{
		if ((processElementIt->first > 0))
		{
			HunterCommon::ProcessDataPtr procInfo = processElementIt->second;
			parentsCollection.insert({ procInfo->pid, procInfo->name });
		}
	}


	for (HunterCommon::ProcessCollection::const_iterator processElementIt = processesToAnalyze.begin();
		processElementIt != processesToAnalyze.end();
		++processElementIt)
	{
		const DWORD processID = processElementIt->first;
		if (processID > 0)
		{
			HunterCommon::ProcessDataPtr procInfo = processElementIt->second;

			//Only looking active process
			if ((procInfo->handle != INVALID_HANDLE_VALUE) &&
				(procInfo->bbProcessReady) &&
				(procInfo->bbProcess.valid()))
			{
				//Getting parent pid name
				DWORD parentPid = 0;
				if ((HunterHelpers::GetParentPid(processID, parentPid)) && 
					(!parentsCollection[parentPid].empty()))
				{
					std::wstring processName = GeneralHelpers::GetBaseFileName(procInfo->name);
					std::wstring parentProcessName = GeneralHelpers::GetBaseFileName(parentsCollection[parentPid]);

					//magic happens here
					if(IsParentSuspicious(parentProcessName, processName))
					{
						HunterCommon::SuspiciousProcessDataPtr suspiciousElement = nullptr;
						if (ReportManager::GetInstance().GetReportElement(procInfo->pid, GetHunterID(), suspiciousElement) &&
							ReportManager::GetInstance().PopulateCommonFields(procInfo->pid, 0, procInfo, suspiciousElement))
						{
							//Adding hunter specific information 										
							suspiciousElement->SetProcessName(procInfo->name);
							std::wstring wstrModule(GetName());

							suspiciousElement->AddNewProperty(L"Parent PID", std::to_wstring(parentPid));
							suspiciousElement->AddNewProperty(L"Parent Process", parentProcessName);
						}
					}
					
				}
			}

			ret = true;
		}
	}


	return ret;
}