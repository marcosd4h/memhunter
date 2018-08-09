#include "common.h"

bool HunterSuspiciousRegistryPersistence::Execute(HunterCommon::ProcessCollection &processesToAnalyze)
{
	bool ret = false;

	HunterHelpers::ModuleExclusionsManagement exclusionManager;
	return ret;
	bool AppInitDLLPersistenceReadyForHunting = false;
	bool IFEODLLPersistenceReadyForHunting = false;
	const std::wstring subKeyAppInitDLL = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
	//const std::wstring subKeyIFEO = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
	const std::wstring appInitSubValue = L"AppInit_DLLs";
	const std::wstring loadAppInitSubValue = L"LoadAppInit_DLLs";
	std::vector<std::wstring> ListOfHuntedDLLs;

	DWORD valueLoadAppInit = 0;
	std::wstring valueAppInitDLL;
	
	ListOfHuntedDLLs.clear();

	//Checking for LoadAppInit Persistence method Presence
	if (RegistryHelpers::RegistryValueExists(HKEY_LOCAL_MACHINE, subKeyAppInitDLL, loadAppInitSubValue) && 
		RegistryHelpers::RegistryValueExists(HKEY_LOCAL_MACHINE, subKeyAppInitDLL, appInitSubValue) && 
		RegistryHelpers::GetRegDWORDValue(HKEY_LOCAL_MACHINE, subKeyAppInitDLL, loadAppInitSubValue, valueLoadAppInit) &&
		valueLoadAppInit >= 1 && // AppInitDLL is disabled if LoadAppInit_DLLs is set to 0
		RegistryHelpers::GetRegStringValue(HKEY_LOCAL_MACHINE, subKeyAppInitDLL, appInitSubValue, valueAppInitDLL) &&
		!valueAppInitDLL.empty() &&
		valueAppInitDLL.size() > 3 // Injection is not triggered if AppInit_DLLs is empty or it is filled with spaces
		)
	{
		std::vector<std::wstring> vecSpacesListDlls;
		std::vector<std::wstring> vecCommasListDlls;

		//Splitting AppInit_DLLs by space
		if (GeneralHelpers::GetVectorByToken(valueAppInitDLL, L' ', vecSpacesListDlls) &&
			vecSpacesListDlls.size() > 0)
		{
			for (auto it = vecSpacesListDlls.begin(); it != vecSpacesListDlls.end(); ++it)
			{
				const std::wstring &elementDLL(*it);
				std::wstring baseFilenameElementDLL;
				//if (!elementDLL.empty() && GeneralHelpers::IsValidFile(elementDLL) && GeneralHelpers::GetBaseFileName(elementDLL, baseFilenameElementDLL))
				if (!elementDLL.empty() && GeneralHelpers::GetBaseFileName(elementDLL, baseFilenameElementDLL))
				{
					ListOfHuntedDLLs.push_back(baseFilenameElementDLL);
				}
			}			
		}

		//Splitting AppInit_DLLs by comma
		if (GeneralHelpers::GetVectorByToken(valueAppInitDLL, L',', vecCommasListDlls) &&
			vecCommasListDlls.size() > 0)
		{
			for (auto it = vecCommasListDlls.begin(); it != vecCommasListDlls.end(); ++it)
			{
				const std::wstring &elementDLL(*it);
				std::wstring baseFilenameElementDLL;
				//if (!elementDLL.empty() && GeneralHelpers::IsValidFile(elementDLL) && GeneralHelpers::GetBaseFileName(elementDLL, baseFilenameElementDLL))
				if (!elementDLL.empty() && GeneralHelpers::GetBaseFileName(elementDLL, baseFilenameElementDLL))
				{					
					ListOfHuntedDLLs.push_back(baseFilenameElementDLL);
				}
			}
		}

		//Checking if we got any finding
		if (ListOfHuntedDLLs.size() > 0)
		{
			AppInitDLLPersistenceReadyForHunting = true;
		}
	}


	//There are things to look for
	if (AppInitDLLPersistenceReadyForHunting)
	{	 
		for (HunterCommon::ProcessCollection::const_iterator processElementIt = processesToAnalyze.begin();
			processElementIt != processesToAnalyze.end();
			++processElementIt)
		{
			if (processElementIt->first > 0)
			{
				HunterCommon::ProcessDataPtr procInfo = processElementIt->second;

				//Only looking active process
				if ((procInfo->handle != INVALID_HANDLE_VALUE) && (procInfo->bbProcess.valid()) && (!procInfo->isManaged))
				{
					//using mapModules = std::unordered_map<std::pair<std::wstring, eModType>, ModuleDataPtr>;
					//std::shared_ptr<const ModuleData>

					const blackbone::ProcessModules::mapModules& procModules = procInfo->bbProcess.modules().GetAllModules();
					for (auto moduleIT = procModules.begin(); moduleIT != procModules.end(); ++moduleIT)
					{
						const blackbone::ModuleDataPtr modulePtr = moduleIT->second;

						std::wstring basenameDLLToAnalyze;
						std::wstring fullPathDLLToAnalyze(modulePtr->fullPath);

						if (!fullPathDLLToAnalyze.empty() && 
							GeneralHelpers::GetBaseFileName(fullPathDLLToAnalyze, basenameDLLToAnalyze) && 
							!basenameDLLToAnalyze.empty())
						{
							if (GeneralHelpers::IsElementPresentOnList(ListOfHuntedDLLs, basenameDLLToAnalyze))
							{
								//found here!
								HunterCommon::SuspiciousProcessDataPtr suspiciousElement = nullptr;
								if (ReportManager::GetInstance().GetReportElement(procInfo->pid, GetHunterID(), suspiciousElement) &&
									ReportManager::GetInstance().PopulateCommonFields(procInfo->pid, 0, procInfo, suspiciousElement))
								{
									//Adding hunter specific information 										
									suspiciousElement->SetProcessName(procInfo->name);
									std::wstring wstrModule(GetName());
									suspiciousElement->AddModulesInformation(wstrModule);

									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_NAME, wstrModule);
									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_PATH, L"memory");
								}
								
							}								
						}
					}
				}

				ret = true;
			}
		}
	}



	return ret;
}