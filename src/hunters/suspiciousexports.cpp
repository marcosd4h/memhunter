#include "common.h"


bool HunterSuspiciousExports::Execute(HunterCommon::ProcessCollection &processesToAnalyze)
{
	bool ret = false;

	std::vector<std::wstring> exportsToLookFor;
	exportsToLookFor.push_back(L"NextHook");
	exportsToLookFor.push_back(L"ReflectiveLoader");

	HunterHelpers::ModuleExclusionsManagement exclusionManager;
		 
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

					const std::wstring &moduleFullPath = modulePtr->fullPath;
					if (!exclusionManager.ShouldBeExcluded(moduleFullPath))
					{
						//const std::wstring &moduleName = moduleIT->first.first;
						//const blackbone::eModType &moduleType = moduleIT->first.second;
			
						blackbone::pe::PEImage moduleFile;
						if ((moduleFile.Load(moduleFullPath) == ERROR_SUCCESS) && (!moduleFile.isExe()))
						{
							blackbone::pe::vecExports moduleExports;
							moduleFile.GetExports(moduleExports);

							if (moduleExports.size() > 0)
							{
								for (auto exportIT = moduleExports.begin(); exportIT != moduleExports.end(); ++exportIT)
								{
									blackbone::pe::ExportData data(*exportIT);
								    std::wstring exportName = GeneralHelpers::StrToWStr(data.name);

									//TODO: Add check against list of target modules
									for (auto expIt = exportsToLookFor.begin();
										 expIt != exportsToLookFor.end();
										 expIt++)
									{
										std::wstring workingStr = *expIt;
										if (GeneralHelpers::StrCompare(workingStr, exportName))
										{
											HunterCommon::SuspiciousProcessDataPtr suspiciousElement = nullptr;
											if (ReportManager::GetInstance().GetReportElement(procInfo->pid, GetHunterID(), suspiciousElement) &&
												ReportManager::GetInstance().PopulateCommonFields(procInfo->pid, 0, procInfo, suspiciousElement))
											{
												//Adding hunter specific information 										
												suspiciousElement->SetProcessName(procInfo->name);
												std::wstring wstrModule(moduleFullPath);
												suspiciousElement->AddModulesInformation(wstrModule);

												suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_NAME, GeneralHelpers::GetBaseFileName(moduleFullPath));
												suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_PATH, moduleFullPath);
												suspiciousElement->AddNewProperty(L"Export Found", exportName);											
												break;
											}
										}
									}									
								}
							}
						}

						exclusionManager.AddToExclusions(moduleFullPath); //Already parsed
					}
				}
			}

			ret = true;
		}
	}

	return ret;
}