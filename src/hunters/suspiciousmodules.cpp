#include "common.h"

//Some References below
//https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_memory_basic_information
//https://docs.microsoft.com/en-us/windows/desktop/Memory/memory-protection-constants
//https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-createfilemappinga
//https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/ns-tlhelp32-tagmoduleentry32

bool HunterSuspiciousModules::Execute(HunterCommon::ProcessCollection &processesToAnalyze)
{
	bool ret = false;

	HunterHelpers::ModuleExclusionsManagement exclusionManager;

	for (HunterCommon::ProcessCollection::const_iterator handleIt = processesToAnalyze.begin();
		handleIt != processesToAnalyze.end();
		++handleIt)
	{
		if (handleIt->first > 0)
		{
			HunterCommon::ProcessDataPtr procInfo = handleIt->second;

			if ((procInfo->modules.size() > 0) &&
				(procInfo->handle != NULL))
			{
				bool suspiciousProcessFound = false;

				for (HunterCommon::ModulesCollection::const_iterator moduleIT = procInfo->modules.begin();
					moduleIT != procInfo->modules.end();
					++moduleIT)
				{
					//Checking if this module needs to be excluded due to common exclusion policies
					if (!exclusionManager.ShouldBeExcluded(moduleIT->szExePath))
					{
						MEMORY_BASIC_INFORMATION addressMemoryInfo = { 0 };
						size_t moduleBaseAddr = (size_t)moduleIT->modBaseAddr;
						size_t moduleMaxAddr = (moduleBaseAddr + moduleIT->modBaseSize);

						for (size_t addr = moduleBaseAddr;
							((addr < moduleMaxAddr) && (HunterHelpers::GetMemoryRegionInfo(procInfo->handle, addr, addressMemoryInfo)));
							addr += addressMemoryInfo.RegionSize)
						{
							DWORD moduleMemoryAllocationProtect = addressMemoryInfo.AllocationProtect;
							DWORD moduleMemoryProtection = addressMemoryInfo.Protect;
							DWORD moduleMemoryState = addressMemoryInfo.State;
							DWORD moduleMemoryType = addressMemoryInfo.Type;

							if ((moduleMemoryState == MEM_COMMIT) &&
								(moduleMemoryType == MEM_IMAGE) &&
								((moduleMemoryProtection == PAGE_EXECUTE_WRITECOPY) || 
								(moduleMemoryProtection == PAGE_EXECUTE_READWRITE)) &&
								(GeneralHelpers::IsValidFile(moduleIT->szExePath)) &&
								(!HunterHelpers::IsTrustedFile(moduleIT->szExePath)))
							{
								suspiciousProcessFound = true;

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
									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_BASEADDR, GeneralHelpers::GetHexString((PVOID)moduleBaseAddr));
								}

								break; //breaks search of memory regions with the module 
							}
						}

						if (suspiciousProcessFound)
						{
							break; // breaks modules per process iteration
						}
					}
				}
			}
		}
	}


	return ret;
}
