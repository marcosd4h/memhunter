#include "common.h"

bool HunterSuspiciousThreads::Execute(HunterCommon::ProcessCollection &processesToAnalyze)
{
	bool ret = false;

	for (HunterCommon::ProcessCollection::const_iterator handleIt = processesToAnalyze.begin();
		handleIt != processesToAnalyze.end();
		++handleIt)
	{
		if (handleIt->first > 0)
		{
			HunterCommon::ProcessDataPtr procInfo = handleIt->second;

			//Only looking valid process and threads for current process
			if (procInfo->handle != NULL)
			{
				for (HunterCommon::ThreadsCollection::const_iterator threadIT = handleIt->second->threads.begin();
					threadIT != handleIt->second->threads.end();
					++threadIT)
				{
					DWORD threadID = threadIT->th32ThreadID;
					
					HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadID);
					if (hThread != NULL)
					{
						CustomWinTypes::THREAD_BASIC_INFORMATION threadInfo = { 0 };
						PVOID threadStartAddress = { 0 };

						if ((HunterHelpers::GetThreadBasicInfo(hThread, threadInfo)) &&
							(HunterHelpers::GetThreadStartAddress(hThread, threadStartAddress)))
						{
							HANDLE threadInfoPID = threadInfo.ClientId.UniqueProcess;
							HANDLE threadInfoTID = threadInfo.ClientId.UniqueThread;
							PVOID threadInfoTEBBaseAddress = threadInfo.TebBaseAddress;

							size_t startAddress = (size_t)threadStartAddress;
							MEMORY_BASIC_INFORMATION threadStartAddressMemoryInfo = { 0 };
							if (HunterHelpers::GetMemoryRegionInfo(procInfo->handle,
								startAddress,
								threadStartAddressMemoryInfo))
							{								
								SIZE_T threadMemoryRegionSize = threadStartAddressMemoryInfo.RegionSize;
								DWORD threadMemoryAllocationProtect = threadStartAddressMemoryInfo.AllocationProtect;
								DWORD threadMemoryProtection = threadStartAddressMemoryInfo.Protect;
								DWORD threadMemoryState = threadStartAddressMemoryInfo.State;
								DWORD threadMemoryType = threadStartAddressMemoryInfo.Type;

								//memstate can be 0 - MEM_COMMIT - MEM_FREE - MEM_RESERVE
								//memtype can be 0 - MEM_IMAGE - MEM_MAPPED - MEM_PRIVATE
								//memprotection can be 
								// PAGE_NOACCESS	"----"
								// PAGE_READONLY	"r---"
								// PAGE_READWRITE	"rw--"
								// PAGE_WRITECOPY	"rw-c"
								// PAGE_EXECUTE		"--x-"
								// PAGE_EXECUTE_READ		"r-x-"
								// PAGE_EXECUTE_READWRITE	"rwx-"
								// PAGE_EXECUTE_WRITECOPY	"rwxc"

								if ((threadMemoryState == MEM_COMMIT) &&
									(threadMemoryType != MEM_IMAGE) &&
									((threadMemoryProtection == PAGE_EXECUTE_WRITECOPY) || 
									 (threadMemoryProtection == PAGE_EXECUTE_READWRITE) ||
									 (threadMemoryAllocationProtect == PAGE_EXECUTE_WRITECOPY) ||
									 (threadMemoryAllocationProtect == PAGE_EXECUTE_READWRITE)))
								{
									
									HunterCommon::SuspiciousProcessDataPtr suspiciousElement = nullptr;
									if (ReportManager::GetInstance().GetReportElement(procInfo->pid, GetHunterID(), suspiciousElement) &&
										ReportManager::GetInstance().PopulateCommonFields(procInfo->pid, threadID, procInfo, suspiciousElement))
									{
										//Adding hunter specific information 										
										suspiciousElement->SetProcessName(procInfo->name);										
										std::wstring wstrModule(GetName());
										//suspiciousElement->AddThreadInformation(threadID, wstrModule);
										//suspiciousElement->AddModulesInformation(wstrModule);

										suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_NAME, wstrModule);
										suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_PATH, L"memory");
										suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_ID, std::to_wstring(threadID));
										suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_PRIORITY, std::to_wstring(GetThreadPriority(hThread)));
										suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_BASEADDR, GeneralHelpers::GetHexString((PVOID)startAddress));
										suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_MEMORY_PROT, GeneralHelpers::GetMemoryRegionProtection(threadMemoryProtection));
										suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_MEMORY_ALLOC_PROT, GeneralHelpers::GetMemoryRegionProtection(threadMemoryAllocationProtect));
										suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_MEMORY_STATE, GeneralHelpers::GetMemoryRegionState(threadMemoryState));
										suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_MEMORY_TYPE, GeneralHelpers::GetMemoryRegionType(threadMemoryType));
									}

									break; //breaks search of threads for current process
								}
							}
						}

						CloseHandle(hThread);
					}
				}
			}
		}
	}


	return ret;
}