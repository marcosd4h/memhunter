#include "common.h"


//Some References below
//https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_memory_basic_information
//https://docs.microsoft.com/en-us/windows/desktop/Memory/memory-protection-constants
//https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-createfilemappinga
//https://msdn.microsoft.com/en-us/library/ms809762.aspx


//Minjector test tool dissassemble shellcode from shellcodeinjector
//http://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=48+89+4c+24+08+48+89+54+24+10+4c+89+44+24+18+4c+89+4c+24+20+48+83+ec+38+48+b9+00+00+c6+74+6d+01+00+00+48+b8+00+0b+3f+be+f8+7f+00+00+ff+d0+48+83+c4+38+48+8b+4c+24+08+48+8b+54+24+10+4c+8b+44+24+18+4c+8b+4c+24+20+c3+48+89+4c+24+08+48+89+54+24+10+4c+89+44+24+18+4c+89+4c+24+20+48+83+ec+38+48+b8+00+00+c8+74+6d+01+00+00+ff+d0+48+83+c4+38+48+ba+00+00+c9+74+6d+01+00+00+48+89+02+48+8b+d0+48+c7+c1+00+00+00+00+48+b8+c0+0a+d0+c0+f8+7f+00+00+ff+d0+&arch=x86-64&endianness=little#disassembly

bool HunterSuspiciousShellcode::Execute(HunterCommon::ProcessCollection &processesToAnalyze)
{
	bool ret = false;

	HunterHelpers::RangesExclusionsManagement rangesToExclude;
	std::vector<HunterCommon::PatternData> patternsToLookFor;

	//Getting working system info
	SYSTEM_INFO	si = { 0 };
	GetSystemInfo(&si);

	//Adding patterns to look for
	patternsToLookFor.push_back({ { 0x55, 0x8b, 0xEC } , { 0x00 } , { 0x03 } }); //x86 prologue
	patternsToLookFor.push_back({ { 0x48, 0x89, 0x4C, 0x24 } ,{ 0x24 } ,{ 0x04 } }); //x64 prologue
	patternsToLookFor.push_back({ { 0x48, 0x83, 0xEC, 0x20 } ,{ 0x20 } ,{ 0x04 } }); //x64 prologue

	std::unordered_map<DWORD, bool> processesWithShellcode;

	//Building list of patterns to look for
	for (HunterCommon::ProcessCollection::const_iterator handleIt = processesToAnalyze.begin();
		handleIt != processesToAnalyze.end();
		++handleIt)
	{
		const DWORD procesdID = handleIt->first;
		blackbone::Process targetProc;

		if ((ConfigManager::GetInstance().IsValidPID(procesdID)) &&
			(targetProc.Attach(procesdID) == ERROR_SUCCESS) &&
			(targetProc.valid()))
		{
			HunterCommon::ProcessDataPtr procInfo = handleIt->second;

			rangesToExclude.Reset();

			//First build list of regions to exclude
			if ((procInfo->modules.size() > 0) &&
				(procInfo->handle != NULL))
			{
				//Exclude address space range used by process module
				for (HunterCommon::ModulesCollection::const_iterator moduleIT = procInfo->modules.begin();
					moduleIT != procInfo->modules.end();
					++moduleIT)
				{
					MEMORY_BASIC_INFORMATION addressMemoryInfo = { 0 };
					size_t moduleBaseAddr = (size_t)moduleIT->modBaseAddr;
					size_t moduleMaxAddr = (moduleBaseAddr + moduleIT->modBaseSize);
					
					if (HunterHelpers::GetMemoryRegionInfo(procInfo->handle, moduleBaseAddr, addressMemoryInfo))
					{
						rangesToExclude.AddNewRange(moduleBaseAddr,
							moduleMaxAddr,
							addressMemoryInfo.RegionSize);
							//CustomDefs::DEFAULT_PAGE_SIZE); //assuming pagesize to reduce performance hit
					}									
				}
			}

			//Now walking the remote process memory
			size_t minAddr = 0;
			size_t maxAddr = (size_t)(si.lpMaximumApplicationAddress);
			MEMORY_BASIC_INFORMATION addressMemoryInfo = { 0 };

			for (size_t addr = minAddr;
				 ((!processesWithShellcode[procInfo->pid]) &&
				 (addr < maxAddr) && 
				 (HunterHelpers::GetMemoryRegionInfo(procInfo->handle, addr, addressMemoryInfo)));
				addr += addressMemoryInfo.RegionSize)
			{
				PVOID regionBaseAddress = addressMemoryInfo.BaseAddress;
				DWORD regionAllocationProtect = addressMemoryInfo.AllocationProtect;
				DWORD regionProtection = addressMemoryInfo.Protect;
				DWORD regionState = addressMemoryInfo.State;
				DWORD regionType = addressMemoryInfo.Type;
				size_t regionSize = addressMemoryInfo.RegionSize;
				size_t regionMinAddress = (size_t)regionBaseAddress;
				size_t regionMaxAddress = regionMinAddress + regionSize;

				//Magic happens here
				if ((regionState == MEM_COMMIT) &&
//					((regionType == MEM_PRIVATE) || (regionType == MEM_MAPPED))  &&
					(regionType == MEM_PRIVATE)  &&
					((regionProtection == PAGE_EXECUTE_READWRITE) ||
					//(regionAllocationProtect == PAGE_EXECUTE_READWRITE) ||
					//(regionAllocationProtect == PAGE_EXECUTE_WRITECOPY) ||
					(regionProtection == PAGE_EXECUTE_WRITECOPY)) &&
					(!HunterHelpers::IsFuzzyPEHeaderPresent(procInfo->handle, addr, regionSize)) &&
					(!rangesToExclude.IsInRangeFastLookup(regionMinAddress)))
				{
					HunterCommon::SuspiciousProcessDataPtr suspiciousElement = nullptr;

					//if (false)
					{
						for (auto patternIT = patternsToLookFor.begin();
							patternIT != patternsToLookFor.end();
							patternIT++)
						{
							HunterCommon::PatternData worker = *patternIT;
							std::vector<blackbone::ptr_t> results;
							//Only scanning worker.patternSize bytes
							size_t nrFindings = worker.pattern.SearchRemote(targetProc, worker.wildcard, regionMinAddress, worker.patternSize, results);

							if (nrFindings > 0)
							{
								processesWithShellcode[procInfo->pid] = true;

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
									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_BASEADDR, GeneralHelpers::GetHexString((PVOID)regionBaseAddress));
									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_MEMORY_PROT, GeneralHelpers::GetMemoryRegionProtection(regionProtection));
									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_MEMORY_ALLOC_PROT, GeneralHelpers::GetMemoryRegionProtection(regionAllocationProtect));
									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_MEMORY_STATE, GeneralHelpers::GetMemoryRegionState(regionState));
									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_MEMORY_TYPE, GeneralHelpers::GetMemoryRegionType(regionType));
								}

								break;
							}
						}
					}
				}				
			}
		}
	}

	return ret;
}