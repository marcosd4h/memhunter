#include "common.h"

bool HunterSuspiciousHollowedModules::Execute(HunterCommon::ProcessCollection &processesToAnalyze)
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
				(procInfo->bbPEReady) &&
				(procInfo->bbProcessReady) &&
				(procInfo->bbProcess.valid()) && 
				(!procInfo->isManaged) &&
				(procInfo->bbModulesLdrList.size() > 0))
			{
				//Getting main module
				blackbone::ModuleDataPtr &mainModulePtr = procInfo->bbMainModule;
				blackbone::pe::PEImage &mainModuleDisk = procInfo->bbPE;
				blackbone::pe::PEImage mainModuleMemory;

				std::unique_ptr<uint8_t[]> localBuf(new uint8_t[procInfo->bbMainModule->size]);
				memset(localBuf.get(), 0, procInfo->bbMainModule->size);
				procInfo->bbProcess.memory().Read(procInfo->bbMainModule->baseAddress, procInfo->bbMainModule->size, localBuf.get());

				if ((mainModuleMemory.Parse(localBuf.get()) == ERROR_SUCCESS) &&
					(mainModuleDisk.base()) &&
					(mainModuleMemory.base()) &&
					(mainModuleMemory.imageSize() > 0) &&
					(mainModuleDisk.imageSize() > 0))
				{
			
					const IMAGE_DOS_HEADER *pMainModuleMemoryDosHdr = nullptr;
					const IMAGE_SECTION_HEADER *pMainModuleMemorySection = nullptr;
					const IMAGE_DOS_HEADER *pMainModuleDiskDosHdr = nullptr;
					const IMAGE_SECTION_HEADER *pMainModuleDiskSection = nullptr;

					pMainModuleMemoryDosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(mainModuleDisk.base());
					pMainModuleDiskDosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(mainModuleMemory.base());

					//Now checking if loaded module and one on disk are the same
					if ((pMainModuleMemoryDosHdr->e_magic == IMAGE_DOS_SIGNATURE) &&
						(pMainModuleDiskDosHdr->e_magic == IMAGE_DOS_SIGNATURE) &&
						(pMainModuleDiskDosHdr->e_oemid == pMainModuleMemoryDosHdr->e_oemid) &&
						(mainModuleMemory.imageSize() == mainModuleDisk.imageSize()) &&
						(mainModuleMemory.DirectorySize(0) == mainModuleDisk.DirectorySize(0)) &&
						(mainModuleMemory.mType() == mainModuleDisk.mType()) &&
						(mainModuleMemory.headersSize() == mainModuleDisk.headersSize()) &&
						(mainModuleMemory.subsystem() == mainModuleDisk.subsystem()) &&
						(mainModuleMemory.DllCharacteristics() == mainModuleDisk.DllCharacteristics()) &&
						(mainModuleMemory.GetImports().size() == mainModuleDisk.GetImports().size()) &&
						(mainModuleMemory.sections().size() == mainModuleDisk.sections().size()))
					{
						continue;
					}
					else
					{
						HunterCommon::SuspiciousProcessDataPtr suspiciousElement = nullptr;
						if (ReportManager::GetInstance().GetReportElement(procInfo->pid, GetHunterID(), suspiciousElement) &&
							ReportManager::GetInstance().PopulateCommonFields(procInfo->pid, 0, procInfo, suspiciousElement))
						{
							//Adding hunter specific information 										
							suspiciousElement->SetProcessName(procInfo->name);
							std::wstring wstrModule(mainModuleMemory.name());
							suspiciousElement->AddModulesInformation(wstrModule);

							suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_NAME, wstrModule);
							suspiciousElement->AddNewProperty(L"Image Size DISK", GeneralHelpers::GetHexString((PVOID)mainModuleDisk.imageSize()));
							suspiciousElement->AddNewProperty(L"Image Size MEMORY", GeneralHelpers::GetHexString((PVOID)mainModuleMemory.imageSize()));
							suspiciousElement->AddNewProperty(L"Headers Size DISK", GeneralHelpers::GetHexString((PVOID)mainModuleDisk.headersSize()));
							suspiciousElement->AddNewProperty(L"Headers Size MEMORY", GeneralHelpers::GetHexString((PVOID)mainModuleMemory.headersSize()));
							suspiciousElement->AddNewProperty(L"DLL Characteristics DISK", GeneralHelpers::GetHexString((PVOID)mainModuleDisk.DllCharacteristics()));
							suspiciousElement->AddNewProperty(L"DLL Characteristics MEMORY", GeneralHelpers::GetHexString((PVOID)mainModuleMemory.DllCharacteristics()));
							suspiciousElement->AddNewProperty(L"Imports Size DISK", GeneralHelpers::GetHexString((PVOID)mainModuleDisk.GetImports().size()));
							suspiciousElement->AddNewProperty(L"Imports Size MEMORY", GeneralHelpers::GetHexString((PVOID)mainModuleMemory.GetImports().size()));
							suspiciousElement->AddNewProperty(L"Sections Size DISK", GeneralHelpers::GetHexString((PVOID)mainModuleDisk.sections().size()));
							suspiciousElement->AddNewProperty(L"Sections Size MEMORY", GeneralHelpers::GetHexString((PVOID)mainModuleMemory.sections().size()));
						}
					}
				}
			}

			ret = true;
		}
	}

	return ret;
}