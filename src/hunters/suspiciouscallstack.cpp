#include "common.h"

bool HunterSuspiciousCallStack::Execute(HunterCommon::ProcessCollection &processesToAnalyze)
{
	bool ret = false;
	static const size_t MIN_NUMBER_OF_FRAMES = 3;

	for (HunterCommon::ProcessCollection::const_iterator processElementIt = processesToAnalyze.begin();
		processElementIt != processesToAnalyze.end();
		++processElementIt)
	{
		if (processElementIt->first > 0)
		{
			HunterCommon::ProcessDataPtr procInfo = processElementIt->second;

			//Only looking active process
			//TODO: Mixed-mode callstacks are not supported for now
			if ((procInfo->handle != INVALID_HANDLE_VALUE) && (GeneralHelpers::IsProcessStillRunning(procInfo->handle)) && (!procInfo->isManaged))
			{
				for (HunterCommon::ThreadsCollection::const_iterator threadIT = procInfo->threads.begin();
					threadIT != procInfo->threads.end();
					++threadIT)
				{
					DWORD threadID = threadIT->th32ThreadID;
					HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, threadID);

					//Only looking for active threads
					if ((hThread != NULL) && (hThread != INVALID_HANDLE_VALUE) && (GeneralHelpers::IsThreadStillRunning(hThread)))
					{
						HunterCommon::CallStackDataList csElements;
						bool suspiciousFound = false;				

						if (HunterHelpers::GetListOfCallStackModules(procInfo->pid, procInfo->handle, hThread, procInfo->modules, csElements, suspiciousFound))
						{
							if (suspiciousFound && (csElements.size() > MIN_NUMBER_OF_FRAMES))
							{
								HunterCommon::SuspiciousProcessDataPtr suspiciousElement = nullptr;
								if (ReportManager::GetInstance().GetReportElement(procInfo->pid, GetHunterID(), suspiciousElement) &&
									ReportManager::GetInstance().PopulateCommonFields(procInfo->pid, threadID, procInfo, suspiciousElement))
								{
									//Adding hunter specific information 										
									suspiciousElement->SetProcessName(procInfo->name);
									std::wstring wstrModule(GetName());
									suspiciousElement->AddThreadInformation(threadID, wstrModule);
									suspiciousElement->AddModulesInformation(wstrModule);

									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_NAME, wstrModule);
									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_MODULE_PATH, L"memory");
									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_ID, std::to_wstring(threadID));
									suspiciousElement->AddNewProperty(ReportAttributes::REPORT_THREAD_PRIORITY, std::to_wstring(GetThreadPriority(hThread)));

									std::stringstream dumpedCallstack;
									for (auto csIT = csElements.begin(); csIT != csElements.end(); csIT++)
									{
										HunterCommon::CallStackDataPtr element = *csIT;
										{
											dumpedCallstack << std::endl;
											dumpedCallstack << "\tstackFrameAddress: " << element->stackFrameAddress << std::endl;
											dumpedCallstack << "\tsymbolAddress: " << element->symbolAddress << std::endl;
											dumpedCallstack << "\tbaseOfImageAddress: " << element->baseOfImageAddress << std::endl;
											dumpedCallstack << "\tloadedImageName: " << element->loadedImageName << std::endl;
											dumpedCallstack << "\timageName: " << element->imageName << std::endl;
											dumpedCallstack << "\tmoduleName: " << element->moduleName << std::endl;
											dumpedCallstack << "\tsymbolName: " << element->symbolName << std::endl;
										}
									}

									suspiciousElement->AddNewProperty(L"Dumped Suspicious Callstack", GeneralHelpers::StrToWStr(dumpedCallstack.str()) );
								}
							}
						}

						CloseHandle(hThread);
					}
				}
			}

			ret = true;
		}
	}

	return ret;
}