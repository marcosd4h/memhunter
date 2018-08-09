#include "common.h"

void HunterCommon::SuspiciousProcessData::AddThreadInformation(DWORD &threadID, std::wstring &threadInfo)
{
	ThreadInfoCollection::iterator it = m_threads.find(threadID);
	if (it != m_threads.end())
	{
		it->second.push_back(threadInfo);
	}
	else
	{
		std::vector<std::wstring> threadInfoContainer;
		threadInfoContainer.push_back(threadInfo);
		m_threads.insert(std::make_pair(threadID, threadInfoContainer));
	}
}

void HunterCommon::SuspiciousProcessData::AddProcessInformation(std::wstring &key, std::wstring &value)
{
	ProcessInfoContainer::iterator it = m_processData.find(key);
	if (it != m_processData.end())
	{
		it->second.assign(value);
	}
	else
	{
		m_processData.insert(std::make_pair(key, value));
	}
}


void ReportManager::Clear()
{
	std::lock_guard<std::mutex> lock(m_lock);
	m_container.clear();
}


bool ReportManager::GetReportElement(const DWORD pid, const CustomTypes::HunterID &hunterID, HunterCommon::SuspiciousProcessDataPtr &element)
{
	std::lock_guard<std::mutex> lock(m_lock);
	bool ret = false;

	if (ConfigManager::GetInstance().IsValidPID(pid) && Hunter::IsValidHunterID(hunterID))
	{
		bool addNewElement = false;
		size_t foundElements = m_container.count(pid);

		if (foundElements == 0) //item does not exists
		{
			addNewElement = true;
		}
		else if (foundElements == 1) //there is a single instance of the given key
		{
			auto itElement = m_container.find(pid);
			if (itElement != m_container.end() && 
				(itElement->second->GetDetectedHunter() == hunterID))
			{
				element = itElement->second;
				ret = true;
			}
			else 
			{
				//for some reason it was not found. Adding it below.
				addNewElement = true;
			}			
		}
		else // give key exists more than once so we need to iterate through a range
		{			
			bool found = false;
			std::pair <HunterCommon::SuspiciousProcessess::const_iterator, HunterCommon::SuspiciousProcessess::const_iterator> range;
			range = m_container.equal_range(pid);
			for (HunterCommon::SuspiciousProcessess::const_iterator it = range.first; it != range.second; ++it)
			{
				HunterCommon::SuspiciousProcessDataPtr itElement(it->second);
				if (itElement && (hunterID == itElement->GetDetectedHunter()) == 0)
				{
					element = itElement;
					found = true;
					ret = true;
					break;
				}
			}

			if (!found) //for some reason target element it was not found. Adding it below.
			{
				addNewElement = true;
			}
		}

		//adding new element if it was not found above
		if (addNewElement)
		{
			HunterCommon::SuspiciousProcessDataPtr newElement(new HunterCommon::SuspiciousProcessData(pid, hunterID));
			std::pair<DWORD, HunterCommon::SuspiciousProcessDataPtr> newData(pid, newElement);
			m_container.insert(newData);
			element = newElement;
			ret = true;
		}
	}

	return ret;
}

std::wstring ReportManager::GetCommonReportData(
	const HunterCommon::SuspiciousProcessDataPtr &suspiciousProcessData,
	const CustomTypes::ReportVerbosity &mode)
{
	std::wstring ret;
	std::wostringstream output;

	if (suspiciousProcessData)
	{
		std::wstring processName(suspiciousProcessData->GetProcessName());
		std::wstring hunterName(HunterHelpers::HunterIDToString(suspiciousProcessData->GetDetectedHunter()));

		//std::wstring serializedProcessInfo;
		//HunterCommon::ProcessInfoContainer &processData = suspiciousProcessData->GetProcessInformation();
		output << std::endl << L" ========== New Suspicious Process Found: " << processName << L" ========== " << std::endl;

		//fetching specific properties
		if (mode == CustomTypes::ReportVerbosity::REPORT_MODE_MINIMAL)
		{
			output << ReportAttributes::REPORT_PROCESS_NAME << L": " << processName << std::endl;
			output << ReportAttributes::REPORT_PROCESS_ID << L": " << suspiciousProcessData->GetPID() << std::endl;
			output << ReportAttributes::REPORT_HUNTER_NAME << L": " << hunterName << std::endl;
		}
		else
		{
			//fetching all properties
			HunterCommon::ReportPropertiesType properties = suspiciousProcessData->GetProperties();
			for (auto propIT = properties.begin(); propIT != properties.end(); propIT++)
			{
				if (propIT->first.empty())
				{
					output << std::endl;
				}
				else
				{
					output << propIT->first << L": " << propIT->second << std::endl;
				}				
			}

			//fetching token info
			if (mode == CustomTypes::ReportVerbosity::REPORT_MODE_VERBOSE)
			{
				output << ReportAttributes::REPORT_TOKEN_INFO << L": " << suspiciousProcessData->GetTokenInfo() << std::endl;
			}
		}

		//adding extended information if needed
		if (mode == CustomTypes::ReportVerbosity::REPORT_MODE_VERBOSE)
		{
			std::wstring serializedThreadInfo;
			const HunterCommon::ThreadInfoCollection &threads = suspiciousProcessData->GetThreadsInformation();
			for (HunterCommon::ThreadInfoCollection::const_iterator threadIT = threads.begin();
				threadIT != threads.end();
				++threadIT)
			{
				DWORD tid = threadIT->first;
				if (threadIT != threads.begin()) serializedThreadInfo.append(L":");
				serializedThreadInfo.append(GeneralHelpers::ToWstring(tid));
			}
			output << ReportAttributes::REPORT_EXTENDED_THREAD_INFO << L": " << serializedThreadInfo << std::endl;

			std::wstring serializedModulesInfo;
			const HunterCommon::ModulesInfoContainer &modules = suspiciousProcessData->GetModulesInformation();
			for (HunterCommon::ModulesInfoContainer::const_iterator moduleIT = modules.begin();
				moduleIT != modules.end();
				++moduleIT)
			{
				if (moduleIT != modules.begin()) serializedModulesInfo.append(L":");
				serializedModulesInfo.append(*moduleIT);
			}
			output << ReportAttributes::REPORT_EXTENDED_MODULES_INFO << L": " << serializedModulesInfo << std::endl;
		}

		output << std::endl;
		ret.assign(output.str());
	}

	return ret;
}

bool ReportManager::PrintFindingsOnConsole(const CustomTypes::ReportVerbosity &mode)
{
	bool ret = false;
	size_t suspiciousProcessCollectionSize = m_container.size();
	std::wstring output;
	
	if (suspiciousProcessCollectionSize > 0)
	{
		output.clear();

		for (HunterCommon::SuspiciousProcessess::const_iterator it = m_container.begin();
			it != m_container.end();
			++it)
		{
			HunterCommon::SuspiciousProcessDataPtr suspiciousProcessData = it->second;
	
			output.append(GetCommonReportData(suspiciousProcessData, mode));
		}

		std::wcout << output << std::endl;

		ret = true;
	}

	return ret;
}


bool ReportManager::PrintFindingsOnEventLog(const CustomTypes::ReportVerbosity &mode)
{
	bool ret = false;
	size_t suspiciousProcessCollectionSize = m_container.size();
	std::wstring output;

	if (suspiciousProcessCollectionSize > 0)
	{
		output.clear();

		for (HunterCommon::SuspiciousProcessess::const_iterator it = m_container.begin();
			it != m_container.end();
			++it)
		{
			HunterCommon::SuspiciousProcessDataPtr suspiciousProcessData = it->second;

			output.append(GetCommonReportData(suspiciousProcessData, mode));
		}

		HANDLE hEventLog = RegisterEventSource(NULL, _T("Memhunter"));
		if (hEventLog != INVALID_HANDLE_VALUE)
		{
			const TCHAR *eventOutput = output.c_str();
			const WORD  CUSTOM_CATEGORY = ((WORD)0x00000003L);
			const DWORD CUSTOM_MSG = ((DWORD)0xC0020100L);
			ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, CUSTOM_CATEGORY, CUSTOM_MSG, NULL, 1, 0, &(eventOutput), NULL);
			DeregisterEventSource(hEventLog);

			CloseHandle(hEventLog);
			hEventLog = INVALID_HANDLE_VALUE;
		}

		ret = true;
	}

	return ret;
}


bool ReportManager::PopulateCommonFields(const DWORD pid,
										 const DWORD tid,
										 const HunterCommon::ProcessDataPtr &processData,
									     HunterCommon::SuspiciousProcessDataPtr &reportElement)
{
	bool ret = false;

	if (ConfigManager::GetInstance().IsValidPID(processData->pid))
	{		
		//Adding hunter specific information  
		reportElement->SetProcessName(processData->name);

		//Adding token properties
		std::wstring tokenInfo;
		HANDLE hTargetHandle = INVALID_HANDLE_VALUE;
		
		reportElement->AddNewProperty(L"", L"");
		reportElement->AddNewProperty(ReportAttributes::REPORT_HUNTER_NAME, HunterHelpers::HunterIDToString(reportElement->GetDetectedHunter()) );
		reportElement->AddNewProperty(ReportAttributes::REPORT_PROCESS_ID, std::to_wstring(processData->pid));
		reportElement->AddNewProperty(ReportAttributes::REPORT_PROCESS_NAME, GeneralHelpers::GetBaseFileName(processData->name));
		reportElement->AddNewProperty(ReportAttributes::REPORT_PROCESS_EXECUTABLE_PATH, processData->bbMainModule->fullPath);

		std::wstring processCmdline;
		if (HunterHelpers::GetProcessCommandLine(processData->bbProcess, processCmdline))
		{
			reportElement->AddNewProperty(ReportAttributes::REPORT_PROCESS_CMDLINE, processCmdline);
		}

		reportElement->AddNewProperty(ReportAttributes::REPORT_PROCESS_NR_THREADS, std::to_wstring(processData->bbProcess.threads().getAll().size()));
		reportElement->AddNewProperty(ReportAttributes::REPORT_PROCESS_BASE_PRIORITY, std::to_wstring(GetPriorityClass(processData->handle)));

		if (tid != 0)
		{
			//hTargetHandle = OpenThread(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 0, tid);
			hTargetHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid); //not a thread handle
			if ((hTargetHandle != INVALID_HANDLE_VALUE) &&
				(TokenUtils::GetBasicTokenInfo(hTargetHandle, tokenInfo)))
			{
				//reportElement->AddNewProperty(ReportAttributes::REPORT_TOKEN_INFO, tokenInfo);
				reportElement->SetTokenInfo(tokenInfo);
			}
		}

		if (hTargetHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hTargetHandle);
			hTargetHandle = NULL;
		}

		ret = true;
	}

	return ret;
}

bool ReportManager::ReportFindings(const CustomTypes::ReportVerbosity &verbosity,
								   const CustomTypes::ReportOutput &output)
{
	bool ret = false;

	if ((output < CustomTypes::ReportOutput::REPORT_OUTPUT_NA) &&
		(verbosity < CustomTypes::ReportVerbosity::REPORT_MODE_NA))
	{
		//Reporting findings
		if (output == CustomTypes::ReportOutput::REPORT_OUTPUT_CONSOLE)
		{
			ret = PrintFindingsOnConsole(verbosity);
		}
		else if (output == CustomTypes::ReportOutput::REPORT_OUTPUT_EVENTLOG)
		{
			ret = PrintFindingsOnEventLog(verbosity);
		}
	}

	return ret;
}