#pragma once

#include "common.h"

namespace GeneralHelpers
{
	bool StartProcess(const std::wstring &process, const std::wstring &args);
	int ToInteger(const std::wstring &st);
	bool IsNumber(const std::wstring& str);
	bool IsValidFile(const std::wstring &fileName);
	bool IsValidDirectory(const std::wstring &directory);
	bool GetFullPathToFile(const std::wstring &fileName, std::wstring &fullPathFile);
	bool GetTargetFileSize(const std::wstring& file, DWORD &size);
	bool GetTargetFileIntoBuffer(const std::wstring& file, const DWORD &fileSize, LPVOID lpBuffer, DWORD &bytesRead);
	bool GetTargetFileIntoString(const std::wstring& fullPathFile, std::wstring& buffer);
	bool GetTargetFileIntoString(const std::wstring& fullPathFile, std::string& buffer);
	bool GetBaseFileName(const std::wstring &fullPath, std::wstring &baseName);
	bool GetCurrentProcessModuleFullPath(std::wstring &fullPath);
	bool GetCurrentProcessModuleDirectory(std::wstring &fullDirectoryPath);
	bool StrCompare(const std::wstring& str1, const std::wstring& str2);
	bool StrCompare(const std::string& str1, const std::string& str2);
	bool StrContainsPattern(const std::wstring& str, const std::wstring& pattern);
	bool StrContainsPatternInsensitive(const std::wstring& str, const std::wstring& pattern);
	bool StrContainsPattern(const std::string& str, const std::string& pattern);
	bool StrContainsPatternInsensitive(const std::string& str, const std::string& pattern);
	bool IsRunningAs64BitProcess();
	bool IsRunningAsAdmin();
	bool TerminateProcess(const DWORD &processID, const uint32_t &exitCode);
	bool GetSystemArchitecture(DWORD &arch);
	bool GetProcessBitness(const HANDLE &hProcess, CustomTypes::ProcessType &processType);
	bool EnableTokenPrivilege(LPTSTR pPrivilege);
	bool IsProcessStillRunning(const HANDLE &hProcess);
	bool IsThreadStillRunning(const HANDLE &hThread);
	bool IsDotNETLib(const std::wstring &name);

	bool GetWindowsSystemDirectory(std::wstring &system32Directory);
	bool GetVectorByToken(const std::string& input, const char token, std::vector<std::string> &vector);
	bool GetVectorByToken(const std::wstring& input, const wchar_t token, std::vector<std::wstring> &vector);
	bool IsElementPresentOnList(const std::vector<std::wstring> &listToCheck, const std::wstring &element);
	bool TrimSpaces(std::string &str);
	bool TrimSpaces(std::wstring &str);
	bool GetUserProfileDirectory(std::wstring &userdir);
	bool GetProcessnameByPID(DWORD pid, std::wstring &processName);
	std::wstring GetBaseFileName(const std::wstring &fullPath);
	std::wstring ToWstring(const unsigned int &value);
	std::wstring ReplaceTokensInStr(const std::wstring &str, const std::wstring &from, const std::wstring &to);
	std::wstring SanitizeStr(const std::wstring &str);
	std::wstring StrToWStr(const std::string& str);
	std::wstring GetHexString(PVOID addr);
	std::wstring GetMemoryRegionType(DWORD id);
	std::wstring GetMemoryRegionState(DWORD id);
	std::wstring GetMemoryRegionProtection(DWORD id);
	std::string  WStrToStr(const std::wstring& wstr);
	std::string GetErrorText(NTSTATUS code);
	void StrAddDelimitator(const wchar_t delim, std::wstring &str);
	void StrTrim(std::wstring &str);
	void StrToUppercase(std::wstring &str);
	void StrToUppercase(std::string &str);
	void StrToLowercase(std::wstring &str);
	void StrToLowercase(std::string &str);
	const time_t GetEpochTimestamp();
}

namespace TraceHelpers
{
	void TraceUp(const char *buffer, ...);
	void TraceDown(const char *buffer, ...);
	void TraceConsoleUp(const char *buffer, ...);
	void TraceConsoleDown(const char *buffer, ...);
	void TraceConsole(const char *buffer, ...);
}

namespace RegistryHelpers
{
	bool DeleteKey(const HKEY &hRootKey, const std::wstring &regSubKey);
	bool CreateKey(const HKEY &hRootKey, const std::wstring &regSubKey);
	bool DeleteValue(const HKEY &hRootKey, const std::wstring &regSubKey, const std::wstring &regValue);
	bool RegistryKeyExists(const HKEY &hRootKey, const std::wstring &regSubKey);
	bool RegistryValueExists(const HKEY &hRootKey, const std::wstring &regSubKey, const std::wstring& regValue);
	bool GetRegStringValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, std::wstring &regContent);
	bool SetRegStringValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const std::wstring &regContent);
	bool GetRegDWORDValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, DWORD &nValue);
	bool SetRegDWORDValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const DWORD &nValue);
	bool GetRegBoolValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, bool &nValue);
	bool SetRegBoolValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const bool &nValue);
}

namespace ServiceHelpers
{
	bool RegisterService(const std::wstring &serviceExecutable, const std::wstring &serviceCmdArgs, const std::wstring &serviceName, const std::wstring &serviceDisplay);
	bool IsSameServiceExecutablePath(const std::wstring &serviceName, const std::wstring &fullServiceExecPath);
	bool DeleteService(const std::wstring &serviceName);
	bool IsServiceCreated(const std::wstring& serviceName);
	bool IsServiceStopped(const std::wstring& serviceName);
	bool IsServiceStarted(const std::wstring& serviceName);
	bool StartTargetService(const std::wstring& serviceName);
	bool StopTargetService(const std::wstring& serviceName);
}

namespace HunterHelpers
{
	bool GetSystemProcessesData(HunterCommon::ProcessCollection &sysProcHandlers);
	bool CleanupSystemProcessData(HunterCommon::ProcessCollection &procHandlers);
	bool GetMemoryRegionInfo(HANDLE &hProcess, size_t &dwStartAddress, MEMORY_BASIC_INFORMATION &info);
	bool GetThreadBasicInfo(HANDLE &thread, CustomWinTypes::THREAD_BASIC_INFORMATION &threadInfo);
	bool GetThreadStartAddress(HANDLE &thread, PVOID &threadStartAddress);
	bool IsTrustedFile(const std::wstring &fileName);
	bool IsSuspiciousSymbolsOnThreadCallStackBeginning(const HunterCommon::CallStackDataList &csElements);
	bool IsAPCInjectionPresent(const HunterCommon::CallStackDataList &csElements);
	bool IsPIDInCollection(HunterCommon::ProcessCollection &sysProcessesData, const DWORD &pid, HunterCommon::ProcessCollection::iterator &it);
	bool IsModuleInThreadsCollection(DWORD &dwProcessId, HANDLE &hProcess, const HunterCommon::ThreadsCollection &threadsData, const HunterCommon::ModulesCollection &modules, const std::wstring &module, DWORD &tid);
	bool IsModuleInThread(const DWORD &dwProcessId, const HANDLE &hProcess, const DWORD &tid, const HunterCommon::ModulesCollection &modules, const std::wstring &module);
	bool GetListOfCallStackModules(const DWORD &dwProcessId, const HANDLE &hProcess, const HANDLE &hThread, const HunterCommon::ModulesCollection &modules, HunterCommon::CallStackDataList &csElements, bool &suspiciousFound);
	bool IsFuzzyPEHeaderPresent(HANDLE &hProcess, size_t &addressToCheck, size_t &regionSize);
	bool PopulateModulesIfNeededByWalkingPEHeaders(HunterCommon::ProcessDataPtr &processData);
	bool PopulateModulesIfNeededByMemorySections(HunterCommon::ProcessDataPtr &processData);
	bool GetParentPid(const DWORD &pid, DWORD &parentPID);
	bool GetPEBAddress(const HANDLE &processHandle, PVOID &baseaddr);
	bool GetProcessCommandLine(blackbone::Process &targetProc, std::wstring &cmdline);
	const wchar_t *HunterIDToString(const CustomTypes::HunterID &value);

	class ThreadCallstackWalker
	{
	public:
		static ThreadCallstackWalker& GetInstance()
		{
			static ThreadCallstackWalker instance;
			return instance;
		}

		bool GetThreadCallStack(const DWORD &pid, HANDLE hProcess, HANDLE hThread, const HunterCommon::ModulesCollection &modules, HunterCommon::CallStackDataList &element);

	private:
		ThreadCallstackWalker() : currentProcessHandle(INVALID_HANDLE_VALUE), currentPID(0) 
		{
			SymSetOptions(SymGetOptions() |
				SYMOPT_AUTO_PUBLICS | SYMOPT_CASE_INSENSITIVE | 
				SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_INCLUDE_32BIT_MODULES |
				SYMOPT_OMAP_FIND_NEAREST | SYMOPT_UNDNAME |
				SYMOPT_LOAD_ANYTHING | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS | SYMOPT_IGNORE_NT_SYMPATH | SYMOPT_NO_IMAGE_SEARCH
			);
		};

		ThreadCallstackWalker(const ThreadCallstackWalker&) {};

		HANDLE currentProcessHandle; //assuming that handle will be closed by caller
		DWORD currentPID;
	};


	class ModuleExclusionsManagement
	{
	public:
		ModuleExclusionsManagement()
		{
			m_analyzedFiles.clear();
			//const std::wstring &systemDir = ConfigManager::GetInstance().GetWindowsSystemDirectory();
			std::wstring systemDir;
			if (GeneralHelpers::GetWindowsSystemDirectory(systemDir))
			{
				m_systemDirectory.assign(systemDir);
			}
		}

		bool ShouldBeExcluded(const std::wstring &moduleFullPath)
		{
			bool ret = false;

			if (m_analyzedFiles[moduleFullPath]) // Was the file already scanned
			{
				ret = true;
			}
			else if (GeneralHelpers::StrContainsPatternInsensitive(moduleFullPath, m_systemDirectory)) // Is part of win32 directory?
			{
				m_analyzedFiles[moduleFullPath] = true;
				ret = true;
			}

			return ret;
		}

		void AddToExclusions(const std::wstring &moduleFullPath)
		{
			m_analyzedFiles[moduleFullPath] = true;
		}


	private:

		std::wstring m_systemDirectory;
		std::unordered_map<std::wstring, bool> m_analyzedFiles;
	};


	class RangesExclusionsManagement
	{

	public:
		RangesExclusionsManagement()
		{
			m_rangesToLookFor.clear();
			m_lookupMap.clear();
		}

		void Reset()
		{
			m_rangesToLookFor.clear();
			m_lookupMap.clear();
		}

		bool IsInRange(const size_t &value)
		{
			bool ret = false;

			for (auto it = m_rangesToLookFor.begin(); it != m_rangesToLookFor.end(); ++it)
			{
				//check if value is in range
				if ((value <= it->maxValue) && (value >= it->minValue))
				{
					ret = true;
					break;
				}
			}

			return ret;
		}

		bool IsInRangeFastLookup(const size_t &value)
		{
			return m_lookupMap[value];
		}

		void AddNewRange(const size_t &lower, const size_t &upper, const size_t &regionSize)
		{
			HunterCommon::RangeData newData(lower, upper);
			m_rangesToLookFor.push_back(newData);

			for (size_t addrToAdd = lower; addrToAdd <= upper; addrToAdd += regionSize)
			{
				m_lookupMap.insert({ addrToAdd , true });
			}			
		}


	private:
		std::vector<HunterCommon::RangeData> m_rangesToLookFor;
		std::unordered_map<size_t, bool> m_lookupMap;
	};
}