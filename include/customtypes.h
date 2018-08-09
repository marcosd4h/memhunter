#pragma once

#include "common.h"

namespace CustomDefs
{	
	static const std::string MEMHUNTER_VERSION = "v0.7";
	static const uint32_t MAX_BUFFER_SIZE = 2048;
	static const std::string UPMARK = "[+] ";
	static const std::string DOWNMARK = "[-] ";
	static const std::string SEPARATOR = " - ";
	static const std::string ENDLINE = "\n";
	static const std::string APPNAME = "Memhunter";
	static const bool DEFAULT_DISSOLVABLE_MODE = false;
	static const bool DEFAULT_FP_MITIGATIONS_MODE = true;
	static const std::wstring DEFAULT_VALUE = L"";
	static const std::wstring DEFAULT_REPORT_MODE = L"regular";
	static const std::wstring DEFAULT_REPORT_OUTPUT = L"console";
	static const std::wstring SERVICE_NAME = L"memhuntercollect";
	static const std::wstring SERVICE_DISPLAY = L"memhuntercollect";
	static const std::wstring SERVICE_ARGS = L" -s";
	static const DWORD SYSTEM_MIN_VALID_PID = 5; // System processes are found below this
	static const UINT32 DEFAULT_NR_WORKING_THREADS = 1;
	static const size_t DEFAULT_PAGE_SIZE = 4096;
	static const std::wstring DEFAULT_CSV_COLON_SEP = L";";
	static const std::wstring DEFAULT_CSV_COMMA_SEP = L",";
	static const std::wstring DEFAULT_RET_SEP = L"\n";

	static const std::wstring DEFAULT_SYSTEM32_DIRECTORY = L"c:\\windows\\system32\\";

	//Signatures Constants
	static const std::wstring MICROSOFT_CORP_SIGNER_TO_VERIFY = L"Microsoft Corporation";
	
	static const BYTE VERISIGN_CERT_THUMBPRINT[] = { 0x4E, 0xB6, 0xD5, 0x78, 0x49, 0x9B, 0x1C, 0xCF, 0x5F, 0x58, 0x1E, 0xAD, 0x56, 0xBE, 0x3D, 0x9B, 0x67, 0x44, 0xA5, 0xE5 };
	static const BYTE ADDTRUST_CERT_THUMBPRINT[] = { 0x02, 0xFA, 0xF3, 0xE2, 0x91, 0x43, 0x54, 0x68, 0x60, 0x78, 0x57, 0x69, 0x4D, 0xF5, 0xE4, 0x5B, 0x68, 0x85, 0x18, 0x68 };
	static const BYTE INTEL_SHA256_CERT_THUMBPRINT[] = { 0x30, 0xa1, 0xa6, 0xc9, 0xbc, 0x92, 0x0e, 0x60, 0x1a, 0x44, 0xa3, 0x05, 0x4e, 0x77, 0xf4, 0x0b, 0xd3, 0x1b, 0xe6, 0x39 };

}

namespace ReportAttributes
{	
	//Common
	static const std::wstring REPORT_HUNTER_NAME = L"Hunter Module";
	static const std::wstring REPORT_PROCESS_ID = L"Process ID";
	static const std::wstring REPORT_PROCESS_NAME = L"Process Name";
	static const std::wstring REPORT_PROCESS_EXECUTABLE_PATH = L"Process Path";
	static const std::wstring REPORT_PROCESS_CMDLINE = L"Process Commmand Line";
	static const std::wstring REPORT_PROCESS_BASE_PRIORITY = L"Process Base Priority";
	static const std::wstring REPORT_PROCESS_NR_THREADS = L"Process Nr Threads";
	static const std::wstring REPORT_TOKEN_INFO = L"Suspicious Thread Token Information";

	static const std::wstring REPORT_EXTENDED_THREAD_INFO = L"Suspicious Extended Thread Information";
	static const std::wstring REPORT_EXTENDED_MODULES_INFO = L"Suspicious Extended Module Information";

	// Hunter Specifics
	static const std::wstring REPORT_MODULE_NAME = L"Suspicious Module Name";
	static const std::wstring REPORT_MODULE_PATH = L"Suspicious Module Path";
	static const std::wstring REPORT_MODULE_EXPORT_NAME = L"Suspicious Module Export Name";
	static const std::wstring REPORT_THREAD_ID = L"Suspicious Thread ID";
	static const std::wstring REPORT_THREAD_PRIORITY = L"Suspicious Thread Priority";
	static const std::wstring REPORT_THREAD_BASEADDR = L"Suspicious Thread Base Addr";
	static const std::wstring REPORT_THREAD_BASE_PRIORITY = L"Suspicious Thread Base Priority";
	static const std::wstring REPORT_THREAD_MEMORY_ADDR = L"Suspicious Memory Addr";
	static const std::wstring REPORT_THREAD_MEMORY_ALLOC_PROT = L"Suspicious Memory Alloc Protection";
	static const std::wstring REPORT_THREAD_MEMORY_PROT = L"Suspicious Memory Protection";
	static const std::wstring REPORT_THREAD_MEMORY_STATE = L"Suspicious Memory State";
	static const std::wstring REPORT_THREAD_MEMORY_TYPE = L"Suspicious Memory Type";
}

namespace CustomTypes
{
	struct YaraRulesData
	{
		YaraRulesData() {}

		std::wstring description;
		std::wstring filename;
	};

	struct ExclusionsData
	{
		ExclusionsData() {}

		std::wstring process;
		std::wstring memhash;
	};

	typedef std::vector<std::string> StringsContainer;
	typedef std::vector<ExclusionsData> ExclusionsList;
	typedef std::vector<YaraRulesData> YaraRulesList;

	struct ServiceProperties
	{
		ServiceProperties(): canBeStopped(true), canBeShuttedDown(true), canBePausedOrResumed(true) {}

		bool canBeStopped;
		bool canBeShuttedDown;
		bool canBePausedOrResumed;
	};

	enum HunterType
	{
		HUNT_OBSERVER = 0x00,
		HUNT_MODIFIER,
	};

	static const HunterType DEFAULT_HUNTER_TYPE = HunterType::HUNT_OBSERVER;

	enum ProcessType
	{
		PROCESS_32_BITS = 0x00,
		PROCESS_WOW_32_BITS,
		PROCESS_64_BITS, 
		PROCESS_UNKNOWN
	};

	enum HunterID
	{
		HUNT_SUSPICIOUS_THREADS = 0x01,
		HUNT_SUSPICIOUS_CALLSTACK,
		HUNT_SUSPICIOUS_EXPORTS,
		HUNT_SUSPICIOUS_HOLLOWS,
		HUNT_SUSPICIOUS_MODULES,
		HUNT_SUSPICIOUS_PARENTS,
		HUNT_SUSPICIOUS_REGIONS,
		HUNT_SUSPICIOUS_REGISTRY_PERSISTENCE,
		HUNT_SUSPICIOUS_SHELLCODE,
		HUNT_NA,
	};
	typedef std::unordered_map<HunterID, bool> HuntersList;

	enum ReportVerbosity
	{
		REPORT_MODE_VERBOSE = 0x00,
		REPORT_MODE_REGULAR,
		REPORT_MODE_MINIMAL,
		REPORT_MODE_NA
	};

	enum ReportOutput
	{
		REPORT_OUTPUT_CONSOLE = 0x00,
		REPORT_OUTPUT_EVENTLOG,
		REPORT_OUTPUT_NA
	};


}


namespace HunterCommon
{
	typedef std::vector<THREADENTRY32> ThreadsCollection;
	typedef std::vector<MODULEENTRY32> ModulesCollection;
	
	struct ProcessData
	{
		ProcessData() : handle(INVALID_HANDLE_VALUE), pid(0) {}

		ProcessData(HANDLE _handle, DWORD _pid, CustomTypes::ProcessType _type = CustomTypes::ProcessType::PROCESS_UNKNOWN)
			: handle(_handle), pid(_pid), processType(_type), isManaged(false), bbProcessReady(false), bbPEReady(false), bbMainModule(nullptr) {}
		ProcessData(HANDLE _handle, DWORD _pid, std::wstring &_name, CustomTypes::ProcessType _type = CustomTypes::ProcessType::PROCESS_UNKNOWN)
			: handle(_handle), pid(_pid), processType(_type), isManaged(false), bbProcessReady(false), bbPEReady(false), bbMainModule(nullptr), name(_name) {}

		HANDLE handle;
		DWORD pid;
		CustomTypes::ProcessType processType;
		bool isManaged;
		bool bbProcessReady;
		bool bbPEReady;
		blackbone::ModuleDataPtr bbMainModule;
		std::wstring name;
		blackbone::Process bbProcess;
		blackbone::pe::PEImage bbPE;
		std::vector<blackbone::HandleInfo> bbHandles;
		blackbone::ProcessModules::mapModules bbModulesManuallyMapped; //Get List of manually mapped modules
		blackbone::ProcessModules::mapModules bbModulesLdrList;   //modules found thru walking list at peb.ldr.InLoadOrderModuleList
		blackbone::ProcessModules::mapModules bbModulesPEHeaders; //modules found thru walking memory looking for valid PE headers
		blackbone::ProcessModules::mapModules bbModulesSections;  //modules found thru walking memory sections and looking for PE headers
															      //(wiped headers will be detected)

		ThreadsCollection threads;
		ModulesCollection modules;
	};

	typedef std::shared_ptr<ProcessData> ProcessDataPtr;
	typedef std::map<DWORD, ProcessDataPtr> ProcessCollection;
	typedef std::map<DWORD, std::vector<std::wstring>> ThreadInfoCollection;
	typedef std::map<std::wstring, std::wstring> ProcessInfoContainer;
	typedef std::vector<std::wstring> ModulesInfoContainer;
//	typedef std::unordered_map<std::wstring, std::wstring> ReportPropertiesType;
	typedef std::vector<std::pair<std::wstring, std::wstring>> ReportPropertiesType;

	class SuspiciousProcessData
	{
	public:

		SuspiciousProcessData(const DWORD _pid, const CustomTypes::HunterID &_hunter) : 
			m_pid(_pid), m_hunterDetected(_hunter) 
		{
			m_processMainThreadID = 0;
		}

		void ClearProcessName() { m_processName.clear(); }
		void ClearThreadsInformation() { m_threads.clear(); }
		void ClearProcessInformation() { m_processData.clear(); }
		void ClearModulesInformation() { m_modules.clear(); }
		void ClearHunterDetected() { m_hunterDetected = CustomTypes::HunterID::HUNT_NA; }
		void ClearProperties() { m_properties.clear(); }
		void ClearTokenInfo() { m_ProcessTokenInfo.clear(); }

		void ClearAll()
		{
			m_processName.clear();
			m_threads.clear();
			m_processData.clear();
			m_modules.clear();
			m_properties.clear();
			m_ProcessTokenInfo.clear();
			m_hunterDetected = CustomTypes::HunterID::HUNT_NA;
		}

		void SetTokenInfo(std::wstring &tokenInfo) { m_ProcessTokenInfo.assign(tokenInfo);  }
		void SetProcessName(std::wstring &processName) { m_processName.assign(processName); }
		void AddThreadInformation(DWORD &threadID, std::wstring &threadInfo);
		void AddProcessInformation(std::wstring &key, std::wstring &value);
		void AddModulesInformation(std::wstring &modules) { m_modules.push_back(modules); };
		void AddNewProperty(const std::wstring &key, const std::wstring &value)
		{
			std::pair newElement(key, value);
			m_properties.push_back(newElement);
		}

		DWORD GetPID() { return m_pid; }
		const std::wstring &GetTokenInfo() { return m_ProcessTokenInfo; }
		const std::wstring &GetProcessName() { return m_processName; }
		const CustomTypes::HunterID &GetDetectedHunter() { return m_hunterDetected; }
		const ThreadInfoCollection &GetThreadsInformation() { return m_threads; }
		const ProcessInfoContainer &GetProcessInformation() { return m_processData; }
		const ModulesInfoContainer &GetModulesInformation() { return m_modules; }
		const ReportPropertiesType &GetProperties() { return m_properties; }
		const std::wstring &GetProperties(const std::wstring &key)
		{ 
			std::wstring ret;

			for (auto it = m_properties.begin(); it != m_properties.end(); it++)
			{
				std::pair newElement(*it);
				if (newElement.first == key)
				{
					ret.assign(newElement.second);
					break;
				}
			}

			return ret; 
		}

	private:
		DWORD m_pid;
		std::wstring m_processName;
		ThreadInfoCollection m_threads;
		ProcessInfoContainer m_processData;
		ModulesInfoContainer m_modules;
		CustomTypes::HunterID m_hunterDetected;
		
		std::wstring m_processCmdLine;
		std::wstring m_processMainModulePath;
		std::wstring m_ProcessTokenInfo;
		DWORD m_processMainThreadID;
		ReportPropertiesType m_properties;
	};
	//typedef std::map<DWORD, std::shared_ptr<HunterCommon::SuspiciousProcessData>> SuspiciousProcessType;
	typedef std::shared_ptr<HunterCommon::SuspiciousProcessData> SuspiciousProcessDataPtr;
	typedef std::map<DWORD, SuspiciousProcessDataPtr> SuspiciousProcessType;

	struct RangeData
	{
		RangeData() : minValue(0), maxValue(0) {}

		RangeData(size_t _minValue, size_t _maxValue)
			: minValue(_minValue), maxValue(_maxValue) {}

		size_t minValue;
		size_t maxValue;
	};

	struct CallStackData
	{
		CallStackData() : stackFrameAddress(0), baseOfImageAddress(0), symbolAddress(0), imageSize(0), symbolAvailable(0),
			timeDateStamp(0), checksum(0), numSyms(0), symType(SymNone) {}

		DWORD64 stackFrameAddress;
		DWORD64 baseOfImageAddress;
		DWORD64 symbolAddress;
		DWORD64 symbolAvailable;
		DWORD imageSize;
		DWORD timeDateStamp;
		DWORD checksum;
		DWORD numSyms;
		SYM_TYPE symType;
		std::string moduleName;
		std::string imageName;
		std::string loadedImageName;
		std::string symbolName;
	};

	typedef std::multimap<DWORD, SuspiciousProcessDataPtr> SuspiciousProcessess;

	typedef std::shared_ptr<CallStackData> CallStackDataPtr;
	typedef std::vector<CallStackDataPtr> CallStackDataList;

	struct PatternData
	{
		blackbone::PatternSearch pattern;
		uint8_t wildcard;
		size_t patternSize;
	};
	typedef std::shared_ptr<PatternData> PatternDataPtr;
}

namespace CustomWinTypes
{
	typedef struct _CLIENT_ID {
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;

	typedef LONG NTSTATUS;
	typedef LONG KPRIORITY;
#define STATUS_SUCCESS    ((NTSTATUS)0x00000000L)

	typedef struct _THREAD_BASIC_INFORMATION {
		NTSTATUS  ExitStatus;
		PVOID     TebBaseAddress;
		CLIENT_ID ClientId;
		KAFFINITY AffinityMask;
		KPRIORITY Priority;
		KPRIORITY BasePriority;
	} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

	const static THREADINFOCLASS ThreadBasicInformation = (THREADINFOCLASS)0;
	const static THREADINFOCLASS ThreadQuerySetWin32StartAddress = (THREADINFOCLASS)9;

	typedef NTSTATUS(WINAPI *PNtQueryInformationThread) (
		HANDLE thread,
		THREADINFOCLASS infoclass, 
		PVOID buffer, 
		ULONG buffersize,
		PULONG used);

	typedef NTSTATUS(NTAPI *pNtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);

	typedef BOOL(WINAPI *PFN_ISWOW64PROCESS)(HANDLE hProcess, PBOOL Wow64Process);
}