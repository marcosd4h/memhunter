#pragma once

#include "common.h"

class ConfigManager 
{
public:
	static ConfigManager& GetInstance() 
	{
		static ConfigManager instance;
		return instance;
	}

	bool Initialize(int argc, wchar_t *argv[]);

	const bool IsInitialized() { return m_isInitialized; }
	const bool IsConfigurationFileReady() { return m_isConfigurationReady; }
	const bool IsServiceModeEnabled() { return m_isServiceMode; }
	const bool IsServiceDataAvailable() { return m_isServiceDataAvailable; }
	const bool IsDissolvableModeEnabled() { return m_dissolvableMode; }
	const bool IsFPMitigationLogicEnabled() { return m_fpMitigations; }
	const bool IsProcessExcluded(const std::wstring &processName);
	const bool IsValidPID(const DWORD& pid);
	const bool IsHunterEnabled(const CustomTypes::HunterID &hunterID);

	const UINT32 GetWorkerHunterThreads() { return m_nrWorkerHunterThreads; }
	const UINT32 GetWorkerOrchestrationThreads() { return m_nrWorkerOrchThreads; }
	const CustomTypes::ReportVerbosity &GetReportVerbosity() { return m_reportVerbosity; }
	const CustomTypes::ReportOutput &GetReportOutput() { return m_reportOutput; }
	const std::wstring &GetYaraPath() { return m_yaraPath; }
	const std::wstring &GetVirusTotalPath() { return m_virusTotalPath; }
	const std::wstring &GetWindowsSystemDirectory() { return m_systemDirectory; }
	const CustomTypes::YaraRulesList &GetYaraRules() { return m_yaraRules; }

private:

	const CustomTypes::HuntersList &GetEnabledHunters() { return m_enabledHunters; }
	const CustomTypes::ExclusionsList &GetProcessExclusions() { return m_exclusions; }

	bool ParseYaraRulesFromJSON(nlohmann::json &jconf);
	bool ParseExclusionsFromJSON(nlohmann::json &jconf);
	void BuildListOfEnabledHunters(const std::wstring &enabledHunterIds);
	void BuildReportOptions(const std::wstring &reportMode, const std::wstring &reportOutput);
	void BuildSystemData();
	ConfigManager() : m_isInitialized(false), m_isConfigurationReady(false), 
		m_isServiceMode(false), m_isServiceDataAvailable(false), 
		m_dissolvableMode(false), m_fpMitigations(false), 
		m_nrWorkerHunterThreads(CustomDefs::DEFAULT_NR_WORKING_THREADS), 
		m_nrWorkerOrchThreads(CustomDefs::DEFAULT_NR_WORKING_THREADS) {};

	ConfigManager(const ConfigManager&) = delete;
	ConfigManager& operator = (const ConfigManager&) = delete;

	bool m_isInitialized;
	bool m_isConfigurationReady;
	bool m_isServiceMode;
	bool m_isServiceDataAvailable;
	bool m_dissolvableMode;
	bool m_fpMitigations;
	UINT32 m_nrWorkerHunterThreads;
	UINT32 m_nrWorkerOrchThreads;
	CustomTypes::ReportVerbosity m_reportVerbosity;
	CustomTypes::ReportOutput m_reportOutput;
	std::wstring m_yaraPath;
	std::wstring m_virusTotalPath;
	std::wstring m_systemDirectory;
	CustomTypes::HuntersList m_enabledHunters;
	CustomTypes::YaraRulesList m_yaraRules;
	CustomTypes::ExclusionsList m_exclusions;
};