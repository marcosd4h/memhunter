#include "common.h"

bool ConfigManager::Initialize(int argc, wchar_t *argv[])
{
	bool ret = false;
	CmdArgsParser cmdArgs;

	try 
	{
		//attempting to initialize config using user provided data
		if (cmdArgs.Initialize(argc, argv))
		{
			//Parsing values not comming from conf file
			if (cmdArgs.WasOptionRequested(L"-s"))
			{
				m_isServiceMode = true;
			}
			else
			{
				m_isServiceMode = false;
			}

			//Checking if service data is available
			if (CollectorService::GetInstance().CheckServiceSanity())
			{
				m_isServiceDataAvailable = true;
			}
		
			//No need to parse rest of configuration on service mode
			if (m_isServiceMode)
			{
				ret = true;
			}
			else
			{
				nlohmann::json jconf;

				if (cmdArgs.WasOptionRequested(L"-h") || 
					cmdArgs.WasOptionRequested(L"-H") ||
					cmdArgs.WasOptionRequested(L"/?"))
				{
					//help is needed. Quitting now.
					ret = false;
				}
				else
				{
					//Now parsing configuration from both conf file
					std::string configFileContent;
					std::wstring enabledHunterIds;
					std::wstring workingReportMode;
					std::wstring workingReportOutput;
					if (cmdArgs.WasOptionRequested(L"-c"))
					{
						//Config file was specified, check config file content					
						std::wstring workingFile = cmdArgs.GetOptionValue(L"-c");
						std::wstring workingFullPathFile;

						if (!workingFile.empty() &&
							GeneralHelpers::IsValidFile(workingFile) &&
							GeneralHelpers::GetFullPathToFile(workingFile, workingFullPathFile) &&
							GeneralHelpers::GetTargetFileIntoString(workingFullPathFile, configFileContent))
						{
							//getting content into JSON object
							jconf = nlohmann::json::parse(configFileContent.c_str());
							if (!jconf.empty())
							{
								m_isConfigurationReady = true;
							}
							else
							{
								TraceHelpers::TraceConsoleDown("There was a problem parsing config file content");
							}
						}
						else
						{
							TraceHelpers::TraceConsoleDown("There was a problem with the given config file");
						}
					}

					//If configuration file parsing was succesfull, fetching conf values from there
					if (m_isConfigurationReady)
					{
						//Parsing values coming from conf file
						m_dissolvableMode = jconf.value("dissolvableMode", CustomDefs::DEFAULT_DISSOLVABLE_MODE);
						m_fpMitigations = jconf.value("fpMitigations", CustomDefs::DEFAULT_FP_MITIGATIONS_MODE);
						m_nrWorkerOrchThreads = jconf.value("workerOrchestrationThreads", CustomDefs::DEFAULT_NR_WORKING_THREADS);
						m_nrWorkerHunterThreads = jconf.value("workerHunterThreads", CustomDefs::DEFAULT_NR_WORKING_THREADS);
						workingReportOutput = jconf.value("verboseMode", CustomDefs::DEFAULT_REPORT_MODE);
						workingReportMode = jconf.value("reportMode", CustomDefs::DEFAULT_REPORT_OUTPUT);
						m_yaraPath = jconf.value("yaraPath", CustomDefs::DEFAULT_VALUE);
						m_virusTotalPath = jconf.value("virusTotalPath", CustomDefs::DEFAULT_VALUE);

						//Saving list of hunters ID
						enabledHunterIds = jconf.value("enabledHunters", CustomDefs::DEFAULT_VALUE);

						//Parsing Exclusions
						if (!ParseExclusionsFromJSON(jconf))
						{
							TraceHelpers::TraceConsoleUp("There was a problem parsing Exclusions content. Assigning empty value");
							m_exclusions.clear();
						}

						if (!ParseYaraRulesFromJSON(jconf))
						{
							TraceHelpers::TraceConsoleUp("There was a problem parsing Yara Rules content. Assigning empty value");
							m_yaraRules.clear();
						}

					}
					else //otherwise check if commandline was provided or if we should use default values
					{
						//Parsing Enabled Hunter IDs
						enabledHunterIds = CustomDefs::DEFAULT_VALUE;
						if (cmdArgs.WasOptionRequested(L"-m"))
						{
							enabledHunterIds = cmdArgs.GetOptionValue(L"-m");
						}

						//Parsing Dissolvable Mode
						m_dissolvableMode = CustomDefs::DEFAULT_DISSOLVABLE_MODE;
						if (cmdArgs.WasOptionRequested(L"-d"))
						{			
							m_dissolvableMode = true;
						}

						//Parsing FP Mitigations
						m_fpMitigations = CustomDefs::DEFAULT_FP_MITIGATIONS_MODE;
						if (cmdArgs.WasOptionRequested(L"-f"))
						{
							m_fpMitigations = false;
						}

						//Parsing YARA Rules Path
						m_yaraPath = CustomDefs::DEFAULT_VALUE;
						if (cmdArgs.WasOptionRequested(L"-y"))
						{
							std::wstring yaraRulesPath = cmdArgs.GetOptionValue(L"-y");
							if (!yaraRulesPath.empty())
							{
								m_yaraPath = yaraRulesPath;
							}
						}

						//Parsing Virus Total License Path
						m_virusTotalPath = CustomDefs::DEFAULT_VALUE;
						if (cmdArgs.WasOptionRequested(L"-v"))
						{
							std::wstring virusTotalPath = cmdArgs.GetOptionValue(L"-v");
							if (!virusTotalPath.empty())
							{
								m_virusTotalPath = virusTotalPath;
							}
						}

						//Parsing Verbosity Mode
						workingReportMode = CustomDefs::DEFAULT_REPORT_MODE;
						if (cmdArgs.WasOptionRequested(L"-r"))
						{
							std::wstring workingVerbosityMode = cmdArgs.GetOptionValue(L"-r");
							if (!workingVerbosityMode.empty())
							{
								workingReportMode = workingVerbosityMode;
							}
						}

						//Parsing Output Options
						workingReportOutput = CustomDefs::DEFAULT_REPORT_OUTPUT;
						if (cmdArgs.WasOptionRequested(L"-o"))
						{
							std::wstring workingReportOutputMode = cmdArgs.GetOptionValue(L"-o");
							if (!workingReportOutputMode.empty())
							{
								workingReportOutput = workingReportOutputMode;
							}
						}

						//Parsing Exclusion List
						m_exclusions.clear();
						if (cmdArgs.WasOptionRequested(L"-e"))
						{
							std::wstring exclusionValueFromConf = cmdArgs.GetOptionValue(L"-e");

							std::vector<std::wstring> workingListOfExclusions;
							if ((!exclusionValueFromConf.empty()) &&
								(GeneralHelpers::GetVectorByToken(exclusionValueFromConf, ',', workingListOfExclusions)) &&
								(workingListOfExclusions.size() > 0))
							{
								for (auto it = workingListOfExclusions.begin(); 
									 it != workingListOfExclusions.end(); 
									 it++)
								{
									std::wstring excValue = *it;
									if (GeneralHelpers::TrimSpaces(excValue))
									{
										CustomTypes::ExclusionsData workExclusion;
										workExclusion.process.assign(excValue);
										m_exclusions.push_back(workExclusion);
									}
								}
							}
						}

					}

					//Build report options
					BuildReportOptions(workingReportMode, workingReportOutput);

					//Build list of hunters
					BuildListOfEnabledHunters(enabledHunterIds);

					//Build System data
					BuildSystemData();

					//No exceptions and parsing went OK
					m_isInitialized = true;
					ret = true;
				}
			}
		}
	}
	catch (nlohmann::json::parse_error& e)
	{
		TraceHelpers::TraceConsoleDown("There was a parsing problem with configuration content %s", e.what());
	}
	catch (...)
	{
		TraceHelpers::TraceConsoleDown("There was a problem initializing given configuration");
	}

	return ret;
}


bool ConfigManager::ParseYaraRulesFromJSON(nlohmann::json &jconf)
{
	bool ret = false;

	if (IsConfigurationFileReady())
	{
		try
		{
			auto itYaraRules = jconf.find("yaraRules");
			if (itYaraRules != jconf.end())
			{
				auto yaraRulesList = jconf["yaraRules"]["files"];
				if (!yaraRulesList.empty())
				{
					for (auto& ruleEntry : yaraRulesList.items())
					{
						auto ruleContent = ruleEntry.value();
						CustomTypes::YaraRulesData newEntry;

						auto itRuleDescription = ruleContent.find("description");
						if (itRuleDescription != ruleContent.end())
						{							
							newEntry.description = ruleContent.at("description").get<std::wstring>();
						}

						auto itRuleFile = ruleContent.find("file");
						if (itRuleFile != ruleContent.end())
						{
							newEntry.filename = ruleContent.at("file").get<std::wstring>();
						}

						if (!newEntry.description.empty() || !newEntry.filename.empty())
						{
							m_yaraRules.push_back(newEntry);
						}						
					}

					ret = true;
				}
			}
		}
		catch (nlohmann::json::parse_error& e)
		{
			TraceHelpers::TraceConsoleDown("There was a parsing problem arsing YaraRules data from configuration: %s", e.what());
		}
		catch (...)
		{
			TraceHelpers::TraceConsoleDown("There was a problem a problem parsing YaraRules data from configuration");
		}
	}

	return ret;
}

bool ConfigManager::ParseExclusionsFromJSON(nlohmann::json &jconf)
{
	bool ret = false;

	if (IsConfigurationFileReady())
	{
		try
		{
			auto itExclusions = jconf.find("exclusions");
			if (itExclusions != jconf.end())
			{
				auto exclusionsList = jconf["exclusions"]["items"];
				if (!exclusionsList.empty())
				{
					for (auto& exclusionEntry : exclusionsList.items())
					{
						auto exclusionContent = exclusionEntry.value();
						CustomTypes::ExclusionsData newEntry;

						auto itExclusionsProcess = exclusionContent.find("process");
						if (itExclusionsProcess != exclusionContent.end())
						{
							newEntry.process = exclusionContent.at("process").get<std::wstring>();
						}

						auto itExclusionsMemhash = exclusionContent.find("memhash");
						if (itExclusionsMemhash != exclusionContent.end())
						{
							newEntry.memhash = exclusionContent.at("memhash").get<std::wstring>();
						}

						if (!newEntry.process.empty() || !newEntry.memhash.empty())
						{
							m_exclusions.push_back(newEntry);
						}
					}

					ret = true;
				}
			}
		}
		catch (nlohmann::json::parse_error& e)
		{
			TraceHelpers::TraceConsoleDown("There was a parsing problem arsing YaraRules data from configuration: %s", e.what());
		}
		catch (...)
		{
			TraceHelpers::TraceConsoleDown("There was a problem a problem parsing YaraRules data from configuration");
		}
	}

	return ret;
}

void ConfigManager::BuildReportOptions(const std::wstring &reportMode, const std::wstring &reportOutput)
{
	if (GeneralHelpers::StrCompare(reportMode, L"verbose"))
	{
		m_reportVerbosity = CustomTypes::ReportVerbosity::REPORT_MODE_VERBOSE;
	}
	else if (GeneralHelpers::StrCompare(reportMode, L"regular"))
	{
		m_reportVerbosity = CustomTypes::ReportVerbosity::REPORT_MODE_REGULAR;
	}
	else if (GeneralHelpers::StrCompare(reportMode, L"minimal"))
	{
		m_reportVerbosity = CustomTypes::ReportVerbosity::REPORT_MODE_MINIMAL;
	}

	if (GeneralHelpers::StrCompare(reportOutput, L"console"))
	{
		m_reportOutput = CustomTypes::ReportOutput::REPORT_OUTPUT_CONSOLE;
	}
	else if (GeneralHelpers::StrCompare(reportOutput, L"eventlog"))
	{
		m_reportOutput = CustomTypes::ReportOutput::REPORT_OUTPUT_EVENTLOG;
	}
}

void ConfigManager::BuildListOfEnabledHunters(const std::wstring &enabledHunterIds)
{
	std::vector<std::wstring> listOfEnabledHunterIDs;
	if ((!enabledHunterIds.empty()) &&
		(GeneralHelpers::GetVectorByToken(enabledHunterIds, ',', listOfEnabledHunterIDs)) &&
		(listOfEnabledHunterIDs.size() > 0))
	{
		for (auto it = listOfEnabledHunterIDs.begin(); it != listOfEnabledHunterIDs.end(); it++)
		{
			std::wstring workElement = *it;
			if (GeneralHelpers::TrimSpaces(workElement) && GeneralHelpers::IsNumber(workElement))
			{
				CustomTypes::HunterID convertedID = 
					(CustomTypes::HunterID)GeneralHelpers::ToInteger(workElement);

				if (Hunter::IsValidHunterID(convertedID))
				{
					m_enabledHunters.insert({convertedID, true });
				}
			}
		}
	}

	//sanity check to fill the list in case previous parsing failed or configuration value was empty
	if (m_enabledHunters.empty())
	{
		UINT32 minValue = (UINT32)CustomTypes::HunterID::HUNT_SUSPICIOUS_THREADS;
		UINT32 maxValue = (UINT32)CustomTypes::HunterID::HUNT_NA;
		for (UINT32 it = minValue;
			it < maxValue;
			it++)
		{
			m_enabledHunters.insert({ (CustomTypes::HunterID)it, true });
		}
	}
}


void ConfigManager::BuildSystemData()
{
	std::wstring workingSystemDirectory;
	if (!GeneralHelpers::GetWindowsSystemDirectory(workingSystemDirectory))
	{
		workingSystemDirectory.assign(CustomDefs::DEFAULT_SYSTEM32_DIRECTORY);
	}
	m_systemDirectory.assign(workingSystemDirectory);
}

const bool ConfigManager::IsValidPID(const DWORD& pid)
{
	bool ret = false;

	if (pid >= CustomDefs::SYSTEM_MIN_VALID_PID)
	{
		ret = true;
	}

	return ret;
}

const bool ConfigManager::IsProcessExcluded(const std::wstring &processName)
{
	bool ret = false;

	if (!processName.empty())
	{
		for (auto procIT = m_exclusions.begin(); procIT != m_exclusions.end(); procIT++)
		{
			if ((!procIT->process.empty()) &&
				(GeneralHelpers::StrCompare(procIT->process, processName)))
			{
				ret = true;
				break;
			}			
		}
	}

	return ret;
}

const bool ConfigManager::IsProcessExcluded(const DWORD &pid)
{
	bool ret = false;

	if (IsValidPID(pid))
	{
		std::wstring processName;
		for (auto procIT = m_exclusions.begin(); procIT != m_exclusions.end(); procIT++)
		{
			if ((GeneralHelpers::GetProcessnameByPID(pid, processName)) &&
				(!processName.empty()) &&
				(!procIT->process.empty()) &&
				(GeneralHelpers::StrCompare(procIT->process, processName)))
			{
				ret = true;
				break;
			}
		}
	}

	return ret;
}


const bool ConfigManager::IsHunterEnabled(const CustomTypes::HunterID &hunterID)
{
	bool ret = false;

	if ((Hunter::IsValidHunterID(hunterID)) && (m_enabledHunters[hunterID]))
	{
		ret = true;
	}

	return ret;
}