#include "common.h"

void ShowHelp()
{
	TraceHelpers::TraceConsole(" _____           _           _           ");
	TraceHelpers::TraceConsole("|     |___ _____| |_ _ _ ___| |_ ___ ___ ");
	TraceHelpers::TraceConsole("| | | | -_|     |   | | |   |  _| -_|  _|");
	TraceHelpers::TraceConsole("|_|_|_|___|_|_|_|_|_|___|_|_|_| |___|_|  ");
	TraceHelpers::TraceConsole("     Live Memory Forensics Hunter        ");
	TraceHelpers::TraceConsole("\nMemhunter Version: %s", CustomDefs::MEMHUNTER_VERSION.c_str());

	TraceHelpers::TraceConsole("\nAvailable Hunters IDs:");
	TraceHelpers::TraceConsole(" %d - Suspicious Threads - It looks for RWX pages on threads base address", 
		CustomTypes::HunterID::HUNT_SUSPICIOUS_THREADS);
	TraceHelpers::TraceConsole(" %d - Suspicious CallStack - It perform thread callstack analysis to check on suspicious patterns",
		CustomTypes::HunterID::HUNT_SUSPICIOUS_CALLSTACK);
	TraceHelpers::TraceConsole(" %d - Suspicious Exports - It looks for know bad exports",
		CustomTypes::HunterID::HUNT_SUSPICIOUS_EXPORTS);
	TraceHelpers::TraceConsole(" %d - Suspicious Hollowed Modules - It performs PE Header comparison of on-memory modules vs on-disk counterpart",
		CustomTypes::HunterID::HUNT_SUSPICIOUS_HOLLOWS);
	TraceHelpers::TraceConsole(" %d - Suspicious Modules - It looks for RWX memory regions on modules memory areas",
		CustomTypes::HunterID::HUNT_SUSPICIOUS_MODULES);
	TraceHelpers::TraceConsole(" %d - Suspicious Parents - It looks for suspicious parents",
		CustomTypes::HunterID::HUNT_SUSPICIOUS_PARENTS);
	TraceHelpers::TraceConsole(" %d - Suspicious Regions - It looks for wiped PE headers on section related memory areas",
		CustomTypes::HunterID::HUNT_SUSPICIOUS_REGIONS);
	TraceHelpers::TraceConsole(" %d - Suspicious Registry - It looks for well-know persistence, evasion techniques on the registry",
		CustomTypes::HunterID::HUNT_SUSPICIOUS_REGISTRY_PERSISTENCE);
	TraceHelpers::TraceConsole(" %d - Suspicious Shellcode - It performs fuzzy matching on commited memory to look for function prologues",
		CustomTypes::HunterID::HUNT_SUSPICIOUS_SHELLCODE);

	TraceHelpers::TraceConsole("\nAvailable Options:");
	TraceHelpers::TraceConsole(" -c <conf_file>			Path to configuration file");
	TraceHelpers::TraceConsole(" -m <id_list>			List of Hunters to use. All included by Default");
	TraceHelpers::TraceConsole(" -d				Enable Dissolvable mode. Disabled by Default");
	TraceHelpers::TraceConsole(" -f				Enable False Positive Mitigations. Enabled by Default");
	TraceHelpers::TraceConsole(" -r <verbose|regular|minimal>	Report Verbosity Options. Regular by Default");
	TraceHelpers::TraceConsole(" -e <exclusion_list>		List of Processes To Exclude");
	TraceHelpers::TraceConsole(" -o <console|eventlog>		Report Output Options. Console by Default");
	TraceHelpers::TraceConsole(" -y <path>			Path to YARA Rules to use");
	TraceHelpers::TraceConsole(" -v <path>			Path to VirusTotal license to use");
	TraceHelpers::TraceConsole(" -h				Display help information");

	TraceHelpers::TraceConsole("\nUsage Example:");
	TraceHelpers::TraceConsole(" -h for help			Help");
	TraceHelpers::TraceConsole(" -c <config_file>		Configuration File");
	TraceHelpers::TraceConsole(" -f -o eventlog -m 1,2,3	Normal Usage");
}

int wmain(int argc, wchar_t *argv[])
{
	int ret = EXIT_FAILURE;

	//Check if process is running as Administrator and DEBUG token privileges can be enabled
	if (GeneralHelpers::IsRunningAsAdmin() && GeneralHelpers::EnableTokenPrivilege(SE_DEBUG_NAME))
	{
		if (!ConfigManager::GetInstance().Initialize(argc, argv))
		{
			ShowHelp();
		}
		else
		{
			//Same binary supports two running modes

			//Checking if main thread needs to run as a service 
			if (ConfigManager::GetInstance().IsServiceModeEnabled())
			{
				//Running as a service
				CollectorService::GetInstance().RunService();
			}
			else
			{
				//Checking if service is registered, if yes make sure that it is running
				if (ConfigManager::GetInstance().IsServiceDataAvailable())
				{
					//and making sure that service is still running
					if (ServiceHelpers::IsServiceStopped(CustomDefs::SERVICE_NAME))
					{
						//Starting the service					
						if (!ServiceHelpers::StartTargetService(CustomDefs::SERVICE_NAME))
						{
							TraceHelpers::TraceConsoleDown("There was a problem starting collector service. Service is currently stopped.");
						}						
					}
				}
				else
				{
					TraceHelpers::TraceConsoleDown("There was a problem with collection service. No collected data will be available.");
				}

				//Run hunters orchestration logic
				if (HuntersOrchestration::GetInstance().Run())
				{
					ret = EXIT_SUCCESS;
				}
				else
				{
					TraceHelpers::TraceConsoleDown("There was a problem orchestrating the registered hunters.");
				}
			}
		}
	}
	else
	{
		TraceHelpers::TraceConsoleDown("This process should be with Administrator privileges. Showing help and quitting now.");
		ShowHelp();
	}

    return ret;
}

