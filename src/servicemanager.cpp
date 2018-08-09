#include "common.h"

bool CollectorService::Continue()
{
	bool ret = false;

	try
	{
		TraceHelpers::TraceUp("Continue is not yet supported");
		ret = true;

	}
	catch (...)
	{
		TraceHelpers::TraceDown("There was an error continuing the service. Setting state to original one.");
	}

	return ret;
}


bool CollectorService::Pause()
{
	bool ret = false;

	try
	{
		TraceHelpers::TraceUp("Paused is not yet supported");
		ret = true;

	}
	catch (...)
	{
		TraceHelpers::TraceDown("There was an error pausing the service. Setting state to original one.");
	}

	return ret;
}


bool CollectorService::Shutdown()
{
	bool ret = false;

	DWORD originalState = CollectorService::GetInstance().ServiceStatus.dwCurrentState;

	try
	{
		if (UpdateServiceStatus(SERVICE_STOP_PENDING))
		{
			SetEvent(CollectorService::GetInstance().ServiceStopEvent);

			if (UpdateServiceStatus(SERVICE_STOPPED))
			{
				ret = true;
			}
		}

		if (!ret)
		{
			TraceHelpers::TraceDown("There was an error stopping the service. Setting state to original one");
			UpdateServiceStatus(originalState);
		}
	}
	catch (...)
	{
		TraceHelpers::TraceDown("There was an error stopping the service. Setting state to original one.");
		UpdateServiceStatus(originalState);
	}

	return ret;
}


bool CollectorService::Run(DWORD dwArgc, PWSTR *pszArgv)
{
	bool ret = false;

	try
	{
		if (pszArgv)
		{
			TraceHelpers::TraceUp("test5");
			if (UpdateServiceStatus(SERVICE_START_PENDING))
			{
				//Service is registered, now initialize stop event
				CollectorService::GetInstance().ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
				if (CollectorService::GetInstance().ServiceStopEvent)
				{
					HANDLE hThread = CreateThread(NULL, 0, CollectorService::WorkerThread, NULL, 0, NULL);
					if ((hThread != INVALID_HANDLE_VALUE) && UpdateServiceStatus(SERVICE_RUNNING))
					{
						ret = true;
					}
				}
			}
		}

		if (!ret)
		{
			TraceHelpers::TraceDown("There was an error starting the service. Shutting it down.");
			UpdateServiceStatus(SERVICE_STOPPED);
		}
	}
	catch (...)
	{
		TraceHelpers::TraceDown("There was an error starting the service. Shutting it down.");
		UpdateServiceStatus(SERVICE_STOPPED);
	}

	return ret;
}

bool WINAPI CollectorService::UpdateServiceStatus(DWORD updateState, DWORD exitCode, DWORD waitTime)
{
	bool ret = false;
	DWORD acceptedCtrls = 0;

	acceptedCtrls |= SERVICE_ACCEPT_STOP;
	acceptedCtrls |= SERVICE_ACCEPT_SHUTDOWN;
	//acceptedCtrls |= SERVICE_ACCEPT_PAUSE_CONTINUE;

	Sleep(waitTime);

	CollectorService::GetInstance().ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	CollectorService::GetInstance().ServiceStatus.dwControlsAccepted = acceptedCtrls;
	CollectorService::GetInstance().ServiceStatus.dwCurrentState = updateState;
	CollectorService::GetInstance().ServiceStatus.dwWin32ExitCode = exitCode;
	CollectorService::GetInstance().ServiceStatus.dwServiceSpecificExitCode = 0;
	CollectorService::GetInstance().ServiceStatus.dwCheckPoint = 0;
	CollectorService::GetInstance().ServiceStatus.dwWaitHint = 0;

	if (SetServiceStatus(CollectorService::GetInstance().ServiceStatusHandle, &CollectorService::GetInstance().ServiceStatus))
	{
		ret = true;
	}

	return ret;
}

void WINAPI CollectorService::ServiceControlHandler(DWORD ctrlCode)
{
	switch (ctrlCode)
	{
		case SERVICE_CONTROL_PAUSE: 
			CollectorService::GetInstance().Pause();
			break;
		case SERVICE_CONTROL_CONTINUE: 
			CollectorService::GetInstance().Continue();
			break;
		case SERVICE_CONTROL_STOP: 
		case SERVICE_CONTROL_SHUTDOWN:
			CollectorService::GetInstance().Shutdown();
			break;
		case SERVICE_CONTROL_INTERROGATE:
		default:
			break;
	}
}

void WINAPI CollectorService::ServiceMain(DWORD argc, LPWSTR *argv)
{
	DWORD status = E_FAIL;

	//setting handler
	CollectorService::GetInstance().ServiceStatusHandle = RegisterServiceCtrlHandler(CollectorService::GetInstance().GetServiceName(), ServiceControlHandler);
	if (CollectorService::GetInstance().ServiceStatusHandle != NULL)
	{
		TraceHelpers::TraceUp("test2");
		if (!CollectorService::GetInstance().Run(argc, argv))
		{
			TraceHelpers::TraceUp("test3");
			TraceHelpers::TraceDown("There was a problem starting memhunter collector service");
		}
	}
}



bool CollectorService::RunService()
{
	bool ret = false;

	SERVICE_TABLE_ENTRY sTable[] =
	{
		{ (wchar_t *) CustomDefs::SERVICE_NAME.c_str(), ServiceMain },
		{ NULL, NULL }
	};

	//connects with SCM
	if (StartServiceCtrlDispatcher(sTable))
	{
		ret = true;
		TraceHelpers::TraceUp("StartServiceCtrlDispatcher was succesfully called");
	}
	else
	{
		DWORD err = GetLastError();
		TraceHelpers::TraceDown("There was a problem connecting with SCM. Error is 0x%x", err);
	}

	return ret;
}

bool CollectorService::StopService()
{
	bool ret = false;

	if (Shutdown())
	{
		ret = true;
	}

	return ret;
}


//TODO: Check if service DB is accessible or needs to be regenerated
bool CollectorService::CheckServiceSanity()
{
	bool ret = false;
	bool regIsNeeded = false;
	std::wstring currentBinFullPath;

	//Getting current path first
	if (GeneralHelpers::GetCurrentProcessModuleFullPath(currentBinFullPath))
	{
		//Checking first if service is already created
		if (ServiceHelpers::IsServiceCreated(CustomDefs::SERVICE_NAME))
		{
			//Checking then if same executable is being used
			if (ServiceHelpers::IsSameServiceExecutablePath(CustomDefs::SERVICE_NAME, currentBinFullPath))
			{
				//Service is registered with current executable, all is good
				ret = true;
			}
			else
			{
				ServiceHelpers::DeleteService(CustomDefs::SERVICE_NAME);
				regIsNeeded = true;
			}
		}
		else
		{
			regIsNeeded = true;
		}

		//Registering service
		if (regIsNeeded)
		{
			if (ServiceHelpers::RegisterService(currentBinFullPath, CustomDefs::SERVICE_ARGS, CustomDefs::SERVICE_NAME, CustomDefs::SERVICE_DISPLAY))
			{
				ret = true;
			}
		}
	}

	return ret;
}

DWORD WINAPI CollectorService::WorkerThread(LPVOID lpParam)
{
	DWORD ret = ERROR_SUCCESS;

	if (CollectorService::GetInstance().ServiceStopEvent)
	{
		//Checking if we need to stop periodically
		while (WaitForSingleObject(CollectorService::GetInstance().ServiceStopEvent, 0) != WAIT_OBJECT_0)
		{
			TraceHelpers::TraceUp("--- Checking periodically ---");
			Sleep(500);
		}
	}

	return ret;
}