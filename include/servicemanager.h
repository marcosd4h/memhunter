#pragma once

#include "common.h"

class CollectorService
{
public:

	static CollectorService& GetInstance()
	{
		static CollectorService instance;
		return instance;
	}

	//Control functions
	bool RunService();
	bool StopService();

	//Helpers
	const wchar_t * GetServiceName(){ return m_serviceName.c_str(); };
	bool CheckServiceSanity();

	//Public Methods needed by static SCM-reachable members
	SERVICE_STATUS ServiceStatus;
	HANDLE ServiceStopEvent;
	SERVICE_STATUS_HANDLE ServiceStatusHandle;
	
private:

	CollectorService()
	{
		ServiceStopEvent = INVALID_HANDLE_VALUE;
		ServiceStatusHandle = NULL;
		memset(&ServiceStatus, 0, sizeof(ServiceStatus));
	};

	~CollectorService()
	{
		if (ServiceStopEvent)
		{
			CloseHandle(ServiceStopEvent);
			ServiceStopEvent = NULL;
		}
	}

	CollectorService(const CollectorService&) {};

	//Helpers functions
	
	bool WINAPI UpdateServiceStatus(DWORD updateState, DWORD exitCode = NO_ERROR, DWORD waitTime = 0);

	// Static SCM functions
	static void WINAPI ServiceMain(DWORD argc, LPWSTR *argv);
	static void WINAPI ServiceControlHandler(DWORD ctrlCode);
	static DWORD WINAPI WorkerThread(LPVOID lpParam);

	//SCM Callbacks
	bool Run(DWORD dwArgc, PWSTR *pszArgv);
	bool Pause();
	bool Continue();
	bool Shutdown();

	// The name of the service
	std::wstring m_serviceName;
};
