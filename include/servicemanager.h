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
	void StartKernelTrace() { if (m_kernelTrace) m_kernelTrace->start(); };
	void StopKernelTrace() { if (m_kernelTrace) m_kernelTrace->stop(); };

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
		m_kernelTrace = new krabs::kernel_trace(L"MemhunterETWCollectionTraceSession");
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

	//Workers
	bool InitETWCollectionWorker();

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

	// Private vars
	std::wstring m_serviceName;
	krabs::kernel_trace *m_kernelTrace;
};
