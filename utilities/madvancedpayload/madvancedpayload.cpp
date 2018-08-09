#include "dllcommon.h"
/*
#include <thread>
#include <BlackBone/Config.h>
#include <BlackBone/Process/Process.h>
#include <BlackBone/Process/MultPtr.hpp>
#include <BlackBone/PE/PEImage.h>
#include <BlackBone/Process/RPC/RemoteFunction.hpp>
#include <BlackBone/PE/PEImage.h>
#include <BlackBone/Misc/Utils.h>
#include <BlackBone/Misc/DynImport.h>
#include <BlackBone/Syscalls/Syscall.h>
#include <BlackBone/Patterns/PatternSearch.h>
#include <BlackBone/Asm/LDasm.h>
#include <BlackBone/localHook/VTableHook.hpp>
#include <BlackBone/Patterns/PatternSearch.h>
#include <BlackBone/Process/RPC/RemoteFunction.hpp>
#include <BlackBone/Syscalls/Syscall.h>
*/

static HANDLE workingThread = INVALID_HANDLE_VALUE;

DWORD WINAPI WorkerThread(LPVOID lpParam)
{
	/*
	blackbone::Process localProc;
	if ((localProc.Attach(GetCurrentProcess()) == ERROR_SUCCESS) &&
		(localProc.valid()))
	{
		if (localProc.memory().SetupHook(blackbone::RemoteMemory::MemVirtualAlloc) == ERROR_SUCCESS)
		{
			OutputDebugString(L"[+] MemVirtualAlloc() remot hook succesfully placed!\n");
		}

		if (localProc.memory().SetupHook(blackbone::RemoteMemory::MemVirtualFree) == ERROR_SUCCESS)
		{
			OutputDebugString(L"[+] MemVirtualFree() remot hook succesfully placed!\n");
		}

		if (localProc.memory().SetupHook(blackbone::RemoteMemory::MemMapSection) == ERROR_SUCCESS)
		{
			OutputDebugString(L"[+] MemMapSection() remot hook succesfully placed!\n");
		}

		if (localProc.memory().SetupHook(blackbone::RemoteMemory::MemUnmapSection) == ERROR_SUCCESS)
		{
			OutputDebugString(L"[+] MemUnmapSection() remot hook succesfully placed!\n");
		}
	}
	*/
	//DLL_COMMON_ACTIONS::LaunchShowWindowsMessage();	
	//DLL_COMMON_ACTIONS::BlockingSleep();
	OutputDebugString(DLL_COMMON_DEFS::WINDOW_TITLE);
	OutputDebugString(DLL_COMMON_DEFS::COMMON_MESSAGE);
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,
	DWORD  dwReason,
	LPVOID lpReserved
)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			workingThread = CreateThread(NULL, 0, &WorkerThread, 0, 0, nullptr);
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:			
			if (workingThread != INVALID_HANDLE_VALUE)
			{
				TerminateThread(workingThread, 0);
				//CloseHandle(workingThread);
				//workingThread = INVALID_HANDLE_VALUE;
			}
			break;
		}
	return TRUE;
}
