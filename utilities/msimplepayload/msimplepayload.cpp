#include "dllcommon.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL,
	DWORD  dwReason,
	LPVOID lpReserved
)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			DLL_COMMON_ACTIONS::LaunchShowWindowsMessage();
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:
			DLL_COMMON_ACTIONS::KillShowWindowsMessage();
			break;
		}

	return TRUE;
}
