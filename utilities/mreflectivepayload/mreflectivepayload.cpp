#include "ReflectiveLoader.h"
#include "dllcommon.h"

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern "C" HINSTANCE hAppInstance;
BOOL WINAPI DllMain(HINSTANCE hinstDLL,
	DWORD  dwReason,
	LPVOID lpReserved
)
{
	switch (dwReason)
	{
		case DLL_QUERY_HMODULE:
			if (lpReserved != NULL)
			{
				*(HMODULE *)lpReserved = hAppInstance;
			}
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
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
