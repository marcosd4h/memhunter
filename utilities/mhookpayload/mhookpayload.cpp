#include "dllcommon.h"


// Exporting function usable with SetWindowsHookEx
extern "C" __declspec(dllexport) int NextHook(int code, WPARAM wParam, LPARAM lParam)
{
	return ((int)CallNextHookEx(NULL, code, wParam, lParam));
}


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
			break;
	}
	return TRUE;
}


