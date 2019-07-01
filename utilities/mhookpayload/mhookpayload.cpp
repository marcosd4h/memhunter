#include "dllcommon.h"


// Exporting function usable with SetWindowsHookEx
extern "C" __declspec(dllexport) int NextHook(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == WM_NULL)
	{
		static const wchar_t *EVENT_NAME = L"JustSomeMagicEventName";
		HANDLE syncEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, EVENT_NAME);
		if (SetEvent(syncEvent))
		{
			OutputDebugString(L"NextHook() - Event Set!");
		}
		else
		{
			OutputDebugString(L"NextHook() - Event NOT Set!");
		}
	}

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


