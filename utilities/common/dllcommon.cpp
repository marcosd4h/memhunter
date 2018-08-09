#include "dllcommon.h"

bool DLL_COMMON_ACTIONS::LaunchShowWindowsMessage()
{
	bool ret = false;

	if (!MessageBox(NULL, DLL_COMMON_DEFS::COMMON_MESSAGE, DLL_COMMON_DEFS::WINDOW_TITLE, MB_SYSTEMMODAL | MB_OKCANCEL | MB_ICONQUESTION))
	{
		ret = true;
	}

	return ret;
}

bool DLL_COMMON_ACTIONS::KillShowWindowsMessage()
{
	bool ret = false;

	HWND hwnd = ::FindWindowEx(0, 0, DLL_COMMON_DEFS::WINDOW_TITLE, 0);
	if (hwnd)
	{
		::SendMessage(hwnd, WM_CLOSE, 0, 0);
		ret = true;
	}

	return ret;
}

void DLL_COMMON_ACTIONS::BlockingSleep()
{
	while (true) Sleep(100);
}
