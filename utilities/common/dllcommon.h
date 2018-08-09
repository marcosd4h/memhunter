#pragma once

#include <thread>
#include <string>
#include <iostream>
#include <windows.h>
#include "detours.h"

namespace DLL_COMMON_DEFS
{
	static const wchar_t *WINDOW_TITLE = L"Minjector Test Utility";
	static const wchar_t *COMMON_MESSAGE = L"Code Injected!";
}

namespace DLL_COMMON_ACTIONS
{
	bool LaunchShowWindowsMessage();
	bool KillShowWindowsMessage();
	void BlockingSleep();
}
