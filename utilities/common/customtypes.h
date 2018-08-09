#pragma once

#include <windows.h>

namespace InjectorCommon
{
	enum InjectionMode
	{
		INJ_CREATE_REMOTE_THREAD = 0x01,
		INJ_CREATE_REMOTE_THREAD_STEALTH,
		INJ_QUEUE_USER_APC,
		INJ_SET_WINDOWS_HOOK,
		INJ_REFLECTIVE_DLL_INJECTION,
		INJ_SHELLCODE_DLL_INJECTION,
		INJ_PROCESS_HOLLOWING,
		INJ_SUSPEND_INJECTION_RESUME,
		INJ_IMAGE_MAPPING,
		INJ_THREAD_REUSE,
		INJ_NET_MODULE,
		INJ_PROCESS_DOPPELGANGING,
		INJ_POWERLOADER_EX,
		INJ_APPINIT_DLL,
		INJ_IFEO_PROCESS_CREATION,
		INJ_NA,
	};

	inline const wchar_t* InjectionModeToString(InjectionMode value)
	{
		switch (value)
		{
			case INJ_CREATE_REMOTE_THREAD:			return L"DLL injection via CreateRemoteThread()";
			case INJ_CREATE_REMOTE_THREAD_STEALTH:	return L"DLL injection via an stealth CreateRemoteThread()";
			case INJ_QUEUE_USER_APC:				return L"DLL injection via QueueUserAPC()";
			case INJ_SET_WINDOWS_HOOK:				return L"DLL injection via SetWindowsHookEx()";
			case INJ_SUSPEND_INJECTION_RESUME:		return L"DLL injection via Suspend Injection Resume";
			case INJ_REFLECTIVE_DLL_INJECTION:		return L"DLL injection via Reflective DLL injection";
			case INJ_SHELLCODE_DLL_INJECTION:		return L"DLL injection via Shellcode DLL injection";
			case INJ_PROCESS_HOLLOWING:				return L"Code injection via Process Hollowing";
			case INJ_IMAGE_MAPPING:					return L"DLL injection via Image Mapping";
			case INJ_THREAD_REUSE:					return L"DLL injection via Thread Reuse";
			case INJ_NET_MODULE:					return L".NET DLL injection into native/managed processes";
			case INJ_PROCESS_DOPPELGANGING:			return L"Code injection via Hasherezade Process Doppelganging implementation";		
			case INJ_POWERLOADER_EX:				return L"DLL injection via Ensilo PowerLoaderEx";
			case INJ_APPINIT_DLL:					return L"DLL injection via System APPINIT_DLLS";
			case INJ_IFEO_PROCESS_CREATION:			return L"Code Injection via Image File Execution Options";
			default:								return L"[Unknown Injection Mode]";
		}
	}

	static const InjectionMode DEFAULT_INJECTION_TYPE = InjectionMode::INJ_CREATE_REMOTE_THREAD;
	static const bool DEFAULT_VERBOSITY_STATUS = false;
	static const unsigned int DEFAULT_MINIMUM_USERSPACE_PID = 4;
	static const std::wstring MINJECTOR_VERSION = L"v0.5";
}