// minjector.cpp : Defines the entry point for the console application.
//

#include "common.h"
#include "injectorManager.h"

void ShowHelp()
{
	std::wcerr << L"Minjector - Test Injector Utility" << std::endl;
	std::wcerr << L"Version: " << InjectorCommon::MINJECTOR_VERSION << std::endl << std::endl;

	std::wcerr << L"Available Injection Modes:" << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_CREATE_REMOTE_THREAD << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_CREATE_REMOTE_THREAD) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_CREATE_REMOTE_THREAD_STEALTH << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_CREATE_REMOTE_THREAD_STEALTH) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_QUEUE_USER_APC << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_QUEUE_USER_APC) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_SET_WINDOWS_HOOK << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_SET_WINDOWS_HOOK) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_REFLECTIVE_DLL_INJECTION << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_REFLECTIVE_DLL_INJECTION) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_SHELLCODE_DLL_INJECTION << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_SHELLCODE_DLL_INJECTION) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_PROCESS_HOLLOWING << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_PROCESS_HOLLOWING) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_SUSPEND_INJECTION_RESUME << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_SUSPEND_INJECTION_RESUME) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_IMAGE_MAPPING << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_IMAGE_MAPPING) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_THREAD_REUSE << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_THREAD_REUSE) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_NET_MODULE << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_NET_MODULE) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_PROCESS_DOPPELGANGING << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_PROCESS_DOPPELGANGING) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_POWERLOADER_EX << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_POWERLOADER_EX) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_APPINIT_DLL << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_APPINIT_DLL) << std::endl;
	std::wcerr << L"  " << InjectorCommon::INJ_IFEO_PROCESS_CREATION << L" - " << InjectorCommon::InjectionModeToString(InjectorCommon::INJ_IFEO_PROCESS_CREATION) << std::endl << std::endl;

	std::wcerr << L"Available Options:" << std::endl;
	std::wcerr << L"  -h for help" << std::endl;
	std::wcerr << L"  -m <injector_mode_id_to_use>" << std::endl;
	std::wcerr << L"  -s <source_pid_or_source_process>" << std::endl;
	std::wcerr << L"  -t <target_pid_or_target_process>" << std::endl << std::endl;

	std::wcerr << L"Usage Example: " << std::endl;
	std::wcerr << L"  Classic injection on pid 4524: minjector.exe -m 1 -s c:\\path\\to\\dll\\msimplepayload.dll -t 4524" << std::endl;
	std::wcerr << L"  Process Holllowing injection on notepad.exe: minjector.exe -m 7 -s c:\\path\\to\\payload\\mexepayload.exe -t c:\\windows\\system32\\notepad.exe" << std::endl;
}

int wmain(int argc, wchar_t *argv[])
{
	int ret = 0;
	UINT32 injectionMode = InjectorCommon::DEFAULT_INJECTION_TYPE;
	std::wstring injectionModeName;
	std::wstring fullPathToFileToInject;
	CmdArgsParser inputCmds(argc, argv);

	if (inputCmds.WasOptionRequested(L"-h") ||
		!inputCmds.WasOptionRequested(L"-s") || 
		!inputCmds.WasOptionRequested(L"-t") || 
		!inputCmds.WasOptionRequested(L"-m"))
	{
		std::wcerr << L"[-] Make sure to provide all the required arguments" << std::endl;
		ShowHelp();
		return 1;
	}

	const std::wstring &codeToInject = inputCmds.GetOptionValue(L"-s");
	if (codeToInject.empty() || 
		!InjectorHelpers::IsValidFile(codeToInject) || 
		!InjectorHelpers::GetFullPathToFile(codeToInject, fullPathToFileToInject))
	{
		std::wcerr << L"[-] DLL file to inject cannot be found" << std::endl;
		ShowHelp();
		return 1;
	}

	const std::wstring &targetToInject = inputCmds.GetOptionValue(L"-t");
	if (targetToInject.empty())
	{
		std::wcerr << L"[-] Target PID/Process was not provided" << std::endl;
		ShowHelp();
		return 1;
	}

	const std::wstring &targetMode = inputCmds.GetOptionValue(L"-m");
	if (targetMode.empty())
	{
		std::wcerr << L"[-] Target mode was not provided" << std::endl;
		ShowHelp();
		return 1;
	}
	else
	{
		injectionMode = InjectorHelpers::ToInteger(targetMode);
	}

	//Real work starts here
	InjectorManager manager;
	auto injectCreateRemoteThread = std::make_shared<InjectorCreateRemoteThread>();
	auto injectStealthCreateRemoteThread = std::make_shared<InjectorCreateRemoteStealth>();
	auto injectProcessHollowing = std::make_shared<InjectorProcessHollowing>();
	auto injectQueueUserAPC = std::make_shared<InjectorQueueUserAPC>();
	auto injectReflectiveDLL = std::make_shared<InjectorReflectiveDLL>();
	auto injectShellcodeDLL = std::make_shared<InjectorShellcodeDLL>();
	auto injectSetWindowsHookEx = std::make_shared<InjectorSetWindowsHookEx>();
	auto injectSuspendResume = std::make_shared<InjectorSuspendResume>();
	auto injectImageMapping = std::make_shared<InjectorImageMapping>();
	auto injectThreadReuse = std::make_shared<InjectorThreadReuse>();
	auto injectNetModule = std::make_shared<InjectorNETModule>();
	auto injectProcessDoppelganging = std::make_shared<InjectorProcessDoppelganging>();
	auto injectPowerLoaderEx = std::make_shared<InjectorPowerloaderEx>();
	auto injectAppInitDLL = std::make_shared<InjectorAppInitDLL>();
	auto injectIFEOProcessCreation = std::make_shared<InjectorIFEOProcessCreation>();
		
	manager.AddInjector(injectCreateRemoteThread);
	manager.AddInjector(injectStealthCreateRemoteThread);	
	manager.AddInjector(injectProcessHollowing);
	manager.AddInjector(injectQueueUserAPC);
	manager.AddInjector(injectReflectiveDLL);
	manager.AddInjector(injectShellcodeDLL);
	manager.AddInjector(injectSetWindowsHookEx);
	manager.AddInjector(injectSuspendResume);
	manager.AddInjector(injectImageMapping);
	manager.AddInjector(injectThreadReuse);
	manager.AddInjector(injectNetModule);
	manager.AddInjector(injectProcessDoppelganging);	
	manager.AddInjector(injectPowerLoaderEx);
	manager.AddInjector(injectAppInitDLL);
	manager.AddInjector(injectIFEOProcessCreation);
			
	if (manager.RunInjector((InjectorCommon::InjectionMode)injectionMode, fullPathToFileToInject, targetToInject))
	{
		std::wcout << "[+] Injection was succesfully performed!" << std::endl;
	}
	else
	{
		std::wcout << "[-] There was a problem performing the requested injection: " << 
						InjectorCommon::InjectionModeToString((InjectorCommon::InjectionMode)injectionMode) << 
						std::endl;
	}

    return ret;
}

