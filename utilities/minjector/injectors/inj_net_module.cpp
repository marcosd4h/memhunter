#include "../common.h"
#include "inj_net_module.h"

bool InjectorNETModule::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	NTSTATUS err = ERROR_SUCCESS;
	blackbone::Process targetProc;
	blackbone::pe::PEImage sourceModule;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

	std::wcout << L"[+] Attaching to target process and parsing source mode" << std::endl;

	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetProc))
	{
		std::wcout << L"[+] Checking for valid injection context" << std::endl;
		if (InjectorHelpers::IsValidInjectionTarget(sourceModule, targetProc) && (sourceModule.pureIL()))
		{
			if (InjectorHelpers::IsValidTargetPID(targetToInject))
			{
				std::wstring runtimeVersion = blackbone::ImageNET::GetImageRuntimeVer(sourceModule.path().c_str());

				std::wcout << L"[+] If needed the following CLR runtime version will be injected: " << runtimeVersion << std::endl;

				DWORD returnCode = 0;
				bool injectedMod = targetProc.modules().InjectPureIL(
											blackbone::ImageNET::GetImageRuntimeVer(sourceModule.path().c_str()),
											sourceModule.path(),
											L"Startup.EntryPoint",
											L"",
											returnCode);
				if (injectedMod && (returnCode == ERROR_SUCCESS))
				{
					std::wcout << L"[+] Success! DLL injected via InjectorNETModule method" << std::endl;
					ret = true;
				}
				else
				{
					std::wcout << L"[-] There was a problem when attempting reused remote thread for code injection" << std::endl;
				}
			}
			else
			{
				std::wcout << L"[-] There was a problem with target PID" << std::endl;
			}
		}
		else
		{
			std::wcout << L"[-] There was a problem with context. Check if code to inject is a CLR module" << std::endl;
		}
	}
	else
	{
		std::wcout << L"[-] There was a problem setting up injection context data " << std::endl;
	}

	return ret;
}
