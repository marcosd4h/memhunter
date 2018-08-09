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
								if (PostThreadMessage(targetdTID, WM_NULL, NULL, NULL))
								{
									std::wcout << L"[+] Success! now Placing extra remote hooks" << std::endl;
			
									if (targetProc.memory().SetupHook(blackbone::RemoteMemory::MemVirtualAlloc) == ERROR_SUCCESS)
									{
										std::wcout << L"[+] MemVirtualAlloc() remot hook succesfully placed!" << std::endl;
									}

									if (targetProc.memory().SetupHook(blackbone::RemoteMemory::MemVirtualFree) == ERROR_SUCCESS)
									{
										std::wcout << L"[+] MemVirtualFree() remot hook succesfully placed!" << std::endl;
									}

									if (targetProc.memory().SetupHook(blackbone::RemoteMemory::MemMapSection) == ERROR_SUCCESS)
									{
										std::wcout << L"[+] MemMapSection() remot hook succesfully placed!" << std::endl;
									}

									if (targetProc.memory().SetupHook(blackbone::RemoteMemory::MemUnmapSection) == ERROR_SUCCESS)
									{
										std::wcout << L"[+] MemUnmapSection() remot hook succesfully placed!" << std::endl;
									}

									std::wcout << L"[+] Success! DLL injected via InjectorSetWindowsHookEx method" << std::endl;
									ret = true;
								}
								else
								{
									std::wcout << L"[-] There was a problem found while triggering the target hook" << std::endl;
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
