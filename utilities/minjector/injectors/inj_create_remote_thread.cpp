#include "../common.h"
#include "inj_create_remote_thread.h"

bool InjectorCreateRemoteThread::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	blackbone::Process targetProc;
	blackbone::pe::PEImage sourceModule;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

	std::wcout << L"[+] Attaching to target process and parsing source mode" << std::endl;
	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetProc))
	{
		if (InjectorHelpers::IsValidInjectionTarget(sourceModule, targetProc))
		{
			size_t dllPathNameSize = codeToInject.length() * sizeof(wchar_t);

			if (InjectorHelpers::IsValidTargetPID(targetToInject))
			{
				DWORD targetPID = InjectorHelpers::ToInteger(targetToInject);

				// Getting a handle from target process
				HANDLE hProcess = OpenProcess(
					PROCESS_CREATE_THREAD |
					PROCESS_VM_OPERATION |
					PROCESS_VM_WRITE,
					FALSE, 
					targetPID);
				if (hProcess != NULL)
				{
					std::wcout << L"[+] Target PID 0x" << std::hex << targetPID << L" was succesfully opened" << std::endl;

					// Allocate space in the remote process for the pathname
					//LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dllPathNameSize, MEM_COMMIT, PAGE_READWRITE);
					LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dllPathNameSize, MEM_COMMIT, PAGE_READWRITE);
					if (pszLibFileRemote != NULL)
					{
						std::wcout << L"[+] " << std::dec << dllPathNameSize << L" bytes of memory were allocated into remote process at address "
							<< std::hex << pszLibFileRemote << std::endl;

						// Copy the DLL's pathname to the remote process address space
						DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)codeToInject.c_str(), dllPathNameSize, NULL);
						if (n == 0)
						{
							std::wcout << L"[-] Could not write data into remote process memory at address 0x" << std::hex << pszLibFileRemote << std::endl;
						}
						else
						{
							// Get the real address of LoadLibraryW in Kernel32.dll
							PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
							if (pfnThreadRtn != NULL)
							{
								std::wcout << L"[+] Address of LoadLibraryW was found at 0x" << std::hex << pfnThreadRtn << std::endl;

								HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
								if (hThread != NULL)
								{
									std::wcout << L"[+] Success! DLL injected via InjectorCreateRemoteThread method" << std::endl;
									ret = true;
								}
								else
								{
									std::wcout << L"[-] There was a problem creating a remote thread in target process" << std::endl;
								}
							}
							else
							{
								std::wcout << L"[-] There was a problem obtaining address of LoadLibraryA function inside kernel32.dll library" << std::endl;
							}
						}
					}
					else
					{
						std::wcout << L"[-] There was a problem allocating memory in target process" << std::endl;
					}

					CloseHandle(hProcess);
				}
				else
				{
					std::wcout << L"[-] There was a problem opening target PID" << std::endl;
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
