#include "../common.h"
#include "inj_create_user_thread.h"

bool InjectorCreateUserThread::Execute(const std::wstring codeToInject, const std::wstring targetToInject)
{
	bool ret = false;
	HANDLE  hRemoteThread = NULL;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

	if (!codeToInject.empty() && InjectorHelpers::IsNumber(targetToInject))
	{
		size_t dllPathNameSize = codeToInject.length() * sizeof(wchar_t);
		DWORD targetPID = InjectorHelpers::ToInteger(targetToInject);
		DWORD currentPID = GetCurrentProcessId();

		if ((targetPID > 4) && (targetPID != currentPID))
		{
			// Getting a handle from target process
			HANDLE hProcess = OpenProcess(
				PROCESS_QUERY_INFORMATION |
				PROCESS_CREATE_THREAD |
				PROCESS_VM_OPERATION |
				PROCESS_VM_WRITE,
				FALSE, targetPID);
			if (hProcess != NULL)
			{
				std::wcout << L"[+] Target PID 0x" << std::hex << targetPID << L" was succesfully opened" << std::endl;

				// Get address of LoadLibraryW in Kernel32.dll
				LPVOID LoadLibraryAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
				if (LoadLibraryAddress != NULL)
				{
					std::wcout << L"[+] Address of LoadLibraryW was found at 0x" << std::hex << LoadLibraryAddress << std::endl;

					// Get the real address of RtlCreateUserThread in Kernel32.dll
					pRtlCreateUserThread pfnCreateUserThread = (pRtlCreateUserThread)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlCreateUserThread");
					if (pfnCreateUserThread != NULL)
					{
						std::wcout << L"[+] Address of RtlCreateUserThread was found at 0x" << std::hex << pfnCreateUserThread << std::endl;

						// Allocate space in the remote process for the pathname
						LPVOID lpBaseAddress = (PWSTR)VirtualAllocEx(hProcess,
													NULL,
													dllPathNameSize,
													MEM_COMMIT | MEM_RESERVE,
													PAGE_EXECUTE_READWRITE);
						if (lpBaseAddress != NULL)
						{
							std::wcout << L"[+] " << std::dec << dllPathNameSize << L" bytes of memory were allocated into remote process at address "
								       << std::hex	<< lpBaseAddress << std::endl;


							BOOL bStatus = WriteProcessMemory(hProcess, lpBaseAddress, codeToInject.c_str(), dllPathNameSize, NULL);
							if (bStatus == 0)
							{								
								std::wcout << L"[-] Could not write data into remote process memory at address 0x" << std::hex << lpBaseAddress << std::endl;
							}
							else
							{
								DWORD bStatus = pfnCreateUserThread(
																	hProcess,
																	NULL,
																	0,
																	0,
																	0,
																	0,
																	LoadLibraryAddress,
																	lpBaseAddress,
																	&hRemoteThread,
																	NULL);
								if (bStatus >= 0)
								{
									std::wcout << L"[+] Success! DLL injected via InjectorCreateUserThread method" << std::endl;
									ret = true;
								}
								else
								{
									std::wcout << L"[-] There was a problem calling RtlCreateUserThread() over target process" << std::endl;
								}
							}
						}
						else
						{
							std::wcout << L"[-] There was a problem allocating memory in target process" << std::endl;
						}
					}
					else
					{
						std::wcout << L"[-] There was a problem obtaining address of RtlCreateUserThread function inside kernel32.dll library" << std::endl;
					}
				}
				else
				{
					std::wcout << L"[-] There was a problem obtaining address of LoadLibraryA function inside kernel32.dll library" << std::endl;
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
		std::wcout << L"[-] There was a problem with given arguments" << std::endl;
	}

	return ret;
}
