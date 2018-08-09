#include "../common.h"
#include "inj_queue_user_apc.h"

bool InjectorQueueUserAPC::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	HANDLE  hRemoteThread = NULL;
	blackbone::Process targetProc;
	blackbone::pe::PEImage sourceModule;

	static const size_t MIN_NUMBER_OF_TARGET_THREADS = 3;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;
	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetProc))
	{
		if (InjectorHelpers::IsValidInjectionTarget(sourceModule, targetProc))
		{
			auto listOfThreads = targetProc.threads().getAll();
			size_t numberOfTargetThreads = listOfThreads.size();
			std::wcout << L"[+] There are " << numberOfTargetThreads << " threads to use in target process" << std::endl;

			if ((numberOfTargetThreads >= MIN_NUMBER_OF_TARGET_THREADS) &&
				(InjectorHelpers::IsValidTargetPID(targetToInject)))
			{
				size_t dllPathNameSize = codeToInject.length() * sizeof(wchar_t);
				DWORD targetPID = InjectorHelpers::ToInteger(targetToInject);
				DWORD currentPID = GetCurrentProcessId();

				// Getting a handle from target process
				HANDLE hProcess = OpenProcess(
					PROCESS_QUERY_INFORMATION |
					//PROCESS_CREATE_THREAD |
					PROCESS_VM_OPERATION |
					PROCESS_VM_WRITE,
					FALSE, targetPID);
				if (hProcess != NULL)
				{
					std::wcout << L"[+] Target PID 0x" << std::hex << targetPID << L" was succesfully opened" << std::endl;

					// Get address of LoadLibraryW in Kernel32.dll
					LPVOID LoadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
					if (LoadLibraryAddress != NULL)
					{
						std::wcout << L"[+] Address of LoadLibraryW was found at 0x" << std::hex << LoadLibraryAddress << std::endl;

						// Allocate space in the remote process for the pathname
						LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(hProcess,
							NULL,
							dllPathNameSize,
							MEM_COMMIT,
							PAGE_READWRITE);
						if (lpBaseAddress != NULL)
						{
							std::wcout << L"[+] " << std::dec << dllPathNameSize << L" bytes of memory were allocated into remote process at address "
								<< std::hex << lpBaseAddress << std::endl;

							std::wcout << L"[+] Now writting code to inject (" << codeToInject.c_str() << L") at address 0x"
								<< std::hex << lpBaseAddress << std::endl;

							BOOL bStatus = WriteProcessMemory(hProcess, lpBaseAddress, codeToInject.c_str(), dllPathNameSize, NULL);
							if (bStatus == 0)
							{
								std::wcout << L"[-] Could not write data into remote process memory at address 0x" << std::hex << lpBaseAddress << std::endl;
							}
							else
							{
								//TODO: Fix this. Use of CreateToolhelp32Snapshot to enumerate threads is not needed anymore 
								// as blackbone is being used now :)
								HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, targetPID);
								if (hSnapshot == INVALID_HANDLE_VALUE)
								{
									std::wcout << L"[-] There was a problem enumerating the threads of process " << std::dec << targetPID << std::endl;
								}
								else
								{
									DWORD threadId = 0;
									THREADENTRY32 threadEntry = { 0 };
									threadEntry.dwSize = sizeof(THREADENTRY32);
									BOOL bResult = Thread32First(hSnapshot, &threadEntry);
									while (bResult)
									{
										bResult = Thread32Next(hSnapshot, &threadEntry);
										if (bResult)
										{
											if (threadEntry.th32OwnerProcessID == targetPID)
											{
												threadId = threadEntry.th32ThreadID;
												HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
												if (hThread == NULL)
												{
													std::wcout << L"[-] There was a problem opening thread " << std::dec << threadId << std::endl;
												}
												else
												{
													std::wcout << L"[+] About to attempt queuing APC to thread " << std::dec << threadId << std::endl;
													DWORD dwResult = QueueUserAPC((PAPCFUNC)LoadLibraryAddress, hThread, (ULONG_PTR)lpBaseAddress);
													if (!dwResult)
													{
														std::wcout << L"[-] There was a problem queuing APC to thread" << std::dec << threadId << std::endl;
													}
													else
													{
														std::wcout << L"[+] Success! APC Queued to thread " << std::dec << threadId << std::endl;
														ret = true;
													}

													CloseHandle(hThread);
												}
											}
										}
									}

									CloseHandle(hSnapshot);
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
				std::wcout << L"[-] An Invalid PID was provided or target does not have an expected number of available threads to target" << std::endl;
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
