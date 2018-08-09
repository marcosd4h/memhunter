#include "../common.h"
#include "inj_reflective_dll_injection.h"

bool InjectorReflectiveDLL::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	LPVOID lpBuffer = NULL;
	blackbone::Process targetProc;
	blackbone::pe::PEImage sourceModule;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetProc))
	{
		if (InjectorHelpers::IsValidInjectionTarget(sourceModule, targetProc))
		{
			if (InjectorHelpers::IsValidTargetPID(targetToInject))
			{
				size_t dllPathNameSize = codeToInject.length() * sizeof(wchar_t);
				DWORD targetPID = InjectorHelpers::ToInteger(targetToInject);
				DWORD currentPID = GetCurrentProcessId();
				DWORD fileSize = 0;
				HANDLE hModule = NULL;

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

					if (InjectorHelpers::GetFileToInjectSize(codeToInject, fileSize))
					{
						std::wcout << L"[+] About to allocate " << std::dec << fileSize << " bytes of memory for memory DLL " << std::endl;
						lpBuffer = HeapAlloc(GetProcessHeap(), 0, fileSize);
						if (lpBuffer != nullptr)
						{
							DWORD readBytes = 0;
							if (InjectorHelpers::ReadFileToInjectInBuffer(codeToInject, fileSize, lpBuffer, readBytes))
							{
								hModule = InjectorHelpers::LoadRemoteLibraryR(hProcess, lpBuffer, fileSize, NULL);
								if (hModule)
								{
									std::wcout << L"[+] Success! DLL injected via InjectorReflectiveDLL method" << std::endl;
									ret = true;
								}
								else
								{
									std::wcout << L"[-] There was a problem calling LoadRemoteLibraryR() function" << std::endl;
								}
							}
							else
							{
								std::wcout << L"[-] There was a problem reading data from FS DLL into Memory DLL Buffer" << std::endl;
							}
						}
						else
						{
							std::wcout << L"[-] There was a problem allocating data for memory dll " << std::endl;
						}
					}
					else
					{
						std::wcout << L"[-] There was a problem getting file size of " << codeToInject << std::endl;
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
		std::wcout << L"[-] There was a problem setting up injection context data" << std::endl;
	}


	return ret;
}
