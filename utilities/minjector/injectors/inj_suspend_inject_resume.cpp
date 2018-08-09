#include "../common.h"
#include "inj_suspend_inject_resume.h"

bool InjectorSuspendResume::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
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
			DWORD targetPID = InjectorHelpers::ToInteger(targetToInject);
			std::wcout << L"[+] About to inject shellcode into target PID" << targetPID << std::endl;

			if (InjectorHelpers::IsValidTargetPID(targetToInject))
			{
				size_t nameLength = (codeToInject.size() * sizeof(wchar_t));
				size_t bufferLength = nameLength * 2;
				size_t dllPathNameSize = codeToInject.size() * sizeof(wchar_t);
				std::wcout << L"[+] About to allocate memory at target process for shellcode argument" << std::endl;
				auto resultAllocation = targetProc.memory().Allocate(bufferLength, PAGE_READWRITE);
				if (resultAllocation)
				{
					blackbone::ptr_t bufferAddr = (blackbone::ptr_t)resultAllocation->ptr();
					std::wcout << L"[+] Buffer Allocated at 0x" << std::hex << (void *)bufferAddr << std::endl;

					//writting remote shellcode argument
					const std::unique_ptr<uint8_t[]> zeroHeaderBuff(new uint8_t[bufferLength]());
					if ((targetProc.memory().Write(bufferAddr, bufferLength, zeroHeaderBuff.get()) == ERROR_SUCCESS) &&
						(targetProc.memory().Write(bufferAddr, codeToInject.size() * sizeof(wchar_t), codeToInject.c_str()) == ERROR_SUCCESS))
					{
						std::wcout << L"[+] Shellcode argument was written in target process" << std::endl;
						auto& remote = targetProc.remote();
						remote.CreateRPCEnvironment(blackbone::Worker_None, true);

						auto LoadLibraryWPtr = targetProc.modules().GetExport(L"kernel32.dll", "LoadLibraryW");
						//auto GetModuleHandleWPtr = targetProc.modules().GetExport(L"kernel32.dll", "GetModuleHandleW");
						auto asmPtr = blackbone::AsmFactory::GetAssembler();
						std::wcout << L"[+] Acquiring target thread to use" << std::endl;
						auto mainTargetThread = targetProc.threads().getMain();
			
						if (asmPtr && LoadLibraryWPtr && targetProc.valid() && mainTargetThread->valid())
						{
							const DWORD targetTID = mainTargetThread->id();
							std::wcout << L"[+] We will inject into target thread 0x" << std::hex << targetTID << std::endl;

							auto& shellcode = *asmPtr;

							shellcode.GenPrologue();
							shellcode.GenCall(static_cast<uintptr_t>(LoadLibraryWPtr->procAddress), { bufferAddr }, blackbone::cc_stdcall);
							shellcode.GenEpilogue();

							uint64_t result = 0;
							std::wcout << L"[+] About to suspend and resume the thread to redirect execution flow" << std::endl;
							if (remote.ExecInNewThread(shellcode->make(), shellcode->getCodeSize(), result) == ERROR_SUCCESS)
							{
								std::wcout << L"[+] Success! DLL injected via InjectorSuspendResume method" << std::endl;
								ret = true;
							}
							else
							{
								std::wcout << L"[-] There was a problem when executing shellcode on remote process" << std::endl;
							}
						}
						else
						{
							std::wcout << L"[-] There was a problem when attempting creating shellcode" << std::endl;
						}
					}
					else
					{
						std::wcout << L"[-] There was a problem cleaning up the buffer" << std::endl;
					}
				}
				else
				{
					std::wcout << L"[-] There was a problem allocating space for the shellcode argument" << std::endl;
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

