#include "../common.h"
#include "inj_thread_reuse.h"

bool InjectorThreadReuse::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	NTSTATUS err = ERROR_SUCCESS;
	blackbone::Process targetProc;
	blackbone::pe::PEImage sourceModule;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

	std::wcout << L"[+] Attaching to target process and parsing source mode" << std::endl;
	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetProc))
	{
		std::wcout << L"[+] Checking for valid injection context" << std::endl;
		if (InjectorHelpers::IsValidInjectionTarget(sourceModule, targetProc))
		{
			if (InjectorHelpers::IsValidTargetPID(targetToInject))
			{
				std::wcout << L"[+] Getting most executed thread" << sourceModule.path() << std::endl;
				blackbone::ThreadPtr pThread = targetProc.threads().getLeastExecuted();
				if (pThread && pThread->valid())
				{
					std::wcout << L"[+] About to perform thread reuse injection of module " << sourceModule.path() 
						<< " at thread " << pThread->id() << std::endl;
					auto injectedMod = targetProc.modules().Inject(sourceModule.path(), pThread);
					if (injectedMod.success())
					{
						std::wcout << L"[+] Success! DLL injected via InjectorThreadReuse method" << std::endl;
						ret = true;
					}
					else
					{
						std::wcout << L"[-] There was a problem when attempting reused remote thread for code injection. Failed with status: 0x%x" << std::hex << injectedMod.status << std::endl;
					}
				}
				else
				{
					std::wcout << L"[-] There was a problem getting target thread" << std::endl;
				}
			}
			else
			{
				std::wcout << L"[-] There was a problem with target PID" << std::endl;
			}
		}
		else
		{
			std::wcout << L"[-] There was a problem with context" << std::endl;
		}
	}
	else
	{
		std::wcout << L"[-] There was a problem setting up injection context data " << std::endl;
	}

	return ret;
}

