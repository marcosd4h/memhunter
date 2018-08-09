#include "../common.h"
#include "inj_image_mapping.h"

bool InjectorImageMapping::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	NTSTATUS err = ERROR_SUCCESS;
	blackbone::Process targetProc;
	blackbone::pe::PEImage sourceModule;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

	auto modCallback = [](blackbone::CallbackType type, void*, blackbone::Process&, const blackbone::ModuleData& modInfo)
	{
		if (type == blackbone::PreCallback)
		{
			if (modInfo.name == L"user32.dll")
				return blackbone::LoadData(blackbone::MT_Native, blackbone::Ldr_Ignore);
		}

		return blackbone::LoadData(blackbone::MT_Default, blackbone::Ldr_Ignore);
	};

	std::wcout << L"[+] Attaching to target process and parsing source mode" << std::endl;
	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetProc))
	{
		std::wcout << L"[+] Checking for valid injection context" << std::endl;
		if (InjectorHelpers::IsValidInjectionTarget(sourceModule, targetProc))
		{
			if (InjectorHelpers::IsValidTargetPID(targetToInject))
			{
				//blackbone::eLoadFlags flags = blackbone::CreateLdrRef | blackbone::WipeHeader | blackbone::NoThreads | blackbone::NoTLS;
				blackbone::eLoadFlags flags = blackbone::CreateLdrRef;

				std::wcout << L"[+] About to perform image mapping of module " << sourceModule.path() << std::endl;
				auto injectedMod = targetProc.mmap().MapImage(sourceModule.path(), flags, modCallback);
				if (injectedMod)
				{
					std::wcout << L"[+] Success! DLL injected via InjectorImageMapping method" << std::endl;
					ret = true;
				}
				else
				{
					std::wcout << L"[-] There was a problem when attempting mapping an image into target process. Failed with status: 0x%x" << std::hex << injectedMod.status << std::endl;
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
