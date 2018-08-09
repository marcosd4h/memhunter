#pragma once


#include "../common.h"
#include "../injector.h"

class InjectorShellcodeDLL : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorShellcodeDLL() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_SHELLCODE_DLL_INJECTION),
			InjectorCommon::InjectionMode::INJ_SHELLCODE_DLL_INJECTION) {}

private:

};