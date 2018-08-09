#pragma once


#include "../common.h"
#include "../injector.h"

class InjectorSetWindowsHookEx : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorSetWindowsHookEx() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_SET_WINDOWS_HOOK),
			InjectorCommon::InjectionMode::INJ_SET_WINDOWS_HOOK) {}

private:

};