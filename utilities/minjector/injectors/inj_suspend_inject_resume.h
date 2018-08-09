#pragma once


#include "../common.h"
#include "../injector.h"

class InjectorSuspendResume : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorSuspendResume() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_SUSPEND_INJECTION_RESUME),
			InjectorCommon::InjectionMode::INJ_SUSPEND_INJECTION_RESUME) {}

private:

};