#pragma once


#include "../common.h"
#include "../injector.h"

class InjectorReflectiveDLL : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorReflectiveDLL() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_REFLECTIVE_DLL_INJECTION),
			InjectorCommon::InjectionMode::INJ_REFLECTIVE_DLL_INJECTION) {}

private:

};