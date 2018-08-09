#pragma once

#include "../common.h"
#include "../injector.h"

class InjectorAppInitDLL : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorAppInitDLL() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_APPINIT_DLL),
			InjectorCommon::InjectionMode::INJ_APPINIT_DLL) {}

private:

};