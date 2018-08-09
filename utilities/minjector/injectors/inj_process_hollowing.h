#pragma once

#include "../common.h"
#include "../injector.h"

class InjectorProcessHollowing : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorProcessHollowing() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_PROCESS_HOLLOWING),
			InjectorCommon::InjectionMode::INJ_PROCESS_HOLLOWING) {}

private:

};