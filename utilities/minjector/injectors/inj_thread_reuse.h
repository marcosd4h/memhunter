#pragma once

#include "../common.h"
#include "../injector.h"

class InjectorThreadReuse : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorThreadReuse() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_THREAD_REUSE),
				 InjectorCommon::InjectionMode::INJ_THREAD_REUSE) {}

private:

};