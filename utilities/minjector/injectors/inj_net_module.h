#pragma once


#include "../common.h"
#include "../injector.h"

class InjectorNETModule : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorNETModule() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_NET_MODULE),
			InjectorCommon::InjectionMode::INJ_NET_MODULE) {}

private:

};
