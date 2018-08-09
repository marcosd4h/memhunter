#pragma once


#include "../common.h"
#include "../injector.h"

class InjectorQueueUserAPC : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorQueueUserAPC() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_QUEUE_USER_APC),
			InjectorCommon::InjectionMode::INJ_QUEUE_USER_APC) {}

private:

};