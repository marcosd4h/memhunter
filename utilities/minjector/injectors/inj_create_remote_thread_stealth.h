#pragma once

#include "../common.h"
#include "../injector.h"

class InjectorCreateRemoteStealth : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorCreateRemoteStealth() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_CREATE_REMOTE_THREAD_STEALTH),
			     InjectorCommon::InjectionMode::INJ_CREATE_REMOTE_THREAD_STEALTH) {}
private:

};