#pragma once

#include "../common.h"
#include "../injector.h"

class InjectorCreateRemoteThread : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorCreateRemoteThread() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_CREATE_REMOTE_THREAD), 
			     InjectorCommon::InjectionMode::INJ_CREATE_REMOTE_THREAD) {}
private:

};