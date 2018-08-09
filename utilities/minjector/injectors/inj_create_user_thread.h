#ifndef _INJECTOR_CREATE_USER_THREAD_H_
#define _INJECTOR_CREATE_USER_THREAD_H_

#include "../common.h"
#include "../injector.h"

class InjectorCreateUserThread : public Injector
{
public:
	bool Execute(const std::wstring codeToInject, const std::wstring targetToInject);

	InjectorCreateUserThread() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_RTL_CREATE_USER_THREAD),
			InjectorCommon::InjectionMode::INJ_RTL_CREATE_USER_THREAD) {}

private:

};

#endif