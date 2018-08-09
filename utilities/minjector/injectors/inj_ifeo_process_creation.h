#pragma once

#include "../common.h"
#include "../injector.h"

class InjectorIFEOProcessCreation : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorIFEOProcessCreation() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_IFEO_PROCESS_CREATION),
			InjectorCommon::InjectionMode::INJ_IFEO_PROCESS_CREATION) {}

private:

};