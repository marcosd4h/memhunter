#pragma once

#include "../common.h"
#include "../injector.h"

// ==============================
// Core logic of this injector uses Ensilo's reference implementation at
// https://raw.githubusercontent.com/BreakingMalware/PowerLoaderEx/master/PowerLoaderEx.cpp
// ==============================


class InjectorPowerloaderEx : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorPowerloaderEx() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_POWERLOADER_EX),
			     InjectorCommon::InjectionMode::INJ_POWERLOADER_EX) {}
private:

};