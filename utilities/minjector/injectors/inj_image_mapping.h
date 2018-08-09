#pragma once

#include "../common.h"
#include "../injector.h"

class InjectorImageMapping : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorImageMapping() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_IMAGE_MAPPING),
			InjectorCommon::InjectionMode::INJ_IMAGE_MAPPING) {}

private:

};