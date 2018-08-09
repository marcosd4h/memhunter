#pragma once

#include "../injector.h"
#include "../common.h"

// ==============================
// Core logic of this injector uses hasherezade's implementation at https://github.com/hasherezade/process_doppelganging
// ==============================

class InjectorProcessDoppelganging : public Injector
{
public:
	bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject);

	InjectorProcessDoppelganging() :
		Injector(InjectorCommon::InjectionModeToString(InjectorCommon::InjectionMode::INJ_PROCESS_DOPPELGANGING),
			InjectorCommon::InjectionMode::INJ_PROCESS_DOPPELGANGING) {}

private:

};
