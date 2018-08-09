#pragma once

#include "common.h"
#include "injector.h"
#include "injectors\inj_suspend_inject_resume.h"
#include "injectors\inj_set_windows_hook_ex.h"
#include "injectors\inj_reflective_dll_injection.h"
#include "injectors\inj_queue_user_apc.h"
#include "injectors\inj_process_hollowing.h"
#include "injectors\inj_create_remote_thread.h"
#include "injectors\inj_create_remote_thread_stealth.h"
#include "injectors\inj_shellcode_dll_injection.h"
#include "injectors\inj_image_mapping.h"
#include "injectors\inj_thread_reuse.h"
#include "injectors\inj_net_module.h"
#include "injectors\inj_process_doppelganging.h"
#include "injectors\inj_powerloader_ex.h"
#include "injectors\inj_appinit_dll_injection.h"
#include "injectors\inj_ifeo_process_creation.h"

class InjectorManager
{
public:
	template <typename T>

	void AddInjector(std::shared_ptr<T>& injector)
	{
		m_injectors.push_back(injector);
	}

	bool RunInjector(const InjectorCommon::InjectionMode mode, 
					 const std::wstring codeToInject, 
					 const std::wstring targetToInject);

	InjectorManager::InjectorManager() {}

private:
	std::vector<std::shared_ptr<Injector>> m_injectors;
};
