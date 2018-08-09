#include "injectorManager.h"

bool InjectorManager::RunInjector(const InjectorCommon::InjectionMode mode,
								const std::wstring codeToInject,
								const std::wstring targetToInject)
{
	bool ret = false;

	for (std::vector<std::shared_ptr<Injector>>::const_iterator injectorIt = m_injectors.begin();
		injectorIt != m_injectors.end();
		++injectorIt)
	{
		if (*injectorIt != nullptr)
		{
			std::shared_ptr<Injector> injector = *injectorIt;
			if (injector->GetMode() == mode)
			{
				ret = injector->Execute(codeToInject, targetToInject);
				break;
			}
		}
	}

	return ret;
}