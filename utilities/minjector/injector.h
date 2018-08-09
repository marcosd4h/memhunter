#pragma once


#include "customtypes.h"

class Injector
{

public:
	virtual bool Execute(const std::wstring &codeToInject, const std::wstring &targetToInject) = 0;

	const std::wstring GetDescription()
	{
		return m_description;
	}

	const InjectorCommon::InjectionMode GetMode()
	{
		return m_injectorMode;
	}

	Injector(std::wstring description, InjectorCommon::InjectionMode mode) :
		m_description(description), m_injectorMode(mode) {}

	Injector() :
		m_description(L""), m_injectorMode(InjectorCommon::InjectionMode::INJ_NA) {}

private:
	std::wstring m_description;
	InjectorCommon::InjectionMode m_injectorMode;
};

