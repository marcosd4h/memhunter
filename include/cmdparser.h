#pragma once

#include "common.h"

class CmdArgsParser 
{

public:
	CmdArgsParser() {};

	bool Initialize(int argc, wchar_t *argv[])
	{
		bool ret = false;

		for (int i = 1; i < argc; ++i)
		{
			this->m_cmdTokens.push_back(std::wstring(argv[i]));
			ret = true;
		}

		return ret;
	}

	const std::wstring& GetOptionValue(const std::wstring &cmdOption) const
	{
		std::vector<std::wstring>::const_iterator cmdIt;
		cmdIt = std::find(this->m_cmdTokens.begin(), this->m_cmdTokens.end(), cmdOption);

		if (cmdIt != this->m_cmdTokens.end() && ++cmdIt != this->m_cmdTokens.end())
		{
			return *cmdIt;
		}

		static const std::wstring empty(L"");
		return empty;
	}

	bool WasOptionRequested(const std::wstring &cmdOption) const
	{
		return std::find(this->m_cmdTokens.begin(), this->m_cmdTokens.end(), cmdOption) != this->m_cmdTokens.end();
	}

private:
	std::vector <std::wstring> m_cmdTokens;
};
