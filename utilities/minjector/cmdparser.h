#pragma once

#include <iostream>
#include <string>
#include <vector>

class CmdArgsParser 
{
public:
	CmdArgsParser(int argc, wchar_t *argv[])
	{
		for (int i = 1; i < argc; ++i)
		{
			this->cmdTokens.push_back(std::wstring(argv[i]));
		}

	}

	const std::wstring& GetOptionValue(const std::wstring &cmdOption) const
	{
		std::vector<std::wstring>::const_iterator cmdIt;
		cmdIt = std::find(this->cmdTokens.begin(), this->cmdTokens.end(), cmdOption);
		if (cmdIt != this->cmdTokens.end() && ++cmdIt != this->cmdTokens.end())
		{
			return *cmdIt;
		}
		static const std::wstring empty(L"");
		return empty;
	}

	bool WasOptionRequested(const std::wstring &cmdOption) const
	{
		return 
			std::find(this->cmdTokens.begin(), this->cmdTokens.end(), cmdOption) != this->cmdTokens.end();
	}

private:
	std::vector <std::wstring> cmdTokens;
};

