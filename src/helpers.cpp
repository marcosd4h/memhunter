#include "common.h"


namespace TraceHelpers
{
	void TraceUp(const char *buffer, ...)
	{
		char formattedBuff[CustomDefs::MAX_BUFFER_SIZE] = { 0 };

		va_list varadic;
		va_start(varadic, buffer);
		_vsnprintf_s(formattedBuff, (CustomDefs::MAX_BUFFER_SIZE - 1), CustomDefs::MAX_BUFFER_SIZE, buffer, varadic);
		va_end(varadic);

		std::string outputBuff;
		outputBuff.append(CustomDefs::UPMARK);
		outputBuff.append(CustomDefs::APPNAME);
		outputBuff.append(CustomDefs::SEPARATOR);
		outputBuff.append(formattedBuff);
		outputBuff.append(CustomDefs::ENDLINE);

		OutputDebugStringA(outputBuff.c_str());
	}

	void TraceDown(const char *buffer, ...)
	{
		char formattedBuff[CustomDefs::MAX_BUFFER_SIZE] = { 0 };

		va_list varadic;
		va_start(varadic, buffer);
		_vsnprintf_s(formattedBuff, (CustomDefs::MAX_BUFFER_SIZE - 1), CustomDefs::MAX_BUFFER_SIZE, buffer, varadic);
		va_end(varadic);

		std::string outputBuff;
		outputBuff.append(CustomDefs::DOWNMARK);
		outputBuff.append(CustomDefs::APPNAME);
		outputBuff.append(CustomDefs::SEPARATOR);
		outputBuff.append(formattedBuff);
		outputBuff.append(CustomDefs::ENDLINE);

		OutputDebugStringA(outputBuff.c_str());
	}

	void TraceConsoleUp(const char *buffer, ...)
	{
		char formattedBuff[CustomDefs::MAX_BUFFER_SIZE] = { 0 };

		va_list varadic;
		va_start(varadic, buffer);
		_vsnprintf_s(formattedBuff, (CustomDefs::MAX_BUFFER_SIZE - 1), CustomDefs::MAX_BUFFER_SIZE, buffer, varadic);
		va_end(varadic);

		std::cout << CustomDefs::UPMARK << formattedBuff << CustomDefs::ENDLINE;
	}

	void TraceConsoleDown(const char *buffer, ...)
	{
		char formattedBuff[CustomDefs::MAX_BUFFER_SIZE] = { 0 };

		va_list varadic;
		va_start(varadic, buffer);
		_vsnprintf_s(formattedBuff, (CustomDefs::MAX_BUFFER_SIZE - 1), CustomDefs::MAX_BUFFER_SIZE, buffer, varadic);
		va_end(varadic);

		std::cerr << CustomDefs::DOWNMARK << formattedBuff << CustomDefs::ENDLINE;
	}

	void TraceConsole(const char *buffer, ...)
	{
		char formattedBuff[CustomDefs::MAX_BUFFER_SIZE] = { 0 };

		va_list varadic;
		va_start(varadic, buffer);
		_vsnprintf_s(formattedBuff, (CustomDefs::MAX_BUFFER_SIZE - 1), CustomDefs::MAX_BUFFER_SIZE, buffer, varadic);
		va_end(varadic);

		std::cout << formattedBuff << CustomDefs::ENDLINE;
	}
}



namespace GeneralHelpers
{
	int ToInteger(const std::wstring &str)
	{
		return std::stoi(str);
	}

	bool IsValidFile(const std::wstring &fileName)
	{
		bool ret = false;
		HANDLE hFile = INVALID_HANDLE_VALUE;

		hFile = CreateFile(fileName.c_str(),       // file to open
			GENERIC_READ,          // open for reading
			FILE_SHARE_READ,       // share for reading
			NULL,                  // default security
			OPEN_EXISTING,         // existing file only
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // normal file
			NULL);                 // no attr. template

		if (hFile != INVALID_HANDLE_VALUE)
		{
			ret = true;
			CloseHandle(hFile);
		}

		return ret;
	}

	bool GetFullPathToFile(const std::wstring &fileName, std::wstring &fullPathFile)
	{
		bool ret = true;
		wchar_t ptargetFile[MAX_PATH] = { 0 };

		if (GetFullPathName(fileName.c_str(), MAX_PATH, ptargetFile, NULL) == 0)
		{
			ret = false;
		}
		else
		{
			fullPathFile.assign(ptargetFile);
		}

		return ret;
	}

	bool IsNumber(const std::wstring& str)
	{
		bool ret = false;
		std::wstring::const_iterator it = str.begin();
		while (it != str.end() && iswdigit(*it)) ++it;
		if (!str.empty() && it == str.end())
		{
			ret = true;
		}
		return ret;
	}

	bool GetTargetFileSize(const std::wstring& file, DWORD &size)
	{
		bool ret = false;

		HANDLE hFile = CreateFileW(file.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			size = GetFileSize(hFile, NULL);
			if (size > 0)
			{
				ret = true;
			}

			CloseHandle(hFile);
		}

		return ret;
	}

	bool GetTargetFileIntoBuffer(const std::wstring& file, const DWORD &fileSize, LPVOID lpBuffer, DWORD &bytesRead)
	{
		bool ret = false;

		if (lpBuffer != nullptr)
		{
			HANDLE hFile = CreateFileW(file.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				if (ReadFile(hFile, lpBuffer, fileSize, &bytesRead, NULL) && (bytesRead > 0))
				{
					ret = true;
				}

				CloseHandle(hFile);
			}
		}

		return ret;
	}


	template <typename StringBuffer>
	bool InternalReadBuffer(const std::wstring& fullPathFile, StringBuffer& buffer)
	{
		bool ret = false;

		if (IsValidFile(fullPathFile))
		{
			std::basic_ifstream<typename StringBuffer::value_type> inputFile(fullPathFile, std::ios_base::binary);

			if (inputFile.good())
			{
				StringBuffer workingContent((std::istreambuf_iterator<typename StringBuffer::value_type>(inputFile)), {});

				//buffer.assign((std::istreambuf_iterator<typename StringBuffer::value_type>(inputFile)),
				//			   std::istreambuf_iterator<typename StringBuffer::value_type>());

				if (!workingContent.empty())
				{
					buffer.assign(workingContent);
					//buffer.push_back((StringBuffer::value_type)0);					
					ret = true;
				}
			}

			inputFile.close();
		}

		return ret;
	}


	bool GetTargetFileIntoString(const std::wstring& fullPathFile, std::wstring& buffer)
	{
		return InternalReadBuffer(fullPathFile, buffer);
	}

	bool GetTargetFileIntoString(const std::wstring& fullPathFile, std::string& buffer)
	{
		return InternalReadBuffer(fullPathFile, buffer);
	}

	bool GetBaseFileName(const std::wstring &fullPath, std::wstring &baseName)
	{
		bool ret = false;
		wchar_t sep = '\\';
		std::wstring workingStr(fullPath);
		size_t it = workingStr.rfind(sep, workingStr.length());
		if (it != std::wstring::npos)
		{
			baseName.assign(workingStr.substr(it + 1, workingStr.length() - it));
			ret = true;
		}

		return ret;
	}

	bool GetCurrentProcessModuleFullPath(std::wstring &fullPath)
	{
		bool ret = false;
		DWORD readBytes = 0;
		wchar_t modulePathBuff[MAX_PATH] = { 0 };

		if (GetModuleFileNameEx(GetCurrentProcess(), NULL, modulePathBuff, (sizeof(modulePathBuff) / sizeof(*modulePathBuff))))
		{
			fullPath.assign(modulePathBuff);
			ret = true;
		}

		return ret;
	}

	bool GetCurrentProcessModuleDirectory(std::wstring &fullDirectoryPath)
	{
		bool ret = false;
		std::wstring currentExecPath;

		TCHAR currentDrive[MAX_PATH] = { 0 };
		TCHAR currentDir[MAX_PATH] = { 0 };

		if (GetCurrentProcessModuleFullPath(currentExecPath) && !currentExecPath.empty())
		{
			if ((_tsplitpath_s(currentExecPath.c_str(), currentDrive, MAX_PATH, currentDir, MAX_PATH, NULL, 0, NULL, 0) != 0) &&
				(wcslen(currentDir) > 0))
			{
				fullDirectoryPath.assign(currentDir);
				ret = true;
			}
		}

		return ret;
	}

	bool TerminateProcess(const DWORD &processID, const uint32_t &exitCode)
	{
		bool ret = false;

		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
		if (hProcess != NULL)
		{
			if (::TerminateProcess(hProcess, exitCode))
			{
				ret = true;
			}

			CloseHandle(hProcess);
		}

		return ret;
	}

	template <typename StringBuffer>
	bool InternalStrCompare(StringBuffer& str1, StringBuffer& str2)
	{
		bool ret = false;

		if ((!str1.empty()) && (!str2.empty()) && (str1.compare(str2) == 0))
		{
			ret = true;
		}

		return ret;
	}

	bool StrCompare(const std::wstring& str1, const std::wstring& str2)
	{
		return InternalStrCompare(str1, str2);
	}

	bool StrCompare(const std::string& str1, const std::string& str2)
	{
		return InternalStrCompare(str1, str2);
	}

	bool StrContainsPattern(const std::wstring& str, const std::wstring& pattern)
	{
		bool ret = false;

		if (str.find(pattern) != std::wstring::npos)
		{
			ret = true;
		}

		return ret;
	}

	bool StrContainsPatternInsensitive(const std::wstring& str, const std::wstring& pattern)
	{
		bool ret = false;

		std::wstring test1(str);
		std::wstring test2(pattern);
		StrToLowercase(test1);
		StrToLowercase(test2);

		if (test1.find(test2) != std::wstring::npos)
		{
			ret = true;
		}

		return ret;
	}

	bool StrContainsPattern(const std::string& str, const std::string& pattern)
	{
		bool ret = false;

		if (str.find(pattern) != std::string::npos)
		{
			ret = true;
		}

		return ret;
	}

	bool StrContainsPatternInsensitive(const std::string& str, const std::string& pattern)
	{
		bool ret = false;

		std::string test1(str);
		std::string test2(pattern);
		StrToLowercase(test1);
		StrToLowercase(test2);

		if (test1.find(test2) != std::string::npos)
		{
			ret = true;
		}

		return ret;
	}

	bool IsRunningAs64BitProcess()
	{
#if defined(_WIN64)
		return true;
#else
		bool ret = false;
		BOOL isWow64Process = false;

		if (IsWow64Process(GetCurrentProcess(), &isWow64Process))
		{
			ret = true;
		}

		return ret;
#endif
	}

	bool IsRunningAsAdmin()
	{
		bool ret = false;
		DWORD tokenGroupSize = 0;
		SID adminGroupContainer = { 0 };
		PSID pAdminGroup = &adminGroupContainer;
		BOOL isRunningAsAdmin = false;
		HANDLE hToken = INVALID_HANDLE_VALUE;
		char localBuf[4096] = { 0 };
		PTOKEN_GROUPS pGroupInfo = (PTOKEN_GROUPS)localBuf;

		if (!IsWindows7OrGreater())
		{
			ret = true;
		}
		else
		{
			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
			{
				// Getting group token data sizeof current process
				if ((!GetTokenInformation(hToken, TokenGroups, NULL, tokenGroupSize, &tokenGroupSize)) &&
					(GetLastError() == ERROR_INSUFFICIENT_BUFFER))
				{
					pGroupInfo = (PTOKEN_GROUPS)GlobalAlloc(GPTR, tokenGroupSize);

					if (pGroupInfo &&
						(GetTokenInformation(hToken, TokenGroups, pGroupInfo, tokenGroupSize, &tokenGroupSize)))
					{
						SID_IDENTIFIER_AUTHORITY authNTSID = SECURITY_NT_AUTHORITY;
						if (AllocateAndInitializeSid(&authNTSID, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminGroup))
						{
							if (pAdminGroup && CheckTokenMembership(NULL, pAdminGroup, &isRunningAsAdmin) && isRunningAsAdmin)
							{
								//Now comparing current token group with admin sid
								for (DWORD it = 0; it < pGroupInfo->GroupCount; it++)
								{
									if (EqualSid(pAdminGroup, pGroupInfo->Groups[it].Sid))
									{
										ret = true;
										break;
									}
								}
							}
						}
					}
				}

				if (pAdminGroup)
				{
					FreeSid(pAdminGroup);
					pAdminGroup = NULL;
				}

				if (pGroupInfo)
				{
					GlobalFree(pGroupInfo);
					pGroupInfo = NULL;
				}
			}
		}

		return ret;
	}

	bool GetSystemArchitecture(DWORD &arch)
	{
		bool ret = false;
		static SYSTEM_INFO systemInfo = { 0 };

		if (systemInfo.dwPageSize = 0)
		{
			GetNativeSystemInfo(&systemInfo);
			arch = systemInfo.wProcessorArchitecture;
			ret = true;
		}
		else
		{
			arch = systemInfo.wProcessorArchitecture;
			ret = true;
		}

		return ret;
	}

	bool GetProcessBitness(const HANDLE &hProcess, CustomTypes::ProcessType &processType)
	{
		bool ret = false;
		DWORD arch = 0;
		static CustomWinTypes::PFN_ISWOW64PROCESS IsWow64Process = NULL;
		HMODULE kernel32 = NULL;
		BOOL resultWow64Process = false;

		if ((hProcess != INVALID_HANDLE_VALUE) && GetSystemArchitecture(arch))
		{
			processType = CustomTypes::ProcessType::PROCESS_UNKNOWN;

			if (arch == PROCESSOR_ARCHITECTURE_INTEL)
			{
				processType = CustomTypes::ProcessType::PROCESS_32_BITS;
				ret = true;
			}
			else if (arch == PROCESSOR_ARCHITECTURE_AMD64)
			{
				//lazy siglenton
				if (IsWow64Process == NULL)
				{
					if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"kernel32.dll", &kernel32))
					{
						IsWow64Process = (CustomWinTypes::PFN_ISWOW64PROCESS)GetProcAddress(kernel32, "IsWow64Process");
					}
				}

				//IsWow64Process is not present, assuming 32 bits system
				if (IsWow64Process == NULL)
				{
					processType = CustomTypes::ProcessType::PROCESS_32_BITS;
					ret = true;
				}
				else
				{
					if (IsWow64Process(hProcess, &resultWow64Process))
					{
						if (resultWow64Process)
						{
							processType = CustomTypes::ProcessType::PROCESS_WOW_32_BITS;
						}
						else
						{
							processType = CustomTypes::ProcessType::PROCESS_64_BITS;
						}
						ret = true;
					}
				}

			}
		}

		return ret;
	}

	/******************************************************************************
	* This function adjusts the process token.
	* Source: http://cboard.cprogramming.com/c-programming/108648-help-readprocessmemory-function.html#post802074
	* Another good resource: http://winterdom.com/dev/security/tokens
	******************************************************************************/
	bool EnableTokenPrivilege(LPTSTR pPrivilege)
	{
		bool ret = false;
		HANDLE hToken;
		TOKEN_PRIVILEGES token_privileges;
		DWORD dwSize;
		ZeroMemory(&token_privileges, sizeof(token_privileges));
		token_privileges.PrivilegeCount = 1;

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
		{
			if (LookupPrivilegeValue(NULL, pPrivilege, &token_privileges.Privileges[0].Luid))
			{
				token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
				if (AdjustTokenPrivileges(hToken, FALSE, &token_privileges, 0, NULL, &dwSize))
				{
					ret = true;
				}
			}

			CloseHandle(hToken);
		}

		return TRUE;
	}

	bool IsProcessStillRunning(const HANDLE &hProcess)
	{
		bool ret = false;

		DWORD retExitCode;
		if ((GetExitCodeProcess(hProcess, &retExitCode)) && (retExitCode == STILL_ACTIVE))
		{
			ret = true;
		}

		return ret;
	}

	bool IsThreadStillRunning(const HANDLE &hThread)
	{
		bool ret = false;

		DWORD retExitCode;
		if ((GetExitCodeThread(hThread, &retExitCode)) && (retExitCode == STILL_ACTIVE))
		{
			ret = true;
		}

		return ret;
	}

	bool IsDotNETLib(const std::wstring &name)
	{
		bool ret = false;

		if ((StrContainsPatternInsensitive(name, L"clr.dll")) ||
			(StrContainsPatternInsensitive(name, L"mscorwks.dll")) ||
			(StrContainsPatternInsensitive(name, L"coreclr.dll")))
		{
			ret = true;
		}

		return ret;
	}

	bool GetWindowsSystemDirectory(std::wstring &system32Directory)
	{
		bool ret = false;
		TCHAR windir[MAX_PATH] = { 0 };

		system32Directory.clear();
		if (GetWindowsDirectory(windir, MAX_PATH))
		{
			system32Directory.assign(windir);
			system32Directory.append(L"\\SYSTEM32\\");
			ret = true;
		}
		
		return ret;
	}


	bool GetVectorByToken(const std::string& input, const char token, std::vector<std::string> &vector)
	{
		bool ret = false;
		std::stringstream str(input);
		std::string	line;

		vector.clear();

		while (std::getline(str, line, token))
		{
			vector.push_back(line);
		}

		if (!vector.empty())
		{
			ret = true;
		}

		return ret;
	}

	
	bool GetVectorByToken(const std::wstring& input, const wchar_t token, std::vector<std::wstring> &vector)
	{
		bool ret = false;
		std::wstringstream str(input);
		std::wstring line;

		vector.clear();

		while (std::getline(str, line, token))
		{
			vector.push_back(line);
		}

		if (!vector.empty())
		{
			ret = true;
		}

		return ret;
	}

	bool IsElementPresentOnList(const std::vector<std::wstring> &listToCheck, const std::wstring &element)
	{
		bool ret = false;

		if ((listToCheck.size() > 0) && (element.empty()))
		{
			for (auto it = listToCheck.begin(); it != listToCheck.end(); ++it)
			{
				const std::wstring &elementToCompare(*it);

				if ((!elementToCompare.empty()) && (elementToCompare.compare(element) == 0))
				{
					ret = true;
					break;
				}
			}
		}

		return ret;
	}


	template <typename StringBuffer>
	void InternalTrimSpaces(StringBuffer& buffer)
	{
		buffer.erase(remove_if(buffer.begin(), buffer.end(), isspace), buffer.end());
	}

	bool TrimSpaces(std::string &str)
	{
		bool ret = false;

		if (!str.empty())
		{
			InternalTrimSpaces(str);
			ret = true;
		}

		return ret;
	}

	bool TrimSpaces(std::wstring &str)
	{
		bool ret = false;

		if (!str.empty())
		{
			InternalTrimSpaces(str);
			ret = true;
		}

		return ret;
	}

	std::wstring GetBaseFileName(const std::wstring &fullPath)
	{
		std::wstring ret;

		if (!GetBaseFileName(fullPath, ret))
		{
			ret.clear();
		}
		return ret;
	}

	std::wstring ToWstring(const unsigned int &value)
	{
		std::wostringstream ss;
		ss << value;
		return ss.str();
	}

	std::wstring ReplaceTokensInStr(const std::wstring &str, const std::wstring &from, const std::wstring &to)
	{
		std::wstring ret(str);

		size_t start_pos = 0;
		while ((start_pos = ret.find(from, start_pos)) != std::wstring::npos)
		{
			ret.replace(start_pos, from.length(), to);
			start_pos += to.length();
		}

		return ret;
	}

	std::wstring SanitizeStr(const std::wstring &str)
	{
		std::wstring ret;

		ret = ReplaceTokensInStr(str, L"\\", L"\\\\");

		return ret;
	}

	std::wstring StrToWStr(const std::string& str)
	{
		size_t strCount = str.length();
		int bytesToAllocate = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int) strCount, NULL, 0);

		std::wstring ret(bytesToAllocate, 0);
		int wideCharsCount = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int) strCount, &ret[0], bytesToAllocate);

		//TODO: add check for wideCharsCount == strCount
		return ret;
	}

	std::wstring GetHexString(PVOID addr)
	{
		std::wstring ret;
		std::wstringstream formatter;
		if (addr != NULL)
		{
			formatter << L"0x";
			formatter << std::hex << addr;
			ret.assign(formatter.str());
		}

		return ret;
	}

	std::wstring GetMemoryRegionType(DWORD id)
	{
		std::wstring ret;

		switch (id)
		{
		case SEC_COMMIT:
			ret.assign(L"SEC_COMMIT");
			break;
		case MEM_MAPPED:
			ret.assign(L"MEM_MAPPED");
			break;
		case SEC_FILE:
			ret.assign(L"SEC_FILE");
			break;
		case MEM_IMAGE:
			ret.assign(L"MEM_IMAGE");
			break;
		case MEM_PRIVATE:
			ret.assign(L"MEM_PRIVATE");
			break;
		default:
			break;
		}

		return ret;
	}

	std::wstring GetMemoryRegionState(DWORD id)
	{
		std::wstring ret;

		switch (id)
		{
		case MEM_COMMIT:
			ret.assign(L"MEM_COMMIT");
			break;
		case MEM_FREE:
			ret.assign(L"MEM_FREE");
			break;
		case MEM_RESERVE:
			ret.assign(L"MEM_RESERVE");
			break;
		default:
			break;
		}

		return ret;
	}

	std::wstring GetMemoryRegionProtection(DWORD id)
	{
		std::wstring ret;

		switch (id)
		{
		case PAGE_NOACCESS:
			ret.assign(L"PAGE_NOACCESS");
			break;
		case PAGE_READONLY:
			ret.assign(L"PAGE_READONLY");
			break;
		case PAGE_READWRITE:
			ret.assign(L"PAGE_READWRITE");
			break;
		case PAGE_WRITECOPY:
			ret.assign(L"PAGE_WRITECOPY");
			break;
		case PAGE_EXECUTE:
			ret.assign(L"PAGE_EXECUTE");
			break;
		case PAGE_EXECUTE_READ:
			ret.assign(L"PAGE_EXECUTE_READ");
			break;
		case PAGE_EXECUTE_READWRITE:
			ret.assign(L"PAGE_EXECUTE_READWRITE");
			break;
		case PAGE_EXECUTE_WRITECOPY:
			ret.assign(L"PAGE_EXECUTE_WRITECOPY");
			break;
		case PAGE_GUARD:
			ret.assign(L"PAGE_GUARD");
			break;
		case PAGE_NOCACHE:
			ret.assign(L"PAGE_NOCACHE");
			break;
		case PAGE_WRITECOMBINE:
			ret.assign(L"PAGE_WRITECOMBINE");
			break;
		default:
			break;
		}

		return ret;
	}

	std::string WStrToStr(const std::wstring& wstr)
	{
		size_t strCount = wstr.length();
		int bytesToAllocate = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)strCount, NULL, 0, NULL, NULL);

		std::string ret(bytesToAllocate, 0);
		int w = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int) strCount, &ret[0], bytesToAllocate, NULL, NULL);

		//TODO: add check for wideCharsCount == strCount
		return ret;
	}


	std::string GetErrorText(NTSTATUS code)
	{
		std::string ret;
		LPSTR lpStr = nullptr;

		if (FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_FROM_HMODULE |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			GetModuleHandleA("ntdll.dll"),
			code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPSTR)&lpStr, 0, NULL) != 0)
		{
			ret.assign(lpStr);
			LocalFree(lpStr);
		}

		return ret;
	}

	void StrAddDelimitator(const wchar_t delim, std::wstring &str)
	{
		if (str.length() > 0)
		{
			wchar_t lastCharacter = *(str.rbegin());
			if (delim != lastCharacter)
			{
				str.push_back(delim);
			}
		}
	}

	void StrTrim(std::wstring &str)
	{
		str.erase(remove_if(str.begin(), str.end(), isspace), str.end());
	}


	void StrToUppercase(std::wstring &str)
	{
		std::transform(str.begin(), str.end(), str.begin(), ::towupper);
	}

	void StrToUppercase(std::string &str)
	{
		std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::toupper(c); });
	}

	void StrToLowercase(std::wstring &str)
	{
		std::transform(str.begin(), str.end(), str.begin(), ::towlower);
	}

	void StrToLowercase(std::string &str)
	{
		std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); });
	}

	const std::time_t GetEpochTimestamp()
	{
		std::time_t result = std::time(nullptr);
		return result;
	}
}


namespace RegistryHelpers
{
	bool OpenKey(const HKEY &hRootKey, const std::wstring &regSubKey, HKEY &hKey)
	{
		bool ret = false;

		if ((!regSubKey.empty()) && (hRootKey != NULL))
		{
			LSTATUS retCode = RegOpenKeyEx(hRootKey, regSubKey.c_str(), NULL, KEY_ALL_ACCESS, &hKey);
			if (retCode == ERROR_SUCCESS)
			{
				ret = true;
			}
			else if ((retCode == ERROR_FILE_NOT_FOUND) || (retCode == ERROR_PATH_NOT_FOUND))
			{
				if ((RegCreateKeyEx(hRootKey, regSubKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL)) == ERROR_SUCCESS)
				{
					ret = true;
				}
			}
		}

		return ret;
	}

	bool CloseKey(const HKEY &hKey)
	{
		bool ret = false;

		LSTATUS retCode = RegCloseKey(hKey);
		if (retCode == ERROR_SUCCESS)
		{
			ret = true;
		}

		return ret;
	}

	bool DeleteKey(const HKEY &hRootKey, const std::wstring &regSubKey)
	{
		bool ret = false;
		HKEY hKey = NULL;

		if ((!regSubKey.empty()) && (hRootKey != NULL) && OpenKey(hRootKey, regSubKey, hKey))
		{
			LSTATUS retCode = RegDeleteKey(hRootKey, regSubKey.c_str());
			if ((retCode == ERROR_SUCCESS) && (CloseKey(hKey)))
			{
				ret = true;
			}

		}

		return ret;
	}

	bool RegistryKeyExists(const HKEY &hRootKey, const std::wstring &regSubKey)
	{
		bool ret = false;

		if ((!regSubKey.empty()) && (hRootKey != NULL))
		{
			HKEY hKey = NULL;
			LSTATUS retCode = RegOpenKeyEx(hRootKey, regSubKey.c_str(), NULL, KEY_READ | KEY_WOW64_64KEY, &hKey);
			if ((retCode == ERROR_SUCCESS) && (CloseKey(hKey)))
			{
				ret = true;
			}
		}

		return ret;
	}

	bool RegistryValueExists(const HKEY &hRootKey, const std::wstring &regSubKey, const std::wstring& regValue)
	{
		bool ret = false;

		if ((!regSubKey.empty()) && (hRootKey != NULL))
		{
			HKEY hKey = NULL;
			LSTATUS retCodeKey = RegOpenKeyEx(hRootKey, regSubKey.c_str(), NULL, KEY_READ | KEY_WOW64_64KEY, &hKey);
			if (retCodeKey == ERROR_SUCCESS)
			{
				DWORD dwType;
				LSTATUS retCodeValue = RegQueryValueEx(hKey, regValue.c_str(), NULL, &dwType, NULL, NULL);
				if ((retCodeValue == ERROR_SUCCESS) && (CloseKey(hKey)))
				{
					ret = true;
				}
			}
		}

		return ret;
	}

	bool GetRegStringValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, std::wstring &regContent)
	{
		bool ret = false;

		HKEY hKey = NULL;
		if (!regSubKey.empty() && !regValue.empty() && (hRootKey != NULL) && OpenKey(hRootKey, regSubKey, hKey))
		{
			regContent.clear();
			WCHAR szBuffer[MAX_PATH] = { 0 };
			DWORD dwBufferSize = sizeof(szBuffer);

			if (RegGetValueW(
				hKey,
				NULL,
				regValue.c_str(),
				RRF_RT_REG_SZ,
				NULL,
				szBuffer,
				&dwBufferSize) == ERROR_SUCCESS)
			{
				regContent.assign(szBuffer);
				ret = true;
			}

			RegCloseKey(hKey);
		}

		return ret;
	}


	bool SetRegStringValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const std::wstring &regContent)
	{
		bool ret = false;

		HKEY hKey = NULL;
		if (!regSubKey.empty() && !regValue.empty() && (hRootKey != NULL) && OpenKey(hRootKey, regSubKey, hKey))
		{
			if (RegSetValueExW(hKey, regValue.c_str(), 0, REG_SZ, ((const BYTE*)regContent.c_str()), (DWORD)((regContent.length() * sizeof(TCHAR)) + 1)) == ERROR_SUCCESS)
			{
				ret = true;
			}

			RegCloseKey(hKey);
		}

		return ret;
	}

	bool GetRegDWORDValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, DWORD &nValue)
	{
		bool ret = false;

		HKEY hKey = NULL;
		if (!regSubKey.empty() && !regValue.empty() && (hRootKey != NULL) && OpenKey(hRootKey, regSubKey, hKey))
		{
			nValue = 0;
			DWORD dwBufferSize = sizeof(DWORD);
			DWORD nResult = 0;
			LONG nError = ::RegQueryValueExW(hKey,
				regValue.c_str(),
				0,
				NULL,
				reinterpret_cast<LPBYTE>(&nResult),
				&dwBufferSize);

			if (ERROR_SUCCESS == nError)
			{
				nValue = nResult;
				ret = true;
			}

			RegCloseKey(hKey);
		}

		return ret;
	}


	bool SetRegDWORDValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const DWORD &nValue)
	{
		bool ret = false;

		HKEY hKey = NULL;
		if (!regSubKey.empty() && !regValue.empty() && (hRootKey != NULL) && OpenKey(hRootKey, regSubKey, hKey))
		{
			if (RegSetValueExW(hKey, regValue.c_str(), 0, REG_DWORD, ((const BYTE*)&nValue), sizeof(nValue)) == ERROR_SUCCESS)
			{
				ret = true;
			}

			RegCloseKey(hKey);
		}

		return ret;
	}

	bool GetRegBoolValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, bool &nValue)
	{
		bool ret = false;

		HKEY hKey = NULL;
		if (!regSubKey.empty() && !regValue.empty() && (hRootKey != NULL) && OpenKey(hRootKey, regSubKey, hKey))
		{
			nValue = false;
			DWORD dwBufferSize = sizeof(DWORD);
			DWORD nResult = 0;
			LONG nError = ::RegQueryValueExW(hKey,
				regValue.c_str(),
				0,
				NULL,
				reinterpret_cast<LPBYTE>(&nResult),
				&dwBufferSize);

			if (ERROR_SUCCESS == nError)
			{
				nValue = nResult;
				ret = true;
			}
		}

		return ret;
	}


	bool SetRegBoolValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const bool &nValue)
	{
		bool ret = false;

		HKEY hKey = NULL;
		if (!regSubKey.empty() && !regValue.empty() && (hRootKey != NULL) && OpenKey(hRootKey, regSubKey, hKey))
		{
			DWORD workingValue = 0;

			if (nValue) workingValue = 1;

			if (RegSetValueExW(hKey, regValue.c_str(), 0, REG_DWORD, ((const BYTE*)&workingValue), sizeof(workingValue)) == ERROR_SUCCESS)
			{
				ret = true;
			}

			RegCloseKey(hKey);
		}

		return ret;
	}
}


namespace ServiceHelpers
{
	bool WaitForState(const SC_HANDLE& hService, const DWORD finalState, const DWORD pendingState)
	{
		bool ret = false;
		SERVICE_STATUS_PROCESS status = { 0 };
		DWORD readBytes;

		if (QueryServiceStatusEx(
			hService,
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&status,
			sizeof(SERVICE_STATUS_PROCESS),
			&readBytes))
		{
			if (status.dwCurrentState != finalState)
			{
				DWORD startTime = GetTickCount();
				DWORD waitTime = status.dwWaitHint / 10;

				//Waiting state recommended by MS
				if (waitTime < 1000)
				{
					waitTime = 1000;
				}
				else if (waitTime > 10000)
				{
					waitTime = 10000;
				}

				while (status.dwCurrentState == pendingState)
				{
					Sleep(waitTime);

					if (QueryServiceStatusEx(
						hService,
						SC_STATUS_PROCESS_INFO,
						(LPBYTE)&status,
						sizeof(SERVICE_STATUS_PROCESS),
						&readBytes))
					{
						if (status.dwCurrentState == finalState)
						{
							ret = true;
						}
					}
				}
			}
		}

		return ret;
	}

	bool RegisterService(const std::wstring &serviceExecutable, const std::wstring &serviceCmdArgs, const std::wstring &serviceName, const std::wstring &serviceDisplay)
	{
		bool ret = false;

		SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (hSCM)
		{
			std::wstring fullExecutableLocationPlusArgs;
			//fullExecutableLocationPlusArgs.assign(L"\"");
			fullExecutableLocationPlusArgs.assign(serviceExecutable);
			fullExecutableLocationPlusArgs.append(L" ");
			fullExecutableLocationPlusArgs.append(serviceCmdArgs);
			//fullExecutableLocationPlusArgs.append(L"\"");

			SC_HANDLE hService = CreateService(hSCM,
				serviceName.c_str(),					// Name of service
				serviceDisplay.c_str(),					// Name to display
				SERVICE_ALL_ACCESS,						// Desired access
				SERVICE_WIN32_OWN_PROCESS,				// Service type
				SERVICE_AUTO_START,						// Service start type
				SERVICE_ERROR_NORMAL,					// Error control type
				fullExecutableLocationPlusArgs.c_str(),	// Service's binary location
				NULL,                           // No load ordering group
				NULL,                           // No tag identifier
				NULL,							// Dependencies
				NULL,							// Service running account
				NULL							// Password of the account
			);

			if (hService != NULL )
			{
				SERVICE_DESCRIPTION sd = { 0 };
				sd.lpDescription = (wchar_t *)serviceDisplay.c_str();
				if (ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &sd))
				{
					ret = true;
				}

				CloseServiceHandle(hService);
			}

			CloseServiceHandle(hSCM);
			hSCM = NULL;
		}

		return ret;
	}

	bool IsSameServiceExecutablePath(const std::wstring &serviceName, const std::wstring &fullServiceExecPath)
	{
		bool ret = false;
		DWORD bytesNeeded = 0;
		DWORD buffSize = 0;
		LPQUERY_SERVICE_CONFIG lpsc = { 0 };

		SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (hSCM)
		{
			SC_HANDLE hService = OpenService(hSCM, serviceName.c_str(), SERVICE_QUERY_CONFIG);
			if (hService)
			{
				// Get the configuration information and prepare buffer first
				if (!QueryServiceConfig(hService, NULL, 0, &bytesNeeded))
				{
					DWORD lastRrror = GetLastError();
					if (ERROR_INSUFFICIENT_BUFFER == lastRrror)
					{
						buffSize = bytesNeeded;
						lpsc = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, buffSize);

						if (QueryServiceConfig(hService, lpsc, buffSize, &bytesNeeded))
						{
							std::wstring registeredServiceFullPath(lpsc->lpBinaryPathName);

							//TODO: This can be improved to perform absolut match
							if (GeneralHelpers::StrContainsPattern(registeredServiceFullPath, fullServiceExecPath))
							{
								ret = true;
							}

						}

						if (lpsc)
						{
							LocalFree(lpsc);
						}
					}
				}

				CloseServiceHandle(hService);
				hService = NULL;
			}

			CloseServiceHandle(hSCM);
			hSCM = NULL;
		}

		return ret;
	}

	bool DeleteService(const std::wstring &serviceName)
	{
		bool ret = false;

		StopTargetService(serviceName);

		SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (hSCM)
		{
			SC_HANDLE hService = OpenService(hSCM, serviceName.c_str(), DELETE);
			if (hService)
			{				
				if (DeleteService(hService))
				{
					ret = true;
				}

				CloseServiceHandle(hService);
				hService = NULL;
			}

			CloseServiceHandle(hSCM);
			hSCM = NULL;
		}

		return ret;
	}

	bool IsServiceCreated(const std::wstring& serviceName)
	{
		bool ret = false;

		SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (hSCM)
		{
			SC_HANDLE hService = OpenService(hSCM, serviceName.c_str(), (SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
			if (hService)
			{
				CloseServiceHandle(hService);
				hService = NULL;
				ret = true;
			}

			CloseServiceHandle(hSCM);
			hSCM = NULL;
		}

		return ret;
	}


	bool IsServiceStopped(const std::wstring& serviceName)
	{
		bool ret = false;
		SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (hSCM)
		{
			SC_HANDLE hService = OpenService(hSCM, serviceName.c_str(), (SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
			if (hService)
			{
				SERVICE_STATUS status = { 0 };
				if (QueryServiceStatus(hService, &status))
				{
					if ((status.dwCurrentState == SERVICE_STOP_PENDING) || (status.dwCurrentState == SERVICE_STOPPED))
					{
						if (SERVICE_STOP_PENDING == status.dwCurrentState)
						{
							WaitForState(hService, SERVICE_STOPPED, SERVICE_STOP_PENDING);
						}
						ret = true;
					}
				}

				CloseServiceHandle(hService);
				hService = NULL;
			}

			CloseServiceHandle(hSCM);
			hSCM = NULL;
		}

		return ret;
	}


	bool IsServiceStarted(const std::wstring& serviceName)
	{
		bool ret = false;
		SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (hSCM)
		{
			SC_HANDLE hService = OpenService(hSCM, serviceName.c_str(), (SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
			if (hService)
			{
				SERVICE_STATUS status = { 0 };
				if (QueryServiceStatus(hService, &status))
				{
					if ((status.dwCurrentState == SERVICE_START_PENDING) || (status.dwCurrentState == SERVICE_RUNNING))
					{
						if (SERVICE_START_PENDING == status.dwCurrentState)
						{
							WaitForState(hService, SERVICE_RUNNING, SERVICE_START_PENDING);
						}
						ret = true;
					}
				}

				CloseServiceHandle(hService);
				hService = NULL;
			}

			CloseServiceHandle(hSCM);
			hSCM = NULL;
		}

		return ret;
	}


	bool StartTargetService(const std::wstring& serviceName)
	{
		bool ret = false;

		if (IsServiceStarted(serviceName))
		{
			ret = true;
		}
		else
		{
			//waiting for any pending operation
			IsServiceStopped(serviceName);

			SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
			if (hSCM)
			{
				SC_HANDLE hService = OpenService(hSCM, serviceName.c_str(), (SERVICE_START | SERVICE_ENUMERATE_DEPENDENTS));
				if (hService)
				{
					// Attempt to start the service
					if (::StartService(hService, 0, NULL))
					{
						WaitForState(hService, SERVICE_RUNNING, SERVICE_START_PENDING);
						ret = true;
					}

					CloseServiceHandle(hService);
					hService = NULL;
				}

				CloseServiceHandle(hSCM);
				hSCM = NULL;
			}
		}

		return ret;
	}


	bool StopTargetService(const std::wstring& serviceName)
	{
		bool ret = false;

		if (IsServiceStopped(serviceName))
		{
			ret = true;
		}
		else
		{
			//waiting for any pending operation
			IsServiceStarted(serviceName);

			SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
			if (hSCM)
			{
				SC_HANDLE hService = OpenService(hSCM, serviceName.c_str(), (SERVICE_STOP | SERVICE_ENUMERATE_DEPENDENTS));
				if (hService)
				{
					SERVICE_STATUS_PROCESS status;
					if (ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&status))
					{
						WaitForState(hService, SERVICE_STOPPED, SERVICE_STOP_PENDING);
						ret = true;
					}

					CloseServiceHandle(hService);
					hService = NULL;
				}

				CloseServiceHandle(hSCM);
				hSCM = NULL;
			}
		}

		return ret;
	}
}


namespace HunterHelpers
{
	bool IsPIDInCollection(HunterCommon::ProcessCollection &sysProcessesData, const DWORD &pid, HunterCommon::ProcessCollection::iterator &it)
	{
		bool ret = false;
		it = sysProcessesData.find(pid);
		if (it != sysProcessesData.end())
		{
			ret = true;
		}
		return ret;
	}

	bool GetSystemProcessesData(HunterCommon::ProcessCollection &sysProcessesData)
	{
		bool ret = false;
		HANDLE hSystemSnap = INVALID_HANDLE_VALUE;
		DWORD currentProcessID = GetCurrentProcessId();

		//Clearing container first
		CleanupSystemProcessData(sysProcessesData);

		// Take a snapshot of entire system
		hSystemSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSystemSnap != INVALID_HANDLE_VALUE)
		{
			THREADENTRY32 te32 = { 0 };
			te32.dwSize = sizeof(THREADENTRY32);
			for (BOOL threadSuccess = Thread32First(hSystemSnap, &te32);
				threadSuccess != FALSE;
				threadSuccess = Thread32Next(hSystemSnap, &te32))
			{
				//Skipping critical and current processes
				if ((te32.th32OwnerProcessID > 4) &&
					(te32.th32OwnerProcessID != currentProcessID))
				{
					HunterCommon::ProcessCollection::iterator it;
					if (IsPIDInCollection(sysProcessesData, te32.th32OwnerProcessID, it))
					{
						it->second->threads.push_back(te32);
					}
					else
					{
						//Only initializing process once
						HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, te32.th32OwnerProcessID);
						if (hProcess != NULL)
						{
							wchar_t processNameBuff[MAX_PATH] = { 0 };
							std::wstring processFullPathName;

							//if (GetModuleBaseName( hProcess, 0, processNameBuff, MAX_PATH))
							if (GetModuleFileNameEx(hProcess, 0, processNameBuff, MAX_PATH))
							{
								processFullPathName.assign(processNameBuff);

								std::wstring baseProcessName;
								if (GeneralHelpers::GetBaseFileName(processFullPathName, baseProcessName) &&
									ConfigManager::GetInstance().IsProcessExcluded(baseProcessName))
								{
									//Should skip this entry has it has been flagged for exclusion
									continue;
								}
							}
	
							CustomTypes::ProcessType type = CustomTypes::ProcessType::PROCESS_UNKNOWN;
							GeneralHelpers::GetProcessBitness(hProcess, type);

							auto processData = std::make_shared<HunterCommon::ProcessData>(hProcess, te32.th32OwnerProcessID, processFullPathName, type);

							processData->threads.push_back(te32);

							//Getting modules for the process							
							HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, te32.th32OwnerProcessID);
							if (hModuleSnap != INVALID_HANDLE_VALUE)
							{
								MODULEENTRY32 me32 = { 0 };
								//  Set the size of the structure before using it. 
								me32.dwSize = sizeof(MODULEENTRY32);
								for (BOOL moduleSuccess = Module32First(hModuleSnap, &me32);
									moduleSuccess != FALSE;
									moduleSuccess = Module32Next(hModuleSnap, &me32))
								{
									processData->modules.push_back(me32);

									/*
									if (!processData->isManaged && GeneralHelpers::IsDotNETLib(me32.szModule))
									{
										processData->isManaged = true;
									}
									*/
								}

								CloseHandle(hModuleSnap);
							}

							//Initializing blackbone over process
							if ((!processData->bbProcess.valid()) && (NT_SUCCESS(processData->bbProcess.Attach(te32.th32OwnerProcessID))))
							{
								processData->bbProcessReady = true;

								//if (!processData->bbProcess.barrier().mismatch)
								if (processData->bbProcess.valid())
								{
									processData->bbMainModule = processData->bbProcess.modules().GetMainModule();
									if ((processData->bbMainModule != nullptr) &&
										(!processData->bbMainModule->fullPath.empty()) &&
										(NT_SUCCESS(processData->bbPE.Load(processData->bbMainModule->fullPath))))
									{
										processData->isManaged = processData->bbPE.pureIL();
										processData->bbPEReady = true;
									}

									processData->bbModulesManuallyMapped = processData->bbProcess.modules().GetManualModules();
									processData->bbModulesLdrList = processData->bbProcess.modules().GetAllModules(blackbone::LdrList);
									//processData->bbModulesPEHeaders = processData->bbProcess.modules().GetAllModules(blackbone::PEHeaders);
									//processData->bbModulesSections = processData->bbProcess.modules().GetAllModules(blackbone::Sections);
								}
							}

							sysProcessesData.insert(std::pair<DWORD, std::shared_ptr<HunterCommon::ProcessData>>(te32.th32OwnerProcessID, processData));
						}
					}
				}
			}

			ret = true;
			CloseHandle(hSystemSnap);
		}

		return ret;
	}


	bool CleanupSystemProcessData(HunterCommon::ProcessCollection &sysProcessesData)
	{
		bool ret = true;

		for (HunterCommon::ProcessCollection::iterator handleIt = sysProcessesData.begin();
			handleIt != sysProcessesData.end();
			++handleIt)
		{
			if (handleIt->first > 0)
			{
				std::shared_ptr<HunterCommon::ProcessData> procInfo = handleIt->second;
				CloseHandle(procInfo->handle);
			}
		}

		sysProcessesData.clear();

		return ret;
	}

	bool GetMemoryRegionInfo(HANDLE &hProcess, size_t &dwStartAddress, MEMORY_BASIC_INFORMATION &info)
	{
		bool ret = false;

		memset(&info, 0, sizeof(info));
		if (VirtualQueryEx(hProcess, (LPVOID)dwStartAddress, &info, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
		{
			ret = true;
		}

		return ret;
	}

	bool GetThreadBasicInfo(HANDLE &thread, CustomWinTypes::THREAD_BASIC_INFORMATION &threadInfo)
	{
		bool ret = false;
		HMODULE ntdll = NULL;
		static CustomWinTypes::PNtQueryInformationThread NtQueryInformationThread = NULL;

		//lazy siglenton
		if (NtQueryInformationThread == NULL)
		{
			if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"ntdll.dll", &ntdll))
			{
				NtQueryInformationThread = (CustomWinTypes::PNtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
			}
		}

		if (NtQueryInformationThread != NULL)
		{
			if (NT_SUCCESS(NtQueryInformationThread(thread, CustomWinTypes::ThreadBasicInformation, &threadInfo, sizeof(threadInfo), NULL)))
			{
				ret = true;
			}
		}

		return ret;
	}


	bool GetThreadStartAddress(HANDLE &thread, PVOID &threadStartAddress)
	{
		bool ret = false;
		HMODULE ntdll = NULL;
		static CustomWinTypes::PNtQueryInformationThread NtQueryInformationThread = NULL;
		DWORD dwLen = 0;

		//lazy siglenton
		if (NtQueryInformationThread == NULL)
		{
			if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"ntdll.dll", &ntdll))
			{
				NtQueryInformationThread = (CustomWinTypes::PNtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
			}
		}

		if (NtQueryInformationThread != NULL)
		{
			if (NT_SUCCESS(NtQueryInformationThread(thread, CustomWinTypes::ThreadQuerySetWin32StartAddress, &threadStartAddress, sizeof(PVOID), &dwLen)))
			{
				ret = true;
			}
		}

		return ret;
	}


	bool IsFuzzyPEHeaderPresent(HANDLE &hProcess, size_t &addressToCheck, size_t &regionSize)
	{
		bool ret = false;
		const char *header = "MZ";
		char *buffer = nullptr;

		buffer = (char*)malloc(regionSize);
		if ((ReadProcessMemory(hProcess, (LPVOID)addressToCheck, buffer, regionSize, NULL)) &&
			(strncmp(buffer, header, 2) == 0))
		{
			ret = true;
		}
		free(buffer);

		return ret;
	}

	bool PopulateModulesIfNeededByWalkingPEHeaders(HunterCommon::ProcessDataPtr &processData)
	{
		bool ret = false;

		if (processData)
		{
			if (processData->bbModulesPEHeaders.size() > 0)
			{
				ret = true;
			}
			else
			{
				processData->bbModulesPEHeaders = processData->bbProcess.modules().GetAllModules(blackbone::PEHeaders);
				ret = true;
			}

		}

		return ret;
	}

	bool PopulateModulesIfNeededByMemorySections(HunterCommon::ProcessDataPtr &processData)
	{
		bool ret = false;

		if (processData)
		{
			if (processData->bbModulesSections.size() > 0)
			{
				ret = true;
			}
			else
			{
				processData->bbModulesSections = processData->bbProcess.modules().GetAllModules(blackbone::Sections);
				ret = true;
			}

		}

		return ret;
	}

	bool GetParentPid(const DWORD &pid, DWORD &parentPID)
	{
		bool ret = false;

		if (pid >= 0)
		{
			auto hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (hProcSnap)
			{
				PROCESSENTRY32W pEntry = { 0 };
				pEntry.dwSize = sizeof(PROCESSENTRY32W);

				// Iterate processes
				for (BOOL success = Process32FirstW(hProcSnap, &pEntry);
					success != FALSE;
					success = Process32NextW(hProcSnap, &pEntry))
				{
					if (pEntry.th32ProcessID == pid)
					{
						parentPID = pEntry.th32ParentProcessID;
						ret = true;
					}
				}
			}
		}

		return ret;
	}

	bool GetPEBAddress(const HANDLE &processHandle, PVOID &baseaddr)
	{
		bool ret = false;
		HMODULE ntdll = NULL;
		PROCESS_BASIC_INFORMATION processPEBAddress = { 0 };
		static CustomWinTypes::pNtQueryInformationProcess NtQueryInformationProcess = { 0 };
		DWORD dwLen = 0;

		//lazy siglenton
		if (NtQueryInformationProcess == NULL)
		{
			if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"ntdll.dll", &ntdll))
			{
				NtQueryInformationProcess = (CustomWinTypes::pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
			}
		}

		if (NtQueryInformationProcess != NULL)
		{
			if (NT_SUCCESS(NtQueryInformationProcess(processHandle, 0, &processPEBAddress, sizeof(processPEBAddress), &dwLen)))
			{
				baseaddr = processPEBAddress.PebBaseAddress;
				ret = true;
			}
		}

		return ret;
	}


	bool GetProcessCommandLine(blackbone::Process &targetProc, std::wstring &cmdline)
	{
		bool ret = false;
		PVOID pebAddress = nullptr;
		PVOID rtlUserProcParamsAddress = nullptr;
		UNICODE_STRING commandLine = { 0 };
		WCHAR *commandLineContents = nullptr;

		if (targetProc.valid())
		{
			cmdline.clear();

			HANDLE procHandle = targetProc.core().handle();
			
			if (GetPEBAddress(targetProc.core().handle(), pebAddress) &&
				ReadProcessMemory(targetProc.core().handle(),
				&(((_PEB*)pebAddress)->ProcessParameters),
				&rtlUserProcParamsAddress,
				sizeof(PVOID), NULL))
			{
				/* read the CommandLine UNICODE_STRING structure */
				if (ReadProcessMemory(targetProc.core().handle(),
					&(((_RTL_USER_PROCESS_PARAMETERS*)rtlUserProcParamsAddress)->CommandLine),
					&commandLine, sizeof(commandLine), NULL))
				{
					/* allocate memory to hold the command line */
					commandLineContents = (WCHAR *)malloc((commandLine.Length * sizeof(WCHAR)) + sizeof(WCHAR));
					memset(commandLineContents, 0, commandLine.Length);
					/* read the command line */
					if (ReadProcessMemory(targetProc.core().handle(), commandLine.Buffer,
						commandLineContents, commandLine.Length + sizeof(WCHAR), NULL))
					{
						/* print it */
						/* the length specifier is in characters, but commandLine.Length is in bytes */
						/* a WCHAR is 2 bytes */

						cmdline.assign(commandLineContents);

						if (!cmdline.empty())
						{
							ret = true;
						}
					}
				}
			}

			if (commandLineContents) free(commandLineContents);
		}

		return ret;
	}

	const wchar_t *HunterIDToString(const CustomTypes::HunterID &value)
	{
		switch (value)
		{
			case CustomTypes::HunterID::HUNT_SUSPICIOUS_CALLSTACK:		return L"SuspiciousCallStack";
			case CustomTypes::HunterID::HUNT_SUSPICIOUS_EXPORTS:		return L"SuspiciousExports";
			case CustomTypes::HunterID::HUNT_SUSPICIOUS_HOLLOWS:		return L"SuspiciousHollowedModules";
			case CustomTypes::HunterID::HUNT_SUSPICIOUS_MODULES:		return L"SuspiciousModules";
			case CustomTypes::HunterID::HUNT_SUSPICIOUS_PARENTS:		return L"SuspiciousParents";
			case CustomTypes::HunterID::HUNT_SUSPICIOUS_REGIONS:		return L"SuspiciousRegions";
			case CustomTypes::HunterID::HUNT_SUSPICIOUS_REGISTRY_PERSISTENCE: return L"SuspiciousRegistryPersistence";
			case CustomTypes::HunterID::HUNT_SUSPICIOUS_SHELLCODE:		return L"SuspiciousShellcode";
			case CustomTypes::HunterID::HUNT_SUSPICIOUS_THREADS:		return L"SuspiciousThreads";
			default:													return L"[Unknown Hunter ID]";
		}

	}

	bool VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
	{
		LONG lStatus;
		DWORD dwLastError;
		bool retValue = false;

		// Initialize the WINTRUST_FILE_INFO structure.
		WINTRUST_FILE_INFO FileData;
		memset(&FileData, 0, sizeof(FileData));
		FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
		FileData.pcwszFilePath = pwszSourceFile;
		FileData.hFile = NULL;
		FileData.pgKnownSubject = NULL;

		/*
		WVTPolicyGUID specifies the policy to apply on the file
		WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

		1) The certificate used to sign the file chains up to a root
		certificate located in the trusted root certificate store. This
		implies that the identity of the publisher has been verified by
		a certification authority.

		2) In cases where user interface is displayed (which this example
		does not do), WinVerifyTrust will check for whether the
		end entity certificate is stored in the trusted publisher store,
		implying that the user trusts content from this publisher.

		3) The end entity certificate has sufficient permission to sign
		code, as indicated by the presence of a code signing EKU or no
		EKU.
		*/

		GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		WINTRUST_DATA WinTrustData;

		// Initialize the WinVerifyTrust input data structure.

		// Default all fields to 0.
		memset(&WinTrustData, 0, sizeof(WinTrustData));

		WinTrustData.cbStruct = sizeof(WinTrustData);

		// Use default code signing EKU.
		WinTrustData.pPolicyCallbackData = NULL;

		// No data to pass to SIP.
		WinTrustData.pSIPClientData = NULL;

		// Disable WVT UI.
		WinTrustData.dwUIChoice = WTD_UI_NONE;

		// No revocation checking.
		WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

		// Verify an embedded signature on a file.
		WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

		// Verify action.
		WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

		// Verification sets this value.
		WinTrustData.hWVTStateData = NULL;

		// Not used.
		WinTrustData.pwszURLReference = NULL;

		// This is not applicable if there is no UI because it changes 
		// the UI to accommodate running applications instead of 
		// installing applications.
		WinTrustData.dwUIContext = 0;

		// Set pFile.
		WinTrustData.pFile = &FileData;

		// Prevent network calls during the validation process
		WinTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

		// WinVerifyTrust verifies signatures as specified by the GUID 
		// and Wintrust_Data.
		lStatus = WinVerifyTrust(
			NULL,
			&WVTPolicyGUID,
			&WinTrustData);

		switch (lStatus)
		{
		case ERROR_SUCCESS:
			/*
			Signed file:
			- Hash that represents the subject is trusted.

			- Trusted publisher without any verification errors.

			- UI was disabled in dwUIChoice. No publisher or
			time stamp chain errors.

			- UI was enabled in dwUIChoice and the user clicked
			"Yes" when asked to install and run the signed
			subject.
			*/
			//wprintf_s(L"The file \"%s\" is signed and the signature "
			//	L"was verified.\n",
			//	pwszSourceFile);
			retValue = true;
			break;

		case TRUST_E_NOSIGNATURE:
			// The file was not signed or had a signature 
			// that was not valid.

			// Get the reason for no signature.
			dwLastError = GetLastError();
			if (TRUST_E_NOSIGNATURE == dwLastError ||
				TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
				TRUST_E_PROVIDER_UNKNOWN == dwLastError)
			{
				// The file was not signed.
				//wprintf_s(L"The file \"%s\" is not signed.\n",
				//	pwszSourceFile);
			}
			else
			{
				// The signature was not valid or there was an error 
				// opening the file.
				//wprintf_s(L"An unknown error occurred trying to "
				//	L"verify the signature of the \"%s\" file.\n",
				//	pwszSourceFile);
			}

			break;

		case TRUST_E_EXPLICIT_DISTRUST:
			// The hash that represents the subject or the publisher 
			// is not allowed by the admin or user.
			//wprintf_s(L"The signature is present, but specifically "
			//	L"disallowed.\n");
			break;

		case TRUST_E_SUBJECT_NOT_TRUSTED:
			// The user clicked "No" when asked to install and run.
			//wprintf_s(L"The signature is present, but not "
			//	L"trusted.\n");
			break;

		case CRYPT_E_SECURITY_SETTINGS:
			/*
			The hash that represents the subject or the publisher
			was not explicitly trusted by the admin and the
			admin policy has disabled user trust. No signature,
			publisher or time stamp errors.
			*/
			//wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
			//	L"representing the subject or the publisher wasn't "
			//	L"explicitly trusted by the admin and admin policy "
			//	L"has disabled user trust. No signature, publisher "
			//	L"or timestamp errors.\n");
			break;

		default:
			// The UI was disabled in dwUIChoice or the admin policy 
			// has disabled user trust. lStatus contains the 
			// publisher or time stamp chain error.
			//wprintf_s(L"Error is: 0x%x.\n",
			//	lStatus);
			break;
		}

		// Any hWVTStateData must be released by a call with close.
		WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

		lStatus = WinVerifyTrust(
			NULL,
			&WVTPolicyGUID,
			&WinTrustData);

		return (retValue);
	}


	const std::wstring GetCertsSigner(const std::wstring &fileName, PCCERT_CONTEXT &pCertContext)
	{
		int                nRetCode = 0;
		HCERTSTORE         hCertStore = NULL;
		HCRYPTMSG          hCryptMsg = NULL;
		DWORD              dwContentType = 0;
		DWORD              dwExpectedType =
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED;
		DWORD              cbData = 0;
		CMSG_SIGNER_INFO * pSignerInfo = NULL;
		CERT_INFO          CertInfo = { 0 };

		const int SUBJECT_NAME_BUFFER_SIZE = 512;
		WCHAR             pwszSubjectName[SUBJECT_NAME_BUFFER_SIZE];
		std::wstring	   retValue;


		// Retrieve the signed executable HCRYPTMSG and HCERTSTORE.
		if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE,
			(LPCVOID)fileName.c_str(),
			dwExpectedType,
			CERT_QUERY_FORMAT_FLAG_BINARY,
			0,
			NULL,
			&dwContentType,
			NULL,
			&hCertStore,
			&hCryptMsg,
			NULL))
		{
			//nRetCode = GetLastError();
			//printf("Error [%#x]: CryptQueryObject() failed.\n", nRetCode);
			return(retValue);
		}

		// Sanity check.
		_ASSERT(CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED == dwContentType);

		// Use low level messaging API to retrieve signer's info.
		if (!CryptMsgGetParam(hCryptMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			NULL,
			&cbData))
		{
			//nRetCode = GetLastError();
			//printf("Error [%#x]: CryptMsgGetParam() failed.\n", nRetCode);
			return(retValue);
		}

		if (!(pSignerInfo = (CMSG_SIGNER_INFO *)malloc(cbData)))
		{
			//nRetCode = E_OUTOFMEMORY;
			//printf("Error [%#x]: malloc() failed.\n", nRetCode);
			return(retValue);
		}

		if (!CryptMsgGetParam(hCryptMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			pSignerInfo,
			&cbData))
		{
			//nRetCode = GetLastError();
			//printf("Error [%#x]: CryptMsgGetParam() failed.\n", nRetCode);
			return(retValue);
		}

		// Find signer's cert in store.
		CertInfo.Issuer = pSignerInfo->Issuer;
		CertInfo.SerialNumber = pSignerInfo->SerialNumber;

		if (!(pCertContext = CertFindCertificateInStore(hCertStore,
			X509_ASN_ENCODING |
			PKCS_7_ASN_ENCODING,
			0,

			CERT_FIND_SUBJECT_CERT,
			(LPVOID)&CertInfo,
			NULL)))
		{
			free(pSignerInfo);
			//nRetCode = GetLastError();
			//printf("Error [%#x]: CryptMsgGetParam() failed.\n", nRetCode);
			return(retValue);
		}

		if (!(cbData = CertGetNameStringW(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			pwszSubjectName,
			SUBJECT_NAME_BUFFER_SIZE)))
		{
			free(pSignerInfo);
			//nRetCode = CRYPT_E_NOT_FOUND;
			//printf("Error [%#x]: CertGetNameString() failed.\n", nRetCode);
			return(retValue);
		}

		std::wstring cad(pwszSubjectName);
		retValue = cad;
		// Display signer's simple name.
		//printf("%ls was signed by %ls.\n", fileName.c_str(), pwszSubjectName);

		free(pSignerInfo);
		return retValue;
	}

	bool CompareCertThumbPrint(PCCERT_CONTEXT certContext, const BYTE *thumbprintToVerify)
	{
		bool result = false;
		DWORD thumbPrintSize = 0;
		BYTE* thumbPrint = NULL;

		if (CryptHashCertificate(0, CALG_SHA1, 0, certContext->pbCertEncoded, certContext->cbCertEncoded, NULL, &thumbPrintSize))
		{
			thumbPrint = (BYTE *)calloc(thumbPrintSize, sizeof(BYTE));

			if (thumbPrint != NULL)
			{
				if (CryptHashCertificate(0, CALG_SHA1, 0, certContext->pbCertEncoded, certContext->cbCertEncoded, thumbPrint, &thumbPrintSize))
				{
					if (memcmp(thumbprintToVerify, thumbPrint, thumbPrintSize) == 0)
					{
						result = true;
					}
				}

				free(thumbPrint);
				thumbPrint = NULL;
			}
		}

		return result;
	}

	bool VerifyRootCAChainThumbPrint(PCCERT_CONTEXT &pCertContext)
	{
		bool ret = false;
		DWORD thumbPrintSize = 0;
		BYTE* thumbPrint = NULL;
		CERT_CHAIN_PARA chainPara = { 0 };
		PCCERT_CHAIN_CONTEXT pChainContext = NULL;
		PCERT_SIMPLE_CHAIN pSimpleChain = NULL;
		DWORD  dwTrustErrorMask = ~(CERT_TRUST_IS_NOT_TIME_NESTED | CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_REVOCATION_STATUS_UNKNOWN);
		DWORD  dwFlags = ~(CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_END_CERT);
		DWORD  dwErr = NO_ERROR;
		int numCerts = 0;

		if (CertGetCertificateChain(
			NULL,
			pCertContext,
			NULL,
			pCertContext->hCertStore,
			&chainPara,
			dwFlags,
			NULL,
			&pChainContext))
		{

			pSimpleChain = pChainContext->rgpChain[0];

			//Check revocation
			dwTrustErrorMask &= pSimpleChain->TrustStatus.dwErrorStatus;

			if (dwTrustErrorMask)
			{
				if (dwTrustErrorMask & CERT_TRUST_IS_OFFLINE_REVOCATION)
				{
					dwErr = NO_ERROR;
				}
				else if (dwTrustErrorMask & (CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_UNTRUSTED_ROOT))
				{
					dwErr = SEC_E_UNTRUSTED_ROOT;
				}
				else
				{
					dwErr = SEC_E_CERT_UNKNOWN;
				}
			}

			if (dwErr == NO_ERROR)
			{
				numCerts = pSimpleChain->cElement;
				if (numCerts > 0)
				{
					PCERT_CHAIN_ELEMENT* certPtr = pSimpleChain->rgpElement;

					for (int i = 0; i < numCerts; ++i)
					{
						PCCERT_CONTEXT rootCAContext = certPtr[i]->pCertContext;
						bool isValidChainRootCA = CompareCertThumbPrint(rootCAContext, CustomDefs::INTEL_SHA256_CERT_THUMBPRINT)
							|| CompareCertThumbPrint(rootCAContext, CustomDefs::VERISIGN_CERT_THUMBPRINT)
							|| CompareCertThumbPrint(rootCAContext, CustomDefs::ADDTRUST_CERT_THUMBPRINT);
						if (isValidChainRootCA)
						{
							ret = true;
							break;
						}
					}
				}
			}
		}

		return ret;
	}


	bool IsTrustedSignedFile(const std::wstring &fileName)
	{
		bool ret = false;
		PCCERT_CONTEXT pCertContext = NULL;

		if (VerifyEmbeddedSignature(fileName.c_str()))
		{
			std::wstring signer = GetCertsSigner(fileName, pCertContext);
			if (signer.compare(0, CustomDefs::MICROSOFT_CORP_SIGNER_TO_VERIFY.length(), CustomDefs::MICROSOFT_CORP_SIGNER_TO_VERIFY) == 0)
			{
				//if (VerifyRootCAChainThumbPrint(pCertContext))
				//{
				ret = true;
				//
			}
		}

		return(ret);
	}

	bool GetBaseDir(const std::wstring& fullpathFile, std::wstring& basedir)
	{
		bool ret = false;
		size_t found;

		found = fullpathFile.find_last_of(L"/\\");
		if (found > 0)
		{
			basedir.assign(fullpathFile.substr(0, found));
			basedir.append(L"\\");
			ret = true;
		}
		return ret;
	}

	bool IsFileInSafePath(const std::wstring &fileName)
	{
		bool ret = false;
		TCHAR  sysroot[MAX_PATH] = { 0 };
		TCHAR  programFiles[MAX_PATH] = { 0 };
		std::vector<std::wstring> trustedLocations;
		std::wstring baseFileDirectory;

		std::wstring workingFileName(fileName);
		std::transform(workingFileName.begin(), workingFileName.end(), workingFileName.begin(), ::tolower);

		if (GetWindowsDirectory(sysroot, MAX_PATH) &&
			SHGetSpecialFolderPath(0, programFiles, CSIDL_PROGRAM_FILES, FALSE))
		{
			std::wstring workingSysroot(sysroot);
			std::wstring workingProgramFiles(programFiles);
			std::transform(workingSysroot.begin(), workingSysroot.end(), workingSysroot.begin(), ::tolower);
			std::transform(workingProgramFiles.begin(), workingProgramFiles.end(), workingProgramFiles.begin(), ::tolower);

			std::wstring trustedNETBinariesLocation(workingSysroot);
			trustedNETBinariesLocation.append(L"\\assembly\\");
			trustedLocations.push_back(trustedNETBinariesLocation);

			std::wstring trustedDriversBinariesLocation(workingSysroot);
			trustedDriversBinariesLocation.append(L"\\system32\\drivers\\");
			trustedLocations.push_back(trustedDriversBinariesLocation);

			std::wstring trustedProgramFilesLocation(workingProgramFiles);
			trustedProgramFilesLocation.append(L"\\oracle\\");
			trustedLocations.push_back(trustedProgramFilesLocation);
		}

		if ((GetBaseDir(workingFileName, baseFileDirectory)) &&
			(trustedLocations.size() > 0))
		{
			for (std::vector<std::wstring>::const_iterator locationIt = trustedLocations.begin();
				locationIt != trustedLocations.end();
				++locationIt)
			{
				if (baseFileDirectory.find(*locationIt) == 0)
				{
					ret = true;
					break;
				}
			}
		}

		return ret;
	}

	bool IsTrustedFile(const std::wstring &fileName)
	{
		bool ret = false;

		if (IsFileInSafePath(fileName) || IsTrustedSignedFile(fileName))
		{
			ret = true;
		}

		return ret;
	}


	bool IsSuspiciousSymbolsOnThreadCallStackBeginning(const HunterCommon::CallStackDataList &csElements)
	{
		bool ret = false;
		HunterCommon::CallStackDataPtr element = nullptr;
		static const size_t MIN_NUMBER_OF_STACK_FRAMES = 3;

		//traversing elements from last to first
		if (csElements.size() > MIN_NUMBER_OF_STACK_FRAMES)
		{
			for (HunterCommon::CallStackDataList::const_reverse_iterator csIT = csElements.rbegin(); csIT != csElements.rend(); ++csIT)
			{
				element = *csIT;

				if (element && (!element->symbolName.empty()) && (GeneralHelpers::StrContainsPatternInsensitive(element->symbolName, "RtlUserThreadStart")))
				{
					csIT++;

					if (csIT != csElements.rend())
					{
						element = *csIT;

						if (element && (!element->symbolName.empty()) &&
							(GeneralHelpers::StrContainsPatternInsensitive(element->symbolName, "BaseThreadInitThunk")))
						{
							csIT++;

							if (csIT != csElements.rend())
							{
								element = *csIT;

								if (element && (!element->symbolName.empty()) &&
									((GeneralHelpers::StrContainsPatternInsensitive(element->symbolName, "LoadlibraryExW")) ||
									(GeneralHelpers::StrContainsPatternInsensitive(element->symbolName, "LoadlibraryExA")) ||
									(GeneralHelpers::StrContainsPatternInsensitive(element->symbolName, "LoadlibraryEx"))))
								{
									ret = true;
									break;
								}
							}
						}
					}
				}
			}
		}
		
		return ret;
	}

	bool IsAPCInjectionPresent(const HunterCommon::CallStackDataList &csElements)
	{
		bool ret = false;
		HunterCommon::CallStackDataPtr element = nullptr;
		static const size_t MIN_NUMBER_OF_STACK_FRAMES = 3;

		//traversing elements from last to first
		if (csElements.size() > MIN_NUMBER_OF_STACK_FRAMES)
		{
			for (HunterCommon::CallStackDataList::const_reverse_iterator csIT = csElements.rbegin(); csIT != csElements.rend(); ++csIT)
			{
				element = *csIT;

				if (element && (!element->symbolName.empty()) && (GeneralHelpers::StrContainsPatternInsensitive(element->symbolName, "UserApcDispatcher")))
				{					
					csIT++;

					if (csIT != csElements.rend())
					{
						element = *csIT;

						if (element && (!element->symbolName.empty()))
						{							
							csIT++;

							if (csIT != csElements.rend())
							{
								element = *csIT;

								if (element && (!element->symbolName.empty()) &&
									(GeneralHelpers::StrContainsPatternInsensitive(element->symbolName, "Loadlibrary")))
								{
									ret = true;
									break;
								}
							}
						}
					}
				}
			}
		}

		return ret;
	}

	bool IsModuleInThreadsCollection(DWORD &dwProcessId, HANDLE &hProcess, const HunterCommon::ThreadsCollection &threadsData, const HunterCommon::ModulesCollection &modules, const std::wstring &module, DWORD &tid)
	{
		bool ret = false;

		if (hProcess != INVALID_HANDLE_VALUE)
		{
			std::wstring moduleBaseName;
			if (GeneralHelpers::GetBaseFileName(module, moduleBaseName))
			{
				for (HunterCommon::ThreadsCollection::const_iterator threadIT = threadsData.begin();
					threadIT != threadsData.end();
					++threadIT)
				{
					//HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadIT->th32ThreadID);
					HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadIT->th32ThreadID);
					if (hThread != INVALID_HANDLE_VALUE)
					{
						if (IsModuleInThread(dwProcessId, hProcess, threadIT->th32ThreadID, modules, moduleBaseName))
						{
							tid = threadIT->th32ThreadID;
							ret = true;
							break;
						}

						CloseHandle(hThread);
					}
				}
			}
		}

		return ret;
	}

	bool IsModuleInThread(const DWORD &dwProcessId, const HANDLE &hProcess, const DWORD &tid, const HunterCommon::ModulesCollection &modules, const std::wstring &module)
	{
		bool ret = false;

		std::string moduleToCompare = GeneralHelpers::WStrToStr(module);
		if (hProcess != INVALID_HANDLE_VALUE)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
			if (hThread != INVALID_HANDLE_VALUE)
			{
				HunterCommon::CallStackDataList csElements;

				if (ThreadCallstackWalker::GetInstance().GetThreadCallStack(dwProcessId, hProcess, hThread, modules, csElements))
				{
					for (auto csIT = csElements.begin(); csIT != csElements.end(); csIT++)
					{
						HunterCommon::CallStackDataPtr element = *csIT;
						if (element && (moduleToCompare.compare(element->moduleName) == 0))
						{
							ret = true;
							break;
						}
					}
				}

				CloseHandle(hThread);
			}
		}

		return ret;
	}

	bool GetListOfCallStackModules(const DWORD &dwProcessId, const HANDLE &hProcess, const HANDLE &hThread, const HunterCommon::ModulesCollection &modules, HunterCommon::CallStackDataList &csElements, bool &suspiciousFound)
	{
		bool ret = false;
		static HANDLE currentHandleProcess = INVALID_HANDLE_VALUE;

		if (hProcess != INVALID_HANDLE_VALUE && hThread != INVALID_HANDLE_VALUE)
		{
			csElements.clear();

			if (ThreadCallstackWalker::GetInstance().GetThreadCallStack(dwProcessId, hProcess, hThread, modules, csElements))
			{
				ret = true;

				//Only checking last pushed element of the stack (thread start)
				if (!csElements.empty())
				{
					HunterCommon::CallStackDataPtr element = csElements.back();

					//check for suspicious empty module stack frames 
					if (element && (element->loadedImageName.empty()))
					{
						suspiciousFound = true;
					}
					//or symbols that indicates thread is starting from dll injection
					else if (HunterHelpers::IsSuspiciousSymbolsOnThreadCallStackBeginning(csElements))
					{
						suspiciousFound = true;
					}
					//Check for APC injection
					else if (HunterHelpers::IsAPCInjectionPresent(csElements))
					{
						suspiciousFound = true;
					}
				}				
			}
		}

		return ret;
	}

	bool ThreadCallstackWalker::GetThreadCallStack(const DWORD &pid, HANDLE hProcess, HANDLE hThread, const HunterCommon::ModulesCollection &modules, HunterCommon::CallStackDataList &csElements)
	{
		bool ret = false;
		bool goodToGetSymbols = true;

		static const DWORD MAX_NUMBER_OF_FRAMES = 64;
		if ((pid != 0) && (hProcess != INVALID_HANDLE_VALUE) && (hThread != INVALID_HANDLE_VALUE))
		{
			CONTEXT ctx = { 0 };
			ctx.ContextFlags = CONTEXT_CONTROL;
			bool threadContextWasRetrieved = false;

			//suspending the thread to get its exec context and resume it as quick as possible
			//Early resume will impact performance as we will have to check for thread status later
			if (SuspendThread(hThread) != ((DWORD)-1))
			{
				csElements.clear();

				if (GetThreadContext(hThread, &ctx) != FALSE)
				{
					threadContextWasRetrieved = true;
				}
				
				ResumeThread(hThread);
				
				if (threadContextWasRetrieved)
				{
					//Updating working process symbol initialization
					if (currentPID != pid)
					{
						if (currentProcessHandle != INVALID_HANDLE_VALUE)
						{
							SymCleanup(currentProcessHandle);
						}

						//closing previous initialization
						if (SymInitializeW(hProcess, NULL, TRUE))
						{
							currentPID = pid;
							currentProcessHandle = hProcess;
							
							/*
							//Manually initializing symbols
							for (auto modulesIT = modules.begin(); modulesIT != modules.end(); modulesIT++)
							{
								std::string moduleName(GeneralHelpers::WStrToStr(modulesIT->szExePath));
								PVOID addr = modulesIT->modBaseAddr;
								DWORD64 dwBaseAddr = reinterpret_cast<DWORD64>(addr);
								DWORD64 slret = SymLoadModuleEx(hProcess, NULL, moduleName.c_str(), NULL, dwBaseAddr, 0, NULL, 0);
								if (slret == 0)
								{
									//TODO: We might want to flag an error here
								}
							}		
							*/
						}
						else
						{
							goodToGetSymbols = false;
						}
					}

					if (goodToGetSymbols)
					{
						STACKFRAME64 sf;
						memset(&sf, 0, sizeof(STACKFRAME64));
						DWORD dwImageType = IMAGE_FILE_MACHINE_UNKNOWN;
#ifdef _M_IX86
						dwImageType = IMAGE_FILE_MACHINE_I386;
						sf.AddrPC.Offset = ctx.Eip;
						sf.AddrPC.Mode = AddrModeFlat;
						sf.AddrStack.Offset = ctx.Esp;
						sf.AddrStack.Mode = AddrModeFlat;
						sf.AddrFrame.Offset = ctx.Ebp;
						sf.AddrFrame.Mode = AddrModeFlat;
#elif _M_X64
						dwImageType = IMAGE_FILE_MACHINE_AMD64;
						sf.AddrPC.Offset = ctx.Rip;
						sf.AddrPC.Mode = AddrModeFlat;
						sf.AddrFrame.Offset = ctx.Rsp;
						sf.AddrFrame.Mode = AddrModeFlat;
						sf.AddrStack.Offset = ctx.Rsp;
						sf.AddrStack.Mode = AddrModeFlat;
#endif
						DWORD frameIT = 0;
						//Stack walk will continue until 
						// - process is still active
						// - thread is still active
						// - there are no more frames to read
						// - max number of frames have been reach
						while ((frameIT < MAX_NUMBER_OF_FRAMES) &&
							   (hProcess != NULL) &&
							   (hProcess != INVALID_HANDLE_VALUE) &&
							   (hThread != NULL) &&
							   (hThread != INVALID_HANDLE_VALUE))
//							   (GeneralHelpers::IsProcessStillRunning(hProcess)) &&
//							   (GeneralHelpers::IsThreadStillRunning(hThread)))
						{
							if (!StackWalk64(dwImageType, hProcess, hThread, &sf, &ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) break;

							DWORD64 address = sf.AddrPC.Offset;
							if (address == 0) break;

							HunterCommon::CallStackDataPtr newElement(new HunterCommon::CallStackData());
							newElement->stackFrameAddress = address;

							// Get symbol name
							char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)] = { 0 };
							PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
							pSymbol->MaxNameLen = MAX_SYM_NAME;
							pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
							if (SymFromAddr(currentProcessHandle, address, NULL, pSymbol))
							{
								newElement->symbolAvailable = pSymbol->Value;
								newElement->symbolAddress = pSymbol->Address;
								newElement->symbolName.assign(pSymbol->Name);
							}

							// Get module name
							IMAGEHLP_MODULE64 moduleInfo = { 0 };
							moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
							if (SymGetModuleInfo64(currentProcessHandle, address, &moduleInfo))
							{
								newElement->baseOfImageAddress = moduleInfo.BaseOfImage;
								newElement->imageSize = moduleInfo.ImageSize;
								newElement->timeDateStamp = moduleInfo.TimeDateStamp;
								newElement->checksum = moduleInfo.CheckSum;
								newElement->numSyms = moduleInfo.NumSyms;
								newElement->symType = moduleInfo.SymType;
								newElement->moduleName.assign(moduleInfo.ModuleName);
								newElement->imageName.assign(moduleInfo.ImageName);
								newElement->loadedImageName.assign(moduleInfo.LoadedImageName);
							}

							frameIT++;

							//Adding new stackframe element
							csElements.push_back(newElement);
						}
					}
				}

				if (!csElements.empty())
				{
					ret = true;
				}
			}
		}

		return ret;
	}
}