#include "common.h"

int InjectorHelpers::ToInteger(const std::wstring &str)
{
	return std::stoi(str);
}

void InjectorHelpers::WaitOnEnter()
{
	std::string dummy;
	std::wcout << "[+] Press enter to continue" << std::endl;
	std::getline(std::cin, dummy);
}

bool InjectorHelpers::IsValidFile(const std::wstring &fileName)
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

bool InjectorHelpers::GetFullPathToFile(const std::wstring &fileName, std::wstring &fullPathFile)
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

bool InjectorHelpers::IsNumber(const std::wstring& str)
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


bool InjectorHelpers::GetFileToInjectSize(const std::wstring& file, DWORD &size)
{
	bool ret = false;

	HANDLE hFile = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

bool InjectorHelpers::ReadFileToInjectInBuffer(const std::wstring& file, const DWORD &fileSize, LPVOID lpBuffer, DWORD &bytesRead)
{
	bool ret = false;

	if (lpBuffer != nullptr)
	{
		HANDLE hFile = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

bool InjectorHelpers::GetFileDetailsInBuffer(const std::wstring& file, LPVOID lpBuffer, DWORD &bytesRead)
{
	bool ret = false;
	PVOID lpWorkingBuffer = nullptr;
	DWORD workingBytesRead = 0;
	DWORD workingFileSize = 0;

	lpBuffer = nullptr;
	bytesRead = 0;

	if ((!file.empty()) && 
		(InjectorHelpers::IsValidFile(file)) && 
		(InjectorHelpers::GetFileToInjectSize(file, workingFileSize)) &&
		(workingFileSize > 0))
	{
		// Allocating memory for file content
		lpWorkingBuffer = VirtualAlloc(NULL, workingFileSize, (MEM_COMMIT | MEM_RESERVE),	PAGE_READWRITE);

		if ((lpWorkingBuffer != NULL) && 
			(InjectorHelpers::ReadFileToInjectInBuffer(file, workingFileSize, lpWorkingBuffer, workingBytesRead)) &&
			(workingBytesRead == workingFileSize))
		{
			lpBuffer = lpWorkingBuffer;
			bytesRead = workingBytesRead;
			ret = true;
		}
	}

	return ret;
}


bool InjectorHelpers::IsValidInjectionTarget(blackbone::pe::PEImage &sourceModule, blackbone::pe::PEImage &targetModule)
{
	bool ret = false;

	blackbone::eModType targetFileType = targetModule.mType();
	blackbone::eModType sourceFileType = sourceModule.mType();
	bool IsSourceNETFile = sourceModule.pureIL();
	bool IsTargetNETFile = targetModule.pureIL();
	bool IsSourceExeFile = sourceModule.isExe();
	bool IsTargetExeFile = targetModule.isExe();
	std::wstring sourceProcessPath = sourceModule.path();
	std::wstring targetProcessPath = targetModule.path();

	bool IsWin64ManagementProcess = false;
#ifdef _WIN64
	IsWin64ManagementProcess = true;
#endif

	if (((IsWin64ManagementProcess && targetFileType == blackbone::eModType::mt_mod64) ||
		(!IsWin64ManagementProcess && targetFileType == blackbone::eModType::mt_mod32)))
	{
		ret = true;
	}

	return ret;
}


bool InjectorHelpers::IsValidInjectionTarget(blackbone::pe::PEImage &codeToInject, blackbone::Process& targetToInject)
{
	bool ret = false;

	if ((codeToInject.imageSize() > 0) && (targetToInject.valid()))
	{
		auto& barrier = targetToInject.barrier();
		bool IsTargetWoWProcess = targetToInject.barrier().targetWow64;
		bool IsSourceWoWProcess = targetToInject.barrier().sourceWow64;
		bool mismatch = targetToInject.barrier().mismatch;
		bool x86OS = targetToInject.barrier().x86OS;
		blackbone::eBarrier targetBarrierType = targetToInject.barrier().type;
		blackbone::eModType sourceFileType = codeToInject.mType();
		bool IsSourceNETFile = codeToInject.pureIL();
		bool IsTargetNETFile = false;
		auto targetProcessPath = targetToInject.modules().GetMainModule();
		if (targetProcessPath)
		{
			blackbone::pe::PEImage targetPE;
			if ((ERROR_SUCCESS == targetPE.Load(targetProcessPath->fullPath)) && (targetPE.pureIL()))
			{
				IsTargetNETFile = true;
			}
		}

		//Checking if architectures are valid
		if (IsSourceNETFile && IsTargetNETFile)
		{
			std::cout << "[+] Valid context found: Source .NET module to Target .NET module" << std::endl;
			ret = true;
		}
		else if (!IsTargetNETFile && (targetBarrierType == blackbone::eBarrier::wow_32_32) && (sourceFileType == blackbone::eModType::mt_mod32))
		{
			std::cout << "[+] Valid context found: Source and Target are valid x32 modules" << std::endl;
			ret = true;
		}
		else if (!IsTargetNETFile && (targetBarrierType == blackbone::eBarrier::wow_64_64) && (sourceFileType == blackbone::eModType::mt_mod64))
		{
			std::cout << "[+] Valid context found: Source and Target are valid x64 modules" << std::endl;
			ret = true;
		}
		else if (!IsTargetNETFile && IsTargetWoWProcess && (sourceFileType == blackbone::eModType::mt_mod32))
		{
			std::cout << "[+] Valid context found: Source is 32 bit module and Target is WoW64 process" << std::endl;
			ret = true;
		}
		else if (!IsTargetNETFile && !IsTargetWoWProcess && (sourceFileType == blackbone::eModType::mt_mod64))
		{
			std::cout << "[+] Valid context found: Source is 64 bit module and Target is 64bit process" << std::endl;
			ret = true;
		}
	}

	return ret;
}

bool InjectorHelpers::IsValidTargetPID(const std::wstring &targetPID)
{
	bool ret = false;

	if (InjectorHelpers::IsNumber(targetPID))
	{
		DWORD workingTargetPID = InjectorHelpers::ToInteger(targetPID);
		if ((workingTargetPID > InjectorCommon::DEFAULT_MINIMUM_USERSPACE_PID) && (workingTargetPID != GetCurrentProcessId()))
		{
			ret = true;
		}
	}

	return ret;
}

bool InjectorHelpers::GetExecutionContext(const std::wstring codeToInject, const std::wstring targetToInject, blackbone::pe::PEImage &sourceModule, blackbone::pe::PEImage &targetModule)
{
	bool ret = false;

	if ((!codeToInject.empty()) &&
		(!targetToInject.empty()) &&
		(ERROR_SUCCESS == targetModule.Load(targetToInject)) &&
		(!targetModule.path().empty()) &&
		(ERROR_SUCCESS == sourceModule.Load(codeToInject)) &&
		(!sourceModule.path().empty()))
	{
		ret = true;
	}

	return ret;
}

bool InjectorHelpers::GetExecutionContext(const std::wstring codeToInject, const std::wstring targetToInject, blackbone::pe::PEImage &sourceModule, blackbone::Process &targetProc)
{
	bool ret = false;

	if ((InjectorHelpers::IsNumber(targetToInject)) &&
		(!codeToInject.empty()) &&
		(ERROR_SUCCESS == targetProc.Attach(InjectorHelpers::ToInteger(targetToInject))) &&
		(targetProc.valid()) &&
		(ERROR_SUCCESS == sourceModule.Load(codeToInject)) &&
		(!sourceModule.isExe()) &&
		(!sourceModule.path().empty()))
	{
		ret = true;
	}

	return ret;
}

bool InjectorHelpers::StrContainsPatternInsensitive(const std::wstring& str, const std::wstring& pattern)
{
	bool ret = false;

	std::wstring test1(str);
	std::wstring test2(pattern);

	std::transform(test1.begin(), test1.end(), test1.begin(), ::towlower);
	std::transform(test2.begin(), test2.end(), test2.begin(), ::towlower);

	if (test1.find(test2) != std::wstring::npos)
	{
		ret = true;
	}

	return ret;
}

PIMAGE_SECTION_HEADER InjectorHelpers::GetSectionOffset(const PVOID dwImageBase, const DWORD &offset)
{
	PIMAGE_SECTION_HEADER ret = NULL;

	PIMAGE_DOS_HEADER pDosH = (PIMAGE_DOS_HEADER)dwImageBase;

	ret = (PIMAGE_SECTION_HEADER)((LPBYTE)dwImageBase + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (offset * sizeof(IMAGE_SECTION_HEADER)));

	return ret;
}

bool InjectorHelpers::GetProcessBasicInformation(HANDLE hProcess, PROCESS_BASIC_INFORMATION &processPEB)
{
	bool ret = false;
	DWORD dwLen = 0;
	HMODULE hNTDLL = NULL;
	static _NtQueryInformationProcess ntQueryInformationProcess = { 0 };

	if (ntQueryInformationProcess == NULL && 
		GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"NTDLL.DLL", &hNTDLL))
	{
		ntQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNTDLL, "NtQueryInformationProcess");
	}

	if (ntQueryInformationProcess != NULL)
	{
		if (NT_SUCCESS(ntQueryInformationProcess(hProcess, 0, &processPEB, sizeof(processPEB), &dwLen)))
		{
			ret = true;
		}
	}

	return ret;
}

bool InjectorHelpers::GetRemotePEB(HANDLE hProcess, xPEB &processPEB)
{
	bool ret = false;
	PROCESS_BASIC_INFORMATION processBasicInfo = { 0 };
	SIZE_T bytesRead = 0;
	if (GetProcessBasicInformation(hProcess, processBasicInfo) &&
	    (IsBadReadPtr(&processBasicInfo.PebBaseAddress, sizeof(xPEB)) == 0) &&
		ReadProcessMemory(hProcess, processBasicInfo.PebBaseAddress, &processPEB, sizeof(xPEB), &bytesRead))
	{
		//*processPEB = (xPEB *)processBasicInfo.PebBaseAddress;
		ret = true;
	}

	return ret;
}


bool InjectorHelpers::CreateSuspendedProcess(const std::wstring& targetProcess, 
											 STARTUPINFOW &targetStartupInfo,
											 PROCESS_INFORMATION &targetProcessInfo)
{
	bool ret = false;

	memset(&targetStartupInfo, 0, sizeof(STARTUPINFOW));
	memset(&targetProcessInfo, 0, sizeof(PROCESS_INFORMATION));

	if (CreateProcessW(NULL,
		((wchar_t *)targetProcess.c_str()),
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&targetStartupInfo,
		&targetProcessInfo))
	{
		ret = true;
	}

	return ret;
}

bool InjectorHelpers::GetNTHeaders32(const PVOID execBuffer, IMAGE_NT_HEADERS32 &execNTHeader)
{
	bool ret = false;

	if (execBuffer != nullptr)
	{
		//checking if we have access to valid HEADER
		IMAGE_DOS_HEADER *pDOSHeader = (IMAGE_DOS_HEADER*)execBuffer;
		if ((IsBadReadPtr(pDOSHeader, sizeof(IMAGE_DOS_HEADER)) == 0) &&
			(pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)) 		
		{
			memset(&execNTHeader, 0, sizeof(IMAGE_NT_HEADERS32));

			PVOID pExecBuffNTHeader = (PVOID)((ULONGLONG)execBuffer + pDOSHeader->e_lfanew);

			memcpy(&execNTHeader, pExecBuffNTHeader, sizeof(IMAGE_NT_HEADERS64));
			if ((IsBadReadPtr(&execNTHeader, sizeof(IMAGE_NT_HEADERS32)) == 0) &&
				(execNTHeader.Signature == IMAGE_NT_SIGNATURE))
			{
				ret = true;
			}
		}
	}

	return ret;
}

bool InjectorHelpers::GetNTHeaders64(const PVOID execBuffer, IMAGE_NT_HEADERS64 &execNTHeader)
{
	bool ret = false;

	if (execBuffer != nullptr)
	{
		//checking if we have access to valid HEADER
		IMAGE_DOS_HEADER *pDOSHeader = (IMAGE_DOS_HEADER*)execBuffer;
		if ((IsBadReadPtr(pDOSHeader, sizeof(IMAGE_DOS_HEADER)) == 0) &&
			(pDOSHeader->e_magic == IMAGE_DOS_SIGNATURE))
		{
			memset(&execNTHeader, 0, sizeof(IMAGE_NT_HEADERS64));

			PVOID pExecBuffNTHeader = (PVOID)((ULONGLONG)execBuffer + pDOSHeader->e_lfanew);

			memcpy(&execNTHeader, pExecBuffNTHeader, sizeof(IMAGE_NT_HEADERS64));

			if ((IsBadReadPtr(&execNTHeader, sizeof(IMAGE_NT_HEADERS64)) == 0) &&
				(execNTHeader.Signature == IMAGE_NT_SIGNATURE))
			{
				ret = true;
			}
		}
	}

	return ret;
}


bool InjectorHelpers::GetProcessCmdline(const HANDLE hProc, const PVOID procPEBAddr, std::wstring &cmdline)
{
	bool ret = false;
	PVOID paramDataAddr = nullptr;
	WCHAR commandLineData[8192] = { 0 };
	UNICODE_STRING unicodeCmdlineData = { 0 };

	if (hProc != INVALID_HANDLE_VALUE && procPEBAddr != nullptr)
	{
		PRTL_USER_PROCESS_PARAMETERS *pProcParamAddr = &(((_PEB*)procPEBAddr)->ProcessParameters);

		if ((IsBadReadPtr(pProcParamAddr, sizeof(PRTL_USER_PROCESS_PARAMETERS)) == 0) &&
			(ReadProcessMemory(hProc, pProcParamAddr, &paramDataAddr, sizeof(PVOID), NULL)))
		{
			RTL_USER_PROCESS_PARAMETERS *pProcParams = (RTL_USER_PROCESS_PARAMETERS*)paramDataAddr;
			if ((IsBadReadPtr(pProcParams, sizeof(PRTL_USER_PROCESS_PARAMETERS)) == 0) &&
				(&pProcParams->CommandLine != nullptr) &&
				ReadProcessMemory(hProc,
					&pProcParams->CommandLine,
					&unicodeCmdlineData,
					sizeof(UNICODE_STRING),
					NULL))
			{
				if ((unicodeCmdlineData.Buffer != nullptr) &&
					(unicodeCmdlineData.Length < (8192 - 1)) &&
					(ReadProcessMemory(hProc,
						unicodeCmdlineData.Buffer,
						&commandLineData,
						unicodeCmdlineData.Length,
						NULL)))
				{
					cmdline.assign(commandLineData);
					ret = true;
				}
			}
		}
	}

	return ret;
}

std::wstring InjectorHelpers::StrToWStr(const std::string& str)
{
	size_t strCount = str.length();
	int bytesToAllocate = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)strCount, NULL, 0);

	std::wstring ret(bytesToAllocate, 0);
	int wideCharsCount = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)strCount, &ret[0], bytesToAllocate);

	//TODO: add check for wideCharsCount == strCount
	return ret;
}

std::string InjectorHelpers::WStrToStr(const std::wstring& wstr)
{
	size_t strCount = wstr.length();
	int bytesToAllocate = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)strCount, NULL, 0, NULL, NULL);

	std::string ret(bytesToAllocate, 0);
	int w = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)strCount, &ret[0], bytesToAllocate, NULL, NULL);

	//TODO: add check for wideCharsCount == strCount
	return ret;
}


/*
PLOADED_IMAGE InjectorHelpers::GetLoadedImage(PIMAGE_NT_HEADERS32 dwImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS32 pNTHeaders = GetNTHeaders(dwImageBase);

	PLOADED_IMAGE pImage = new LOADED_IMAGE();

	pImage->FileHeader =
		(PIMAGE_NT_HEADERS32)(dwImageBase + pDosHeader->e_lfanew);

	pImage->NumberOfSections =
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections =
		(PIMAGE_SECTION_HEADER)(dwImageBase + pDosHeader->e_lfanew +
			sizeof(IMAGE_NT_HEADERS32));

	return pImage;
}
*/


bool OpenKey(const HKEY hRootKey, const std::wstring &regSubKey, HKEY &hKey)
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
			if ((RegCreateKeyEx(hRootKey, regSubKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey,	NULL)) == ERROR_SUCCESS)
			{
				ret = true;
			}
		}
	}

	return ret;
}

bool InjectorHelpers::GetRegStringValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, std::wstring &regContent)
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


bool InjectorHelpers::SetRegStringValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const std::wstring &regContent)
{
	bool ret = false;

	HKEY hKey = NULL;
	if (!regSubKey.empty() && !regValue.empty() && (hRootKey != NULL) && OpenKey(hRootKey, regSubKey, hKey))
	{
		if (RegSetValueExW(hKey, regValue.c_str(), 0, REG_SZ, ((const BYTE*)regContent.c_str()), (DWORD)((regContent.length() * sizeof(TCHAR))+ 1)) == ERROR_SUCCESS)
		{
			ret = true;
		}

		RegCloseKey(hKey);
	}

	return ret;
}

bool InjectorHelpers::GetRegDWORDValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, DWORD &nValue, DWORD &nDefaultValue)
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
		else if (ERROR_FILE_NOT_FOUND == nError)
		{
			//entry does not exists, setting it up to default value
			DWORD workDefaultValue = nDefaultValue;


			if (RegSetValueExW(hKey, regValue.c_str(), 0, REG_DWORD, ((const BYTE*)&workDefaultValue), sizeof(workDefaultValue)) == ERROR_SUCCESS)
			{
				nValue = workDefaultValue;
				ret = true;
			}
		}

		RegCloseKey(hKey);
	}

	return ret;
}


bool InjectorHelpers::SetRegDWORDValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const DWORD &nValue)
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

bool InjectorHelpers::GetRegBoolValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, bool &nValue, bool &nDefaultValue)
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
		else if (ERROR_FILE_NOT_FOUND == nError)
		{
			//entry does not exists, setting it up to default value
			DWORD workDefaultValue = 0;
			if (nDefaultValue) workDefaultValue = 1;

			if (RegSetValueExW(hKey, regValue.c_str(), 0, REG_DWORD, ((const BYTE*)&workDefaultValue), sizeof(workDefaultValue)) == ERROR_SUCCESS)
			{
				nValue = workDefaultValue;
				ret = true;
			}
		}
	}

	return ret;
}


bool InjectorHelpers::SetRegBoolValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const bool &nValue)
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


bool InjectorHelpers::ReverseString(const std::string &input, std::string &output)
{
	bool ret = false;

	if (!input.empty())
	{
		output.assign(input);
		std::reverse(output.begin(), output.end());
		ret = true;
	}

	return ret;
}


bool InjectorHelpers::ConvertStringToHexRepresentation(const std::string &input, std::string &output)
{
	bool ret = false;
	std::ostringstream convertedOS;
	std::string workingStr;
	for (size_t it = 0; it < input.length(); it++)
	{
		convertedOS << std::hex << std::uppercase << (int)input[it];
	}

	workingStr = convertedOS.str();

	if (!workingStr.empty())
	{
		output.assign(workingStr);
		ret = true;
	}

	return ret;
}

bool InjectorHelpers::GetNearestRoundValue(const size_t &numToRound, const size_t &multiple, size_t &output)
{
	bool ret = false;

	if ((multiple > 0) && (multiple > 0))
	{
		size_t remainder = numToRound % multiple;
		if (remainder == 0)
		{
			output = numToRound;
		}
		else
		{
			output = (numToRound + multiple) - remainder;
		}

		ret = true;
	}

	return ret;
}

bool InjectorHelpers::PadStringWithValue(const std::string &input, const size_t num, const char paddingChar, std::string &output)
{
	bool ret = false;

	std::string workString;

	if ((!input.empty()) && (num > input.size()))
	{
		workString.insert(0, num - input.size(), paddingChar);
		output.append(input);
		output.append(workString);
		ret = true;
	}

	return ret;
}


bool InjectorHelpers::GetBaseFileName(const std::wstring& fullPath, std::wstring &fileName)
{
	bool ret = false;

	if (!fullPath.empty())
	{
		std::wstring workingPath(fullPath);
		fileName.clear();

		wchar_t sep = '\\';

		size_t it = workingPath.rfind(sep, workingPath.length());

		if (it != std::wstring::npos)
		{
			fileName.assign(workingPath.substr(it + 1, workingPath.length() - it));
			ret = true;
		}
	}

	return ret;
}