#pragma once

#include <iostream>
#include <memory>
#include <vector>
#include <map>
#include <iterator>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <wchar.h>
#include <wctype.h>
#include <winternl.h>
#include <KtmW32.h>
#include <exception>
#include <windows.h>
#include <winreg.h>
#include <psapi.h>
#include <shlwapi.h>
#include <Winternl.h>

#include <BlackBone/Config.h>
#include <BlackBone/Process/Process.h>
#include <BlackBone/Process/MultPtr.hpp>
#include <BlackBone/PE/PEImage.h>
#include <BlackBone/Process/RPC/RemoteFunction.hpp>
#include <BlackBone/PE/PEImage.h>
#include <BlackBone/Misc/Utils.h>
#include <BlackBone/Misc/DynImport.h>
#include <BlackBone/Syscalls/Syscall.h>
#include <BlackBone/Patterns/PatternSearch.h>
#include <BlackBone/Asm/LDasm.h>
#include <BlackBone/localHook/VTableHook.hpp>
#include <BlackBone/Patterns/PatternSearch.h>
#include <BlackBone/Process/RPC/RemoteFunction.hpp>
#include <BlackBone/Syscalls/Syscall.h>

#include "cmdparser.h"
//#include "DbgHelp.h"

#include "customtypes.h"
#include "customwintypes.h"

namespace InjectorHelpers
{	
	int ToInteger(const std::wstring &st);
	void WaitOnEnter();
	bool IsValidFile(const std::wstring &fileName);
	bool GetFullPathToFile(const std::wstring &fileName, std::wstring &fullPathFile);
	bool IsNumber(const std::wstring& str);
	bool GetFileToInjectSize(const std::wstring& file, DWORD &size);
	bool ReadFileToInjectInBuffer(const std::wstring& file, const DWORD &fileSize, LPVOID lpBuffer, DWORD &bytesRead);
	bool GetFileDetailsInBuffer(const std::wstring& file, LPVOID lpBuffer, DWORD &bytesRead);
	bool IsValidInjectionTarget(blackbone::pe::PEImage &codeToInject, blackbone::Process& targetToInject);
	bool IsValidInjectionTarget(blackbone::pe::PEImage &sourceModule, blackbone::pe::PEImage &targetModule);
	bool IsValidTargetPID(const std::wstring &targetPID);
	bool GetExecutionContext(const std::wstring codeToInject, const std::wstring targetToInject, blackbone::pe::PEImage &sourceModule, blackbone::pe::PEImage &targetModule);
	bool GetExecutionContext(const std::wstring codeToInject, const std::wstring targetToInject, blackbone::pe::PEImage &sourceModule, blackbone::Process &targetProc);
	bool StrContainsPatternInsensitive(const std::wstring& str, const std::wstring& pattern);
	bool GetBaseFileName(const std::wstring& fullPath, std::wstring &fileName);
	bool GetRegStringValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, std::wstring &regContent);
	bool GetRegDWORDValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, DWORD &nValue, DWORD &nDefaultValue);
	bool GetRegBoolValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, bool &nValue, bool &nDefaultValue);
	bool SetRegStringValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const std::wstring &regContent);
	bool SetRegDWORDValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const DWORD &nValue);
	bool SetRegBoolValue(const HKEY hRootKey, const std::wstring& regSubKey, const std::wstring& regValue, const bool &nValue);
	bool ReverseString(const std::string &input, std::string &output);
	bool ConvertStringToHexRepresentation(const std::string &input, std::string &output);
	bool GetNearestRoundValue(const size_t &numToRound, const size_t &multiple, size_t &output);
	bool PadStringWithValue(const std::string &input, const size_t num, const char paddingChar, std::string &output);

	FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName);
	HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter);
	DWORD GetReflectiveLoaderOffset(VOID * lpReflectiveDllBuffer);
	HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength);
	bool GetProcessBasicInformation(HANDLE hProcess, PROCESS_BASIC_INFORMATION &processPEB);
	bool GetRemotePEB(HANDLE hProcess, xPEB &processPEB);
	PIMAGE_SECTION_HEADER GetSectionOffset(const PVOID dwImageBase, const DWORD &offset);
	bool CreateSuspendedProcess(const std::wstring& targetProcess,
		STARTUPINFOW &targetStartupInfo,
		PROCESS_INFORMATION &targetProcessInfo);

	bool GetNTHeaders32(const PVOID execBuffer, IMAGE_NT_HEADERS32 &execNTHeader);
	bool GetNTHeaders64(const PVOID execBuffer, IMAGE_NT_HEADERS64 &execNTHeader);
	bool GetProcessCmdline(const HANDLE hProc, const PVOID procPEBAddr, std::wstring &cmdline);

	std::wstring StrToWStr(const std::string& str);
	std::string  WStrToStr(const std::wstring& wstr);

	//PLOADED_IMAGE GetLoadedImage(PIMAGE_NT_HEADERS32 dwImageBase);
}

//Useful Macros

#define CountRelocationEntries(dwBlockSize)		\
	(dwBlockSize -								\
	sizeof(BASE_RELOCATION_BLOCK)) /			\
	sizeof(BASE_RELOCATION_ENTRY)
