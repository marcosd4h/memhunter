#pragma once

#include <windows.h>
#include <winternl.h>

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define PS_INHERIT_HANDLES          4
#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001
#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _CUSTOMCLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CUSTOMCLIENT_ID, *CUSTOMPCLIENT_ID;

typedef long(WINAPI * PRTL_CREATE_USER_THREAD)
(
	__in HANDLE Process,
	__in_opt PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
	__in char Flags,
	__in_opt ULONG ZeroBits,
	__in_opt SIZE_T MaximumStackSize,
	__in_opt SIZE_T CommittedStackSize,
	__in PTHREAD_START_ROUTINE StartAddress,
	__in_opt PVOID Parameter,
	__out_opt PHANDLE Thread,
	__out_opt CUSTOMPCLIENT_ID ClientId
	);

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR(WINAPI * REFLECTIVELOADER)(VOID);
typedef BOOL(WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

// Function Pointer Typedef for RtlCreateUserThread
typedef DWORD(WINAPI * pRtlCreateUserThread)(
	IN HANDLE 					ProcessHandle,
	IN PSECURITY_DESCRIPTOR 	SecurityDescriptor,
	IN BOOL 					CreateSuspended,
	IN ULONG					StackZeroBits,
	IN OUT PULONG				StackReserved,
	IN OUT PULONG				StackCommit,
	IN LPVOID					StartAddress,
	IN LPVOID					StartParameter,
	OUT HANDLE 					ThreadHandle,
	OUT LPVOID					ClientID
	);

struct NtCreateThreadExBuffer {
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
};

/*
typedef NTSTATUS(WINAPI *LPFUN_NtCreateThreadEx) (
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	ULONG StackZeroBits,
	ULONG SizeOfStackCommit,
	ULONG SizeOfStackReserve,
	LPVOID lpBytesBuffer
	);
*/

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

//===============================================================================================//
typedef struct _UNICODE_STR
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) ) 
typedef struct _xLDR_DATA_TABLE_ENTRY
{
	//LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} xLDR_DATA_TABLE_ENTRY, *xPLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _xPEB_LDR_DATA //, 7 elements, 0x28 bytes
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} xPEB_LDR_DATA, *xPPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK

typedef struct _xPEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
	struct _xPEB_FREE_BLOCK * pNext;
	DWORD dwSize;
} xPEB_FREE_BLOCK, *xPPEB_FREE_BLOCK;


// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct __xPEB // 65 elements, 0x210 bytes
{
	BYTE bInheritedAddressSpace;
	BYTE bReadImageFileExecOptions;
	BYTE bBeingDebugged;
	BYTE bSpareBool;
	LPVOID lpMutant;
	LPVOID lpImageBaseAddress;
	xPPEB_LDR_DATA pLdr;
	LPVOID lpProcessParameters;
	LPVOID lpSubSystemData;
	LPVOID lpProcessHeap;
	PRTL_CRITICAL_SECTION pFastPebLock;
	LPVOID lpFastPebLockRoutine;
	LPVOID lpFastPebUnlockRoutine;
	DWORD dwEnvironmentUpdateCount;
	LPVOID lpKernelCallbackTable;
	DWORD dwSystemReserved;
	DWORD dwAtlThunkSListPtr32;
	xPPEB_FREE_BLOCK pFreeList;
	DWORD dwTlsExpansionCounter;
	LPVOID lpTlsBitmap;
	DWORD dwTlsBitmapBits[2];
	LPVOID lpReadOnlySharedMemoryBase;
	LPVOID lpReadOnlySharedMemoryHeap;
	LPVOID lpReadOnlyStaticServerData;
	LPVOID lpAnsiCodePageData;
	LPVOID lpOemCodePageData;
	LPVOID lpUnicodeCaseTableData;
	DWORD dwNumberOfProcessors;
	DWORD dwNtGlobalFlag;
	LARGE_INTEGER liCriticalSectionTimeout;
	DWORD dwHeapSegmentReserve;
	DWORD dwHeapSegmentCommit;
	DWORD dwHeapDeCommitTotalFreeThreshold;
	DWORD dwHeapDeCommitFreeBlockThreshold;
	DWORD dwNumberOfHeaps;
	DWORD dwMaximumNumberOfHeaps;
	LPVOID lpProcessHeaps;
	LPVOID lpGdiSharedHandleTable;
	LPVOID lpProcessStarterHelper;
	DWORD dwGdiDCAttributeList;
	LPVOID lpLoaderLock;
	DWORD dwOSMajorVersion;
	DWORD dwOSMinorVersion;
	WORD wOSBuildNumber;
	WORD wOSCSDVersion;
	DWORD dwOSPlatformId;
	DWORD dwImageSubsystem;
	DWORD dwImageSubsystemMajorVersion;
	DWORD dwImageSubsystemMinorVersion;
	DWORD dwImageProcessAffinityMask;
	DWORD dwGdiHandleBuffer[34];
	LPVOID lpPostProcessInitRoutine;
	LPVOID lpTlsExpansionBitmap;
	DWORD dwTlsExpansionBitmapBits[32];
	DWORD dwSessionId;
	ULARGE_INTEGER liAppCompatFlags;
	ULARGE_INTEGER liAppCompatFlagsUser;
	LPVOID lppShimData;
	LPVOID lpAppCompatInfo;
	UNICODE_STR usCSDVersion;
	LPVOID lpActivationContextData;
	LPVOID lpProcessAssemblyStorageMap;
	LPVOID lpSystemDefaultActivationContextData;
	LPVOID lpSystemAssemblyStorageMap;
	DWORD dwMinimumStackCommit;
} xPEB, *xPPEB;

typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

/*
typedef struct _LOADED_IMAGE {
	PSTR                  ModuleName;
	HANDLE                hFile;
	PUCHAR                MappedAddress;
	PIMAGE_NT_HEADERS32   FileHeader;
	PIMAGE_SECTION_HEADER LastRvaSection;
	ULONG                 NumberOfSections;
	PIMAGE_SECTION_HEADER Sections;
	ULONG                 Characteristics;
	BOOLEAN               fSystemImage;
	BOOLEAN               fDOSImage;
	BOOLEAN               fReadOnly;
	UCHAR                 Version;
	LIST_ENTRY            Links;
	ULONG                 SizeOfImage;
} LOADED_IMAGE, *PLOADED_IMAGE;
*/

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;
