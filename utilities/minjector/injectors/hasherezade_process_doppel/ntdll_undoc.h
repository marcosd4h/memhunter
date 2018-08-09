#pragma once

#include <Windows.h>
//#include "ntddk.h"
#include "ntdll_types.h"
#include <winternl.h>

#define GDI_HANDLE_BUFFER_SIZE      34

typedef struct _HRTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG  TimeStamp;
	STRING DosPath;

} HRTL_DRIVE_LETTER_CURDIR, *HPRTL_DRIVE_LETTER_CURDIR;

typedef struct _HCURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;

} HCURDIR, *HPCURDIR;


typedef struct _RHTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;                            // Should be set before call RtlCreateProcessParameters
	ULONG Length;                                   // Length of valid structure
	ULONG Flags;                                    // Currently only PPF_NORMALIZED (1) is known:
													//  - Means that structure is normalized by call RtlNormalizeProcessParameters
	ULONG DebugFlags;

	PVOID ConsoleHandle;                            // HWND to console window associated with process (if any).
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	HCURDIR CurrentDirectory;                        // Specified in DOS-like symbolic link path, ex: "C:/WinNT/SYSTEM32"
	UNICODE_STRING DllPath;                         // DOS-like paths separated by ';' where system should search for DLL files.
	UNICODE_STRING ImagePathName;                   // Full path in DOS-like format to process'es file image.
	UNICODE_STRING CommandLine;                     // Command line
	PVOID Environment;                              // Pointer to environment block (see RtlCreateEnvironment)
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;                            // Fill attribute for console window
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;                     // Name of WindowStation and Desktop objects, where process is assigned
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	HRTL_DRIVE_LETTER_CURDIR CurrentDirectores[0x20];
	ULONG EnvironmentSize;
} HRTL_USER_PROCESS_PARAMETERS, *HPRTL_USER_PROCESS_PARAMETERS;

//Functions:

extern NTSTATUS (NTAPI *NtCreateProcessEx)
(
    OUT PHANDLE     ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
    IN HANDLE   ParentProcess,
    IN ULONG    Flags,
    IN HANDLE SectionHandle     OPTIONAL,
    IN HANDLE DebugPort     OPTIONAL,
    IN HANDLE ExceptionPort     OPTIONAL,
    IN BOOLEAN  InJob
);

extern NTSTATUS (NTAPI *RtlCreateProcessParametersEx)(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
);


extern NTSTATUS (NTAPI *NtCreateThreadEx) (
    OUT  PHANDLE ThreadHandle, 
    IN  ACCESS_MASK DesiredAccess, 
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, 
    IN  HANDLE ProcessHandle,
    IN  PVOID StartRoutine,
    IN  PVOID Argument OPTIONAL,
    IN  ULONG CreateFlags,
    IN  ULONG_PTR ZeroBits, 
    IN  SIZE_T StackSize OPTIONAL,
    IN  SIZE_T MaximumStackSize OPTIONAL, 
    IN  PVOID AttributeList OPTIONAL
);


extern NTSTATUS(NTAPI *NtReadVirtualMemory) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG NumberOfBytesToRead,
	OUT PULONG NumberOfBytesRead OPTIONAL
	);


/*++

NtCreateSection
===============

Creates a section object.

SectionHandle - Points to a variable that will receive the section
object handle if the call is successful.

DesiredAccess - Specifies the type of access that the caller requires
to the section object. This parameter can be zero, or any combination
of the following flags:

SECTION_QUERY       - Query access
SECTION_MAP_WRITE   - Can be written when mapped
SECTION_MAP_READ    - Can be read when mapped
SECTION_MAP_EXECUTE - Can be executed when mapped
SECTION_EXTEND_SIZE - Extend access
SECTION_ALL_ACCESS  - All of the preceding +
STANDARD_RIGHTS_REQUIRED

ObjectAttributes - Points to a structure that specifies the object s attributes.
OBJ_OPENLINK is not a valid attribute for a section object.

MaximumSize - Optionally points to a variable that specifies the size,
in bytes, of the section. If FileHandle is zero, the size must be
specified; otherwise, it can be defaulted from the size of the file
referred to by FileHandle.

SectionPageProtection - The protection desired for the pages
of the section when the section is mapped. This parameter can take
one of the following values:

PAGE_READONLY
PAGE_READWRITE
PAGE_WRITECOPY
PAGE_EXECUTE
PAGE_EXECUTE_READ
PAGE_EXECUTE_READWRITE
PAGE_EXECUTE_WRITECOPY

AllocationAttributes - The attributes for the section. This parameter must
be a combination of the following values:

SEC_BASED     0x00200000    // Map section at same address in each process
SEC_NO_CHANGE 0x00400000    // Disable changes to protection of pages
SEC_IMAGE     0x01000000    // Map section as an image
SEC_VLM       0x02000000    // Map section in VLM region
SEC_RESERVE   0x04000000    // Reserve without allocating pagefile storage
SEC_COMMIT    0x08000000    // Commit pages; the default behavior
SEC_NOCACHE   0x10000000    // Mark pages as non-cacheable

FileHandle - Identifies the file from which to create the section object.
The file must be opened with an access mode compatible with the protection
flags specified by the Protect parameter. If FileHandle is zero,
the function creates a section object of the specified size backed
by the paging file rather than by a named file in the file system.

--*/

extern NTSTATUS(NTAPI *NtCreateSection) (
	OUT PHANDLE SectionHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  PLARGE_INTEGER MaximumSize OPTIONAL,
	IN  ULONG SectionPageProtection,
	IN  ULONG AllocationAttributes,
	IN  HANDLE FileHandle OPTIONAL
	);



//NTSYSAPI
NTSTATUS
NTAPI
ZwCreateSection(
	OUT PHANDLE SectionHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  PLARGE_INTEGER MaximumSize OPTIONAL,
	IN  ULONG SectionPageProtection,
	IN  ULONG AllocationAttributes,
	IN  HANDLE FileHandle OPTIONAL
);


typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK *Next;
	ULONG Size;

} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;


typedef struct _HPEB
{
	BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
	BOOLEAN ReadImageFileExecOptions;   //
	BOOLEAN BeingDebugged;              //
	BOOLEAN SpareBool;                  //
	HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID FastPebLockRoutine;
	PVOID FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID KernelCallbackTable;
	HANDLE SystemReserved;
	PVOID  AtlThunkSListPtr32;
	PPEB_FREE_BLOCK FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];         // relates to TLS_MINIMUM_AVAILABLE
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;

	//
	// Useful information for LdrpInitialize

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	//
	// Passed up from MmCreatePeb from Session Manager registry key
	//

	LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;

	//
	// Where heap manager keeps track of all heaps created for a process
	// Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
	// to point to the first free byte after the PEB and MaximumNumberOfHeaps
	// is computed from the page size used to hold the PEB, less the fixed
	// size of this data structure.
	//

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;

	//
	//
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;

	//
	// Following fields filled in by MmCreatePeb from system values and/or
	// image header. These fields have changed since Windows NT 4.0,
	// so use with caution
	//

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG ImageProcessAffinityMask;
	ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];

} HPEB, *HPPEB;





NTSTATUS(NTAPI *NtCreateProcessEx)
(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes  OPTIONAL,
	IN HANDLE   ParentProcess,
	IN ULONG    Flags,
	IN HANDLE   SectionHandle OPTIONAL,
	IN HANDLE   DebugPort OPTIONAL,
	IN HANDLE   ExceptionPort OPTIONAL,
	IN BOOLEAN  InJob
	) = NULL;

NTSTATUS(NTAPI *RtlCreateProcessParametersEx)(
	_Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
	_In_ PUNICODE_STRING ImagePathName,
	_In_opt_ PUNICODE_STRING DllPath,
	_In_opt_ PUNICODE_STRING CurrentDirectory,
	_In_opt_ PUNICODE_STRING CommandLine,
	_In_opt_ PVOID Environment,
	_In_opt_ PUNICODE_STRING WindowTitle,
	_In_opt_ PUNICODE_STRING DesktopInfo,
	_In_opt_ PUNICODE_STRING ShellInfo,
	_In_opt_ PUNICODE_STRING RuntimeData,
	_In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
	) = NULL;

NTSTATUS(NTAPI *NtCreateThreadEx) (
	OUT  PHANDLE ThreadHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  HANDLE ProcessHandle,
	IN  PVOID StartRoutine,
	IN  PVOID Argument OPTIONAL,
	IN  ULONG CreateFlags,
	IN  ULONG_PTR ZeroBits,
	IN  SIZE_T StackSize OPTIONAL,
	IN  SIZE_T MaximumStackSize OPTIONAL,
	IN  PVOID AttributeList OPTIONAL
	) = NULL;


NTSTATUS(NTAPI *NtReadVirtualMemory) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG NumberOfBytesToRead,
	OUT PULONG NumberOfBytesRead OPTIONAL
	) = NULL;

NTSTATUS(NTAPI *NtCreateSection) (
	OUT PHANDLE SectionHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  PLARGE_INTEGER MaximumSize OPTIONAL,
	IN  ULONG SectionPageProtection,
	IN  ULONG AllocationAttributes,
	IN  HANDLE FileHandle OPTIONAL
	) = NULL;
