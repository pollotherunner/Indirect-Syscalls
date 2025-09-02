struct Function {
	int Ssn;
	uintptr_t FuncAddr;
	uintptr_t SyscallAddr;
};


namespace Funcs {


	void Xor(unsigned char* Buffer, size_t Size, unsigned char Key) {

		for (size_t i = 0; i < Size; i++) {
			Buffer[i] ^= Key;
		}

	}

	void SetupAsmVars(uintptr_t SyscallsAddr, DWORD SyscallsNumber, uintptr_t* SyscallAddrToChange) {

		*SyscallAddrToChange = SyscallsAddr;

		SSN = SyscallsNumber;

	}

	uintptr_t GetSyscall(uintptr_t Addr) {

		unsigned char* bytes = (unsigned char*)Addr;

		uintptr_t SyscallAddr = NULL;

		for (int i = 0; i < 0x20; i++)
		{

			if (i + 1 < 0x20) {

				if (bytes[i] == 0x0F && bytes[i + 1] == 0x05) {

					SyscallAddr = Addr + i;

					return SyscallAddr;
				}
			}

		}

		return NULL;
	}

	Function GetFunction(const char* FuncNameToFind) {

		Function RetFunc = { 0, 0 };

		HMODULE Ntdll = GetModuleHandleA("ntdll.dll");

		if (!Ntdll) {
			Ntdll = LoadLibraryA("ntdll.dll");

			if (!Ntdll) return { 0, 0 };
		}

		uintptr_t Base = (uintptr_t)Ntdll;

		IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)Base;

		if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return { 0, 0 };

		IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)(Base + DosHeader->e_lfanew);

		IMAGE_EXPORT_DIRECTORY* ExportDir =
			(IMAGE_EXPORT_DIRECTORY*)(Base + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		DWORD* Addresses = (DWORD*)(Base + ExportDir->AddressOfFunctions);
		DWORD* Names = (DWORD*)(Base + ExportDir->AddressOfNames);
		WORD* Ordinals = (WORD*)(Base + ExportDir->AddressOfNameOrdinals);

		for (DWORD i = 0; i < ExportDir->NumberOfNames; i++) {

			const char* FuncName = (const char*)(Base + Names[i]);

			if (strcmp(FuncName, FuncNameToFind) != 0) continue;

			uintptr_t FuncAddr = Base + Addresses[Ordinals[i]];

			unsigned char* P = (unsigned char*)FuncAddr;

			for (int j = 0; j < 8; j++) {

				if (*(P + j) == 0xB8) {
					RetFunc.FuncAddr = FuncAddr;
					RetFunc.Ssn = *(int*)(P + j + 1);
					RetFunc.SyscallAddr = GetSyscall(FuncAddr);
					return RetFunc;
				}
			}
		}

		return { 0, 0 };
	}
}

namespace Nt {

	bool WaitForSingleObjectCaller(HANDLE Handle, PLARGE_INTEGER Timeout = nullptr, BOOLEAN Alertable = FALSE) {

		Function NtWaitForSingleObject = Funcs::GetFunction("NtWaitForSingleObject");

		Funcs::SetupAsmVars(NtWaitForSingleObject.SyscallAddr, NtWaitForSingleObject.Ssn, &NtWaitForSingleObjectSyscall);

		NTSTATUS Status = NtWaitForSingleObjectIndirect(Handle,Alertable,Timeout);

		return NT_SUCCESS(Status);
	}

	HANDLE CreateThreadCaller(HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ACCESS_MASK DesiredAccess = THREAD_ALL_ACCESS, ULONG CreateFlags = 0, SIZE_T StackSize = 0, SIZE_T MaximumStackSize = 0, PVOID AttributeList = nullptr) {

		Function NtCreateThreadEx = Funcs::GetFunction("NtCreateThreadEx");

		Funcs::SetupAsmVars(NtCreateThreadEx.SyscallAddr, NtCreateThreadEx.Ssn, &NtCreateThreadExSyscall);

		HANDLE ThreadHandle = nullptr;

		NTSTATUS Status = NtCreateThreadExIndirect(&ThreadHandle,DesiredAccess,nullptr,ProcessHandle,StartRoutine,Argument,CreateFlags,0,StackSize,MaximumStackSize,AttributeList);

		if (!NT_SUCCESS(Status)) {

			return nullptr;
		}

		return ThreadHandle;
	}

	uintptr_t VirtualAllocCaller(SIZE_T Size, ULONG Protect, ULONG AllocationType = MEM_COMMIT | MEM_RESERVE) {

		Function NtAllocateVirtualMemory = Funcs::GetFunction("NtAllocateVirtualMemory");

		Funcs::SetupAsmVars(NtAllocateVirtualMemory.SyscallAddr, NtAllocateVirtualMemory.Ssn, &NtAllocateVirtualMemorySyscall);

		PVOID BaseAddress = nullptr;

		SIZE_T RegionSize = Size;

		NTSTATUS Status = NtAllocateVirtualMemoryIndirect(GetCurrentProcess(),&BaseAddress,0,&RegionSize,AllocationType,Protect);

		if (!NT_SUCCESS(Status)) {

			return 0;
		}

		return reinterpret_cast<uintptr_t>(BaseAddress);
	}

	/*HANDLE OpenProcessCaller(DWORD Pid, ACCESS_MASK AccessMask) {

	Function NtOpenProcess = Funcs::GetFunction("NtOpenProcess");

	Funcs::SetupAsmVars(NtOpenProcess.SyscallAddr, NtOpenProcess.Ssn, &NtOpenProcessSyscall);

	HANDLE PHandle = nullptr;
	CLIENT_ID ClientId = { (HANDLE)Pid, 0 };
	OBJECT_ATTRIBUTES ObjAttributes{ 0 };

	NTSTATUS Status = NtOpenProcessIndirect(&PHandle, AccessMask, &ObjAttributes, &ClientId);

	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

	return PHandle;
}*/

/*DWORD GetProcessPid(const wchar_t* ProcessName) {
	Function NtQuerySystemInformation = Funcs::GetFunction("NtQuerySystemInformation");

	Funcs::SetupAsmVars(NtQuerySystemInformation.SyscallAddr, NtQuerySystemInformation.Ssn,&NtQuerySystemInformationSyscall);

	ULONG BufferSize = 0x10000;
	BYTE* Buffer = new BYTE[BufferSize];
	NTSTATUS Status;

	while ((Status = NtQuerySystemInformationIndirect(
		SystemProcessInformation,
		Buffer,
		BufferSize,
		&BufferSize
	)) == STATUS_INFO_LENGTH_MISMATCH) {
		delete[] Buffer;
		Buffer = new BYTE[BufferSize];
	}

	if (!NT_SUCCESS(Status)) {
		delete[] Buffer;
		return 0;
	}

	PSYSTEM_PROCESS_INFORMATION Spi = (PSYSTEM_PROCESS_INFORMATION)Buffer;

	while (true) {

		if (Spi->ImageName.Buffer && _wcsicmp(Spi->ImageName.Buffer, ProcessName) == 0) {
			DWORD Pid = (DWORD)(uintptr_t)Spi->UniqueProcessId;
			delete[] Buffer;
			return Pid;
		}

		if (Spi->NextEntryOffset == 0)
			break;

		Spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)Spi + Spi->NextEntryOffset);
	}

	delete[] Buffer;
	return 0;
}

}*/

}




