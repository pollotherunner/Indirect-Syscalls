.code

EXTERN SSN:DWORD

;-----  NtOpenProcess Defs -------
;EXTERN NtOpenProcessSyscall:QWORD
;PUBLIC NtOpenProcessIndirect
;
;NtOpenProcessIndirect PROC
;    mov r10, rcx
;    mov eax, SSN
;    jmp QWORD PTR [NtOpenProcessSyscall]                    
;NtOpenProcessIndirect ENDP
;---------------------------------


; -----  NtQuerySystemInformation Defs -------
;EXTERN NtQuerySystemInformationSyscall:QWORD
;PUBLIC NtQuerySystemInformationIndirect
;
;NtQuerySystemInformationIndirect PROC
;    mov r10, rcx
;    mov eax, SSN
;    jmp QWORD PTR [NtQuerySystemInformationSyscall]                    
;NtQuerySystemInformationIndirect ENDP
; ---------------------------------------------

; -----  NtAllocateVirtualMemory Defs -------
EXTERN NtAllocateVirtualMemorySyscall:QWORD
PUBLIC NtAllocateVirtualMemoryIndirect

NtAllocateVirtualMemoryIndirect PROC
    mov r10, rcx
    mov eax, SSN
    jmp QWORD PTR [NtAllocateVirtualMemorySyscall]                    
NtAllocateVirtualMemoryIndirect ENDP
; ---------------------------------------------


;-----  NtCreateThreadEx Defs -------
EXTERN NtCreateThreadExSyscall:QWORD
PUBLIC NtCreateThreadExIndirect

NtCreateThreadExIndirect PROC
    mov r10, rcx
    mov eax, SSN
    jmp QWORD PTR [NtCreateThreadExSyscall]                    
NtCreateThreadExIndirect ENDP
;---------------------------------

;-----  NtWaitForSingleObject Defs -------
EXTERN NtWaitForSingleObjectSyscall:QWORD
PUBLIC NtWaitForSingleObjectIndirect

NtWaitForSingleObjectIndirect PROC
    mov r10, rcx
    mov eax, SSN
    jmp QWORD PTR [NtWaitForSingleObjectSyscall]                    
NtWaitForSingleObjectIndirect ENDP
;---------------------------------------

END

