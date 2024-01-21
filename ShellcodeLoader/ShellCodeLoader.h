#pragma once
# include <Windows.h>
#include <stdio.h>
// PEB/TEB
#include <winternl.h>
// https://stackoverflow.com/questions/1941307/debug-print-macro-in-c
#define DEBUG

// Debug statements
#ifdef DEBUG
#define DEBUG_PRINT(...) fprintf( stderr, __VA_ARGS__ ); 
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif
#define MAX_DLL_NAME_LENGTH 256;
typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    /*_ACTIVATION_CONTEXT* EntryPointActivationContext;*/
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;
/* 
* Structure to hold information about our syscalls
*/
typedef struct _SYSCALL_INFO_ENTRY {
	LPVOID pSyscall;	 // pointer to syscall instruction
	DWORD syscallId;	 // ID of the syscall
	DWORD functionHash; // unused atm, for future use
} SYSCALL_INFO_ENTRY, *PSYSCALL_INFO_ENTRY;

// see populate_syscall_table() for info on how to add more syscalls
typedef struct SYSCALL_INFO_TABLE {
	SYSCALL_INFO_ENTRY NtAllocateVirtualMemory;
	SYSCALL_INFO_ENTRY NtProtectVirtualMemory;
	SYSCALL_INFO_ENTRY NtCreateThreadEx;
	SYSCALL_INFO_ENTRY NtWaitForSingleObject;
} SYSCALL_INFO_TABLE, * PSYSCALL_INFO_TABLE;

