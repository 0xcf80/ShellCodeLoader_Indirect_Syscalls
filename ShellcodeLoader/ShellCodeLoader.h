#pragma once
# include <Windows.h>
#include <stdio.h>

// https://stackoverflow.com/questions/1941307/debug-print-macro-in-c
#define DEBUG

// Debug statements
#ifdef DEBUG
#define DEBUG_PRINT(...) fprintf( stderr, __VA_ARGS__ ); 
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif

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

