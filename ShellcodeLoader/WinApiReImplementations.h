#pragma once
#include <Windows.h>
// PEB / TEB
#include <winternl.h>

/*
* Todo: 
*	* GetProcAddressByHash
*	* GetModuleHandleByHash
*	* GetPEB
*/

DWORD runtime_hash(unsigned char* str);
LPVOID GetProcAddressByHash(HMODULE hModule, DWORD function_hash);
HMODULE GetModuleHandleByHash(DWORD module_hash);
PVOID MoveMemoryReImpl(PVOID dest, const PVOID src, SIZE_T len);






#if defined( _WIN64 )  
#define PEBOffset 0x60  
#define LdrOffset 0x18  
#define ListOffset 0x10  
PPEB getPEB(void) {
	return (PPEB)__readgsqword(PEBOffset);
}

#elif defined( _WIN32 )  
#define PEBOffset 0x30  
#define LdrOffset 0x0C  
#define ListOffset 0x0C
PPEB getPEB(void) {
	return  (PPEB)__readfsdword(PEBOffset);
}
#endif  