#pragma once
#include <Windows.h>

/*
* Todo: 
*	* GetProcAddressByHash
*	* GetModuleHandleByHash
*	* GetPEB
*/

DWORD runtime_hash(unsigned char* str);
LPVOID GetProcAddressByHash(HMODULE hModule, DWORD function_hash);
PVOID MoveMemoryReImpl(PVOID dest, const PVOID src, SIZE_T len);