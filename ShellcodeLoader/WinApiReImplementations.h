#pragma once
#include <Windows.h>

/*
* Todo: 
*	* GetProcAddressByHash
*	* GetModuleHandleByHash
*	* GetPEB
*/

PVOID MoveMemoryReImpl(PVOID dest, const PVOID src, SIZE_T len);