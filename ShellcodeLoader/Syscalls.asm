; Based on: https://github.com/am0nsec/HellsGate/blob/master/HellsGate/hellsgate.asm
; But use indirect instead of direct syscalls


.data
	wSystemCall DWORD 000h
	; LPVOID not valid in asm context
	pSyscall QWORD 0h

.code 
	; save the systemcall into variable (.data)
	; arg0: Syscall ID
	; arg1: pointer to syscall instruction
	; see https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions
	PrepareSyscall PROC
		mov wSystemCall, 000h
		; DWORD
		mov wSystemCall, ecx
		mov pSyscall, 000h
		; Pointer
		mov pSyscall, rdx
		ret
	PrepareSyscall ENDP

	; execute syscall
	DoIndirectSyscall PROC
		mov r10, rcx
		mov eax, wSystemCall
		; https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls/blob/main/CT_Indirect_Syscalls/CT_Indirect_Syscalls/syscalls.asm#L19C5-L19C51
		jmp QWORD PTR [pSyscall]
		
	DoIndirectSyscall ENDP
end