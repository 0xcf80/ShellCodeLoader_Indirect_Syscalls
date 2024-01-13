# ShellCodeLoader_Indirect_Syscalls
Shellcode Loader using indirect syscalls

Highly inspired (read: stolen) from the following projects:
* BokuLoader: https://github.com/boku7/BokuLoader/tree/main
* HellsGate: https://github.com/am0nsec/HellsGate/tree/master

Make sure to also read the following article by MalwareTech: https://malwaretech.com/2023/12/an-introduction-to-bypassing-user-mode-edr-hooks.html

Created during my preperation for CRTO2 (https://training.zeropointsecurity.co.uk/courses/red-team-ops-ii). Will eventually be used as a basis to create a User Defined Reflective Loader for Cobalt Strike (see https://www.cobaltstrike.com/blog/user-defined-reflective-loader-udrl-update-in-cobalt-strike-4-5). I decided to create a standalone shellcode loader, as this is simply easier to debug and does not need a Cobalt Strike license to play around. 

At a high level the loader re-implements HellsGate but uses indirect instead of direct syscalls to make the Callstack look less suspcicious. No secrets in here and nothing new. I just wanted to implement the stuff by myself ;)

# TBD
* replace GetModuleHandle, GetProcAddress \w custom implementations
* API Hashing
* more sophisticated shellcode loading routines
* probably more
