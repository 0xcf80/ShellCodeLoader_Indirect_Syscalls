#!/usr/bin/env python
# encoding: utf-8

dlls = [
    'ntdll'
]

functions = [
    'NtAllocateVirtualMemory',
	'NtProtectVirtualMemory',
	'NtCreateThreadEx',
	'NtWaitForSingleObject'
]

def hash_djb2(s):                                                                                                                                
    hash = 5381
    for x in s:
        hash = (( hash << 5) + hash) + ord(x)
    return hash & 0xFFFFFFFF

def print_hash(s):
    print("string: {}, hash: {}".format(s,hex(hash_djb2(s))))

def main():
    for dll in dlls:
        print_hash(dll)
    
    for function in functions: 
        print_hash(function)

if __name__ == '__main__':
    main()