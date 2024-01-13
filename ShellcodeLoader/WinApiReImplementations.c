#include <Windows.h>


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