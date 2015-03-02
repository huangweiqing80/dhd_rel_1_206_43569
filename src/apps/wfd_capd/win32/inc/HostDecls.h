#ifndef __HOSTDECLS_H__
#define __HOSTDECLS_H__

#include <Windows.h>

#define MEMZERO		ZeroMemory
#define MEMCPY		CopyMemory
#define MEMMOVE		MoveMemory
#define MALLOC(X)	HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (X))
#define FREE(X)		{ if(X) { HeapFree(GetProcessHeap(), 0, X); X = NULL ; } }
#define ASSERT(X)	{ if(!(X)) { DebugBreak(); } }

#endif /* __HOSTDECLS_H__ */
