#ifndef __HOSTDECLS_H__
#define __HOSTDECLS_H__

#include <stdlib.h>
#include <memory.h>

#define MEMCPY		memcpy
#define MEMZERO(p,sz)	memset(p, 0, sz)
#define MEMMOVE		memmove
#define MALLOC		malloc
#define FREE(X)		{ if (X) { free(X); X=NULL; } }
#define ASSERT(X)	

#endif /* __HOSTDECLS_H__ */
