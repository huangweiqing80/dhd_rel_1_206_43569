#ifndef _CAPDLIB_H_
#define _CAPDLIB_H_

#include "BCMP2PAPI.h"
#include "wfd_capd.h"

typedef struct capdlib_instance_s {
	BCMP2PHandle p2p_handle;

	WFDCAPD_BOOL avl_for_sess;
} capdlib_instance_t;

#endif  /* _CAPDLIB_H_ */
