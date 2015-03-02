/* P2P app UPNP Discovery.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 */

#ifndef _p2plib_upnp_h_
#define _p2plib_upnp_h_

#include "BcmP2PAPI.h"

int p2papp_sd_register_upnp_allsvcs(void);
int p2papp_sd_unregister_upnp_allsvcs(void);
void p2papp_sd_upnp_print_information(BCMP2P_UINT8* dst_str,
	BCMP2P_UINT32 dst_str_size, BCMP2P_UINT8* resp_data, BCMP2P_UINT32 resp_data_size);
BCMP2P_STATUS p2papp_sd_upnp_CreateListOfQueries(BCMP2P_UINT8** svcQueryEntries,
	BCMP2P_UINT32* svcQueryListSize);

#endif /* _p2plib_upnp_h_ */
