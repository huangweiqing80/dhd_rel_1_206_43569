/* P2P APP persistent credentials support.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2papp_persist.h,v 1.3 2010-12-16 07:09:59 $
 */

#ifndef _P2PAPP_PERSISTENT_H_
#define _P2PAPP_PERSISTENT_H_

#ifdef __cplusplus
extern "C" {
#endif
/*
 * This module provides the API for saving and restoring persistent credentials.
 * The implementation of these functions depends on the availability of 
 * non-volatile storage on the target device (eg. file I/O, FLASH, registry, etc.).
 */

/* save persistent credentials */
BCMP2P_BOOL p2papp_persist_save(BCMP2P_PERSISTENT *persist);

/* delete presistent credentials specified by address */
BCMP2P_BOOL p2papp_persist_delete(BCMP2P_ETHER_ADDR *addr);

/* delete all persistent credentials */
BCMP2P_BOOL p2papp_persist_delete_all(void);

/* find persistent credentials specified by address */
BCMP2P_PERSISTENT *p2papp_persist_find_addr(BCMP2P_ETHER_ADDR *addr,
	BCMP2P_PERSISTENT *persist);

/* find persistent credentials  specified by ssid */
BCMP2P_PERSISTENT *p2papp_persist_find_ssid(char *ssid,
	BCMP2P_PERSISTENT *persist);

/* find a Go SSID if we created one */
	const char *p2papp_persist_get_go_ssid(void);
/* save a created Go SSID */
	BCMP2P_BOOL p2papp_persist_save_go_ssid(const char *ssid);

#ifdef __cplusplus
}
#endif

#endif /* _P2PAPP_PERSISTENT_H_ */
