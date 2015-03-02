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
 * $Id: p2papp_persist_mem.c,v 1.1 2011-02-09 18:02:34 $
 */

/* Implements persistent credentials support using memory */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "p2plib_int.h"
#include "p2plib_osl.h"
#include "BcmP2PAPI.h"

struct persist_list {
	BCMP2P_PERSISTENT	persist;
	struct persist_list*	prev;
	struct persist_list*	next;
};

static int persist_count = 0;
static struct persist_list* persist_head = NULL;

BCMP2P_BOOL p2papp_persist_save(BCMP2P_PERSISTENT *persist)
{
	struct persist_list *new_persist;

	if (persist == NULL)
		return BCMP2P_FALSE;

	new_persist = (struct persist_list *)P2PAPI_MALLOC(sizeof(struct persist_list));
	if (new_persist == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"No memory for new persistent group\n"));
		return BCMP2P_FALSE;
	}

	memcpy((void *)&new_persist->persist, persist, sizeof(BCMP2P_PERSISTENT));
	new_persist->next = NULL;
	new_persist->prev = NULL;

	if (persist_head == NULL)
		persist_head = new_persist;
	else {
		struct persist_list *persistp = persist_head;

		while (persistp->next)
			persistp = persistp->next;

		persistp->next = new_persist;
		new_persist->prev = persistp;
	}

	persist_count++;

	return BCMP2P_TRUE;
}

BCMP2P_BOOL p2papp_persist_delete(BCMP2P_ETHER_ADDR *addr)
{
	struct persist_list *persistp;

	if (addr == NULL || persist_head == NULL)
		return BCMP2P_FALSE;

	persistp = persist_head;
	while (persistp) {
		if (memcmp(&persistp->persist.peer_dev_addr,
			addr, sizeof(BCMP2P_ETHER_ADDR)) == 0)
		break;
		persistp = persistp->next;
	}

	/* Not found */
	if (persistp == NULL)
		return BCMP2P_FALSE;

	/* Found */
	if (persistp->next)
		persistp->next->prev = persistp->prev;
	if (persistp->prev)
		persistp->prev->next = persistp->next;

	P2PAPI_FREE(persistp);
	persist_count--;

	return BCMP2P_TRUE;
}

BCMP2P_BOOL p2papp_persist_delete_all(void)
{
	struct persist_list *persistp;

	while (persist_head) {
		persistp = persist_head;
		persist_head = persist_head->next;
		P2PAPI_FREE(persistp);
	}

	persist_count = 0;
	persist_head = NULL;

	return BCMP2P_TRUE;
}

BCMP2P_PERSISTENT *p2papp_persist_find_addr(BCMP2P_ETHER_ADDR *addr,
	BCMP2P_PERSISTENT *persist)
{
	struct persist_list *persistp;

	if (addr == NULL || persist == NULL || persist_head == NULL)
		return 0;

	persistp = persist_head;
	while (persistp) {
		if (memcmp(persistp->persist.peer_dev_addr.octet,
			addr, sizeof(BCMP2P_ETHER_ADDR)) == 0)
		break;
		persistp = persistp->next;
	}

	/* Not found */
	if (persistp == NULL)
		return 0;

	/* Found */
	memcpy((void *)persist, &persistp->persist, sizeof(BCMP2P_PERSISTENT));

	return persist;
}

BCMP2P_PERSISTENT *p2papp_persist_find_ssid(char *ssid,
	BCMP2P_PERSISTENT *persist)
{
	struct persist_list *persistp;

	if (ssid == NULL || persist == NULL || persist_head == NULL)
		return 0;

	persistp = persist_head;
	while (persistp) {
		if (memcmp(&persistp->persist.ssid,
			ssid, sizeof(persistp->persist.ssid)) == 0)
		break;
		persistp = persistp->next;
	}

	/* Not found */
	if (persistp == NULL)
		return 0;

	/* Found */
	memcpy((void *)persist, &persistp->persist, sizeof(BCMP2P_PERSISTENT));

	return persist;
}
