/*
 * wl arpoe command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_arpoe.c 458728 2014-02-27 18:15:25Z $
 */

#ifdef WIN32
#include <windows.h>
#endif

#include <wlioctl.h>


/* Because IL_BIGENDIAN was removed there are few warnings that need
 * to be fixed. Windows was not compiled earlier with IL_BIGENDIAN.
 * Hence these warnings were not seen earlier.
 * For now ignore the following warnings
 */
#ifdef WIN32
#pragma warning(push)
#pragma warning(disable : 4244)
#pragma warning(disable : 4761)
#endif

#include <bcmutils.h>
#include <bcmendian.h>
#include "wlu_common.h"
#include "wlu.h"

static cmd_func_t wl_arp_stats;

static cmd_t wl_arpoe_cmds[] = {
	{ "arp_ol", wl_offload_cmpnt, WLC_GET_VAR, WLC_SET_VAR,
	"Get/Set arp offload components"},
	{ "arp_peerage", wl_varint, WLC_GET_VAR, WLC_SET_VAR,
	"Get/Set age of the arp entry in minutes"},
	{ "arp_table_clear", wl_var_void, -1, WLC_SET_VAR,
	"Clear arp cache"},
	{ "arp_hostip", wl_hostip, WLC_GET_VAR, WLC_SET_VAR,
	"Add a host-ip address or display them"},
	{ "arp_hostip_clear", wl_var_void, -1, WLC_SET_VAR,
	"Clear all host-ip addresses"},
	{ "arp_stats", wl_arp_stats, WLC_GET_VAR, -1,
	"Display ARP offload statistics"},
	{ "arp_stats_clear", wl_var_void, -1, WLC_SET_VAR,
	"Clear ARP offload statistics"},
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_arpoe_module_init(void)
{
	/* get the global buf */
	buf = wl_get_buf();

	/* register arpoe commands */
	wl_module_cmds_register(wl_arpoe_cmds);
}

static int
wl_arp_stats(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	struct arp_ol_stats_t *arpstats;

	if (!*++argv) {
		/* Get */
		void *ptr = NULL;

		if ((ret = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return ret;
		arpstats = (struct arp_ol_stats_t *)ptr;
		printf("host_ip_entries = %d\n", dtoh32(arpstats->host_ip_entries));
		printf("host_ip_overflow = %d\n", dtoh32(arpstats->host_ip_overflow));
		printf("arp_table_entries = %d\n", dtoh32(arpstats->arp_table_entries));
		printf("arp_table_overflow = %d\n", dtoh32(arpstats->arp_table_overflow));
		printf("host_request = %d\n", dtoh32(arpstats->host_request));
		printf("host_reply = %d\n", dtoh32(arpstats->host_reply));
		printf("host_service = %d\n", dtoh32(arpstats->host_service));
		printf("peer_request = %d\n", dtoh32(arpstats->peer_request));
		printf("peer_request_drop = %d\n", dtoh32(arpstats->peer_request_drop));
		printf("peer_reply = %d\n", dtoh32(arpstats->peer_reply));
		printf("peer_reply_drop = %d\n", dtoh32(arpstats->peer_reply_drop));
		printf("peer_service = %d\n", dtoh32(arpstats->peer_service));
		printf("host_ip_entries = %d\n", dtoh32(arpstats->host_ip_entries));
	} else
		printf("Cannot set arp stats, use 'wl arp_stats_clear' to clear the counters\n");

	return 0;
}
