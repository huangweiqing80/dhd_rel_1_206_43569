/*
 * wl ndoe command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_ndoe.c 458728 2014-02-27 18:15:25Z $
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

static cmd_func_t wl_ndstatus, wl_solicitipv6, wl_remoteipv6;

static cmd_t wl_ndoe_cmds[] = {
	{ "nd_hostip", wl_hostipv6, WLC_GET_VAR, WLC_SET_VAR,
	"Add a local host-ipv6 address or display them"},
	{ "nd_solicitip", wl_solicitipv6, WLC_GET_VAR, WLC_SET_VAR,
	"Add a local host solicit ipv6 address or display them"},
	{ "nd_remoteip", wl_remoteipv6, WLC_GET_VAR, WLC_SET_VAR,
	"Add a local remote ipv6 address or display them"},
	{ "nd_status", wl_ndstatus, WLC_GET_VAR, -1,
	"Displays Neighbor Discovery Status"},
	{ "nd_hostip_clear", wl_var_void, -1, WLC_SET_VAR,
	"Clear all host-ip addresses"},
	{ "nd_macaddr", wl_iov_mac, WLC_GET_VAR, WLC_SET_VAR,
	"Get/set the MAC address for offload" },
	{ "nd_status_clear", wl_var_void, -1, WLC_SET_VAR,
	"Clear neighbor discovery status"},
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_ndoe_module_init(void)
{
	(void)g_swap;

	/* get the global buf */
	buf = wl_get_buf();

	/* register ndoe commands */
	wl_module_cmds_register(wl_ndoe_cmds);
}

static int
wl_ndstatus(void *wl, cmd_t *cmd, char **argv)
{
	int ret = 0;
	struct nd_ol_stats_t *nd_stats;

	if (!*++argv) {
	/* Get */
	void *ptr = NULL;

		if ((ret = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return ret;

		nd_stats = (struct nd_ol_stats_t *)ptr;

		printf("host_ip_entries %d\r\n", nd_stats->host_ip_entries);
		printf("host_ip_overflow %d\r\n", nd_stats->host_ip_overflow);
		printf("peer_request %d\r\n", nd_stats->peer_request);
		printf("peer_request_drop %d\r\n", nd_stats->peer_request_drop);
		printf("peer_reply_drop %d\r\n", nd_stats->peer_reply_drop);
		printf("peer_service %d\r\n", nd_stats->peer_service);
	} else {
		printf("Cannot set nd stats\n");
	}

	return 0;
}

/*
 * If a solicit IP address is given, add it
 * e.g. "wl nd_solicitip fe00:0:0:0:0:290:1fc0:18c0 ".
 * If no address is given, dump all the addresses.
 */
static int
wl_solicitipv6(void *wl, cmd_t *cmd, char **argv)
{
	int ret, i;
	struct ipv6_addr ipa_set, *ipa_get, null_ipa;
	uint16 *ip_addr;
	if (!*++argv) {
		/* Get */
		void *ptr = NULL;

		if ((ret = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return ret;

		ip_addr = (uint16*)ptr;
		memset(null_ipa.addr, 0, IPV6_ADDR_LEN);
		for (ipa_get = (struct ipv6_addr *)ptr;
			 memcmp(null_ipa.addr, ipa_get->addr, IPV6_ADDR_LEN) != 0;
			 ipa_get++) {
			/* Print ipv6 Addr */
			for (i = 0; i < 8; i++) {
				printf("%x", ntoh16(ip_addr[i]));
				if (i < 7)
					printf(":");
			}
			printf("\r\n");

			ip_addr += 8;
		}
	} else {
		/* Add */
		if (!wl_atoipv6(*argv, &ipa_set))
			return BCME_USAGE_ERROR;

		/* we add one ip-addr at a time */
		return wlu_var_setbuf(wl, cmd->name, &ipa_set, IPV6_ADDR_LEN);
	}
	return ret;
}

/*
 * If a remote IP address is given, add it
 * e.g. "wl nd_remoteip fe00:0:0:0:0:290:1fc0:18c0 ".
 * If no address is given, dump the addresses.
 */
static int
wl_remoteipv6(void *wl, cmd_t *cmd, char **argv)
{
	int ret, i;
	struct ipv6_addr ipa_set, *ipa_get, null_ipa;
	uint16 *ip_addr;
	if (!*++argv) {
		/* Get */
		void *ptr = NULL;

		if ((ret = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return ret;

		ip_addr = (uint16*)ptr;
		memset(null_ipa.addr, 0, IPV6_ADDR_LEN);
		for (ipa_get = (struct ipv6_addr *)ptr;
			 memcmp(null_ipa.addr, ipa_get->addr, IPV6_ADDR_LEN) != 0;
			 ipa_get++) {
			/* Print ipv6 Addr */
			for (i = 0; i < 8; i++) {
				printf("%x", ntoh16(ip_addr[i]));
				if (i < 7)
					printf(":");
			}
			printf("\r\n");

			ip_addr += 8;
		}
	} else {
		/* Add */
		if (!wl_atoipv6(*argv, &ipa_set))
			return BCME_USAGE_ERROR;

		/* we add one ip-addr at a time */
		return wlu_var_setbuf(wl, cmd->name, &ipa_set, IPV6_ADDR_LEN);
	}
	return ret;
}
