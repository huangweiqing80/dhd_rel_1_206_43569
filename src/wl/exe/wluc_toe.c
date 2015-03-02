/*
 * wl toe command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_toe.c 458728 2014-02-27 18:15:25Z $
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

static cmd_func_t wl_toe_stats;

static cmd_t wl_toe_cmds[] = {
	{ "toe_ol", wl_offload_cmpnt, WLC_GET_VAR, WLC_SET_VAR,
	"Get/Set tcpip offload components"},
	{ "toe_stats", wl_toe_stats, WLC_GET_VAR, -1,
	"Display checksum offload statistics"},
	{ "toe_stats_clear", wl_var_void, -1, WLC_SET_VAR,
	"Clear checksum offload statistics"},
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_toe_module_init(void)
{
	/* get the global buf */
	buf = wl_get_buf();

	/* register toe commands */
	wl_module_cmds_register(wl_toe_cmds);
}

static int
wl_toe_stats(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	struct toe_ol_stats_t *toestats;

	if (!*++argv) {
		/* Get */
		void *ptr = NULL;

		if ((ret = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return ret;
		toestats = (struct toe_ol_stats_t *)ptr;
		printf("tx_summed = %d\n", dtoh32(toestats->tx_summed));
		printf("tx_iph_fill = %d\n", dtoh32(toestats->tx_iph_fill));
		printf("tx_tcp_fill = %d\n", dtoh32(toestats->tx_tcp_fill));
		printf("tx_udp_fill = %d\n", dtoh32(toestats->tx_udp_fill));
		printf("tx_icmp_fill = %d\n", dtoh32(toestats->tx_icmp_fill));
		printf("rx_iph_good = %d\n", dtoh32(toestats->rx_iph_good));
		printf("rx_iph_bad = %d\n", dtoh32(toestats->rx_iph_bad));
		printf("rx_tcp_good = %d\n", dtoh32(toestats->rx_tcp_good));
		printf("rx_tcp_bad = %d\n", dtoh32(toestats->rx_tcp_bad));
		printf("rx_udp_good = %d\n", dtoh32(toestats->rx_udp_good));
		printf("rx_udp_bad = %d\n", dtoh32(toestats->rx_udp_bad));
		printf("rx_icmp_good = %d\n", dtoh32(toestats->rx_icmp_good));
		printf("rx_icmp_bad = %d\n", dtoh32(toestats->rx_icmp_bad));
		printf("tx_tcp_errinj = %d\n", dtoh32(toestats->tx_tcp_errinj));
		printf("tx_udp_errinj = %d\n", dtoh32(toestats->tx_udp_errinj));
		printf("tx_icmp_errinj = %d\n", dtoh32(toestats->tx_icmp_errinj));
		printf("rx_tcp_errinj = %d\n", dtoh32(toestats->rx_tcp_errinj));
		printf("rx_udp_errinj = %d\n", dtoh32(toestats->rx_udp_errinj));
		printf("rx_icmp_errinj = %d\n", dtoh32(toestats->rx_icmp_errinj));
	} else
		printf("Cannot set toe stats, use 'wl toe_stats_clear' to clear the counters\n");

	return 0;
}
