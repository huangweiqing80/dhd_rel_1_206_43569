/*
 * wl traffic_mgmt command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_traffic_mgmt.c 458728 2014-02-27 18:15:25Z $
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

static cmd_func_t wl_trf_mgmt_config;
static cmd_func_t wl_trf_mgmt_filters_add;
static cmd_func_t wl_trf_mgmt_filters_addex;
static cmd_func_t wl_trf_mgmt_filters_remove;
static cmd_func_t wl_trf_mgmt_filters_removeex;
static cmd_func_t wl_trf_mgmt_filters_list;
static cmd_func_t wl_trf_mgmt_filters_clear;
static cmd_func_t wl_trf_mgmt_bandwidth;
static cmd_func_t wl_trf_mgmt_flags;
static cmd_func_t wl_trf_mgmt_stats;
static cmd_func_t wl_trf_mgmt_stats_clear;
static cmd_func_t wl_trf_mgmt_shaping_info;

static cmd_t wl_trf_mgmt_cmds[] = {
	{"trf_mgmt_config", wl_trf_mgmt_config, WLC_GET_VAR, WLC_SET_VAR,
	"Sets/gets traffic management configuration.\n"
	"\tUsage: wl trf_mgmt_config [<enable> \n"
	"\t                          [<host IP address> <host IP subnet mask> \n"
	"\t                           <downlink kbps> <uplink kbps> [<flags>]]] \n"
	"\tenable: 0 - Disable traffic management\n"
	"\t        1 - Enables traffic management (host IP arguments required)\n"
	"\tFlag values are the following:\n"
	"\t0x0001 : Add DSCP values to tx packets\n"
	"\t0x0002 : Disable traffic shaping...just do priority classification\n"
	"\nIf no arguments are entered, the current traffic management configuration \n"
	"is displayed.\n"
	"\ne.g. Configure traffic management and specify local ip addr. and bandwidth data:\n"
	"\nwl trf_mgmt_config 1 12.0.0.1 255.0.0.0 5000 650"},

	{"trf_mgmt_filters_add", wl_trf_mgmt_filters_add, -1, WLC_SET_VAR,
	"Adds a traffic management filter.\n"
	"\tUsage: wl trf_mgmt_filter_add [dst_port src_port prot priority]\n"
	"\tdst_port    : Destination TCP or UDP port \n"
	"\tsrc_port    : Source TCP or UDP port (0 - wildcard for any source port)\n"
	"\tprot        : L4 protocol (6 - TCP, 17 - UDP)\n"
	"\tpriority    : Priority value (see trf_mgmt_priority_values enum) \n"
	"\ne.g. Add a tcp wildcard filter:\n"
	"\nwl trf_mgmt_filters_add 80 0 6 2"},

	{"trf_mgmt_filters_addex", wl_trf_mgmt_filters_addex, -1, WLC_SET_VAR,
	"Adds a traffic management filter.\n"
	"\tUsage: wl trf_mgmt_filter_add flag [dst_port src_port prot priority]\n"
	"\tUsage: wl trf_mgmt_filter_add flag [dst_mac priority] \n"
	"\tFlag values are the following:\n"
	"\t0x0000 : filter on tcp/udp src/dst port\n"
	"\t0x0001 : filter on destination MAC address\n"
	"\t0x0010 : do not update the packet priority \n"
	"\t0x0020 : Tag packets as Favored\n"
	"\tdst_mac    : Destination MAC address \n"
	"\tdst_port    : Destination TCP or UDP port \n"
	"\tsrc_port    : Source TCP or UDP port (0 - wildcard for any source port)\n"
	"\tprot        : L4 protocol (6 - TCP, 17 - UDP)\n"
	"\tpriority    : Priority value (see trf_mgmt_priority_values enum) \n"
	"\ne.g. Add a tcp wildcard filter for all src/dst ports:\n"
	"\nwl trf_mgmt_filters_addex 0 0 0 6 2\n"
	"\ne.g. Add a dst mac address filter\n"
	"\nwl trf_mgmt_filters_addex 0x31 aa:bb:cc:dd:ee:ff 2"},

	{"trf_mgmt_filters_remove", wl_trf_mgmt_filters_remove, -1, WLC_SET_VAR,
	"Removes a traffic management filter.\n"
	"\tUsage: wl trf_mgmt_filter_remove [dst_port src_port prot]\n"
	"\tdst_port    : Destination TCP or UDP port \n"
	"\tsrc_port    : Source TCP or UDP port (0 - wildcard for any source port)\n"
	"\tprot        : L4 protocol (6 - TCP, 17 - UDP)\n"
	"\ne.g. Remove a tcp wildcard filter:\n"
	"\nwl trf_mgmt_filters_remove 80 0 6"},

	{"trf_mgmt_filters_removeex", wl_trf_mgmt_filters_removeex, -1, WLC_SET_VAR,
	"Removes a traffic management filter.\n"
	"\tUsage: wl trf_mgmt_filter_remove flag [dst_port src_port prot]\n"
	"\tUsage: wl trf_mgmt_filter_remove flag [dst_mac]\n"
	"\tFlag values are the following:\n"
	"\t0x0000 : filter on tcp/udp src/dst port\n"
	"\t0x0001 : filter on destination MAC address\n"
	"\t0x0010 : do not update the packet priority \n"
	"\t0x0020 : Tag packets as Favored\n"
	"\tdst_mac    : Destination MAC address \n"
	"\tdst_port    : Destination TCP or UDP port \n"
	"\tsrc_port    : Source TCP or UDP port (0 - wildcard for any source port)\n"
	"\tprot        : L4 protocol (6 - TCP, 17 - UDP)\n"
	"\ne.g. Remove a tcp wildcard filter:\n"
	"\nwl trf_mgmt_filters_removeex 0 80 0 6\n"
	"\nwl trf_mgmt_filters_removeex 0x31 00:90:4c:52:a8:83"},

	{"trf_mgmt_filters_list", wl_trf_mgmt_filters_list, WLC_GET_VAR, -1,
	"Lists all traffic management filters.\n"
	"\tUsage: wl trf_mgmt_filter_list"},

	{"trf_mgmt_filters_clear", wl_trf_mgmt_filters_clear, -1, WLC_SET_VAR,
	"Clears all traffic management filters.\n"
	"\tUsage: wl trf_mgmt_filters_clear"},

	{"trf_mgmt_bandwidth", wl_trf_mgmt_bandwidth, WLC_GET_VAR, WLC_SET_VAR,
	"Sets/gets traffic management bandwidth configuration.\n"
	"\tUsage: wl trf_mgmt_bandwidth \n"
	"\t          [downlink uplink min_tx_bk min_tx_be min_tx_vi\n"
	"\t                          [min_rx_b min_rx_be min_rx_vi]]\n"
	"\tdownlink   : downlink bandwidth (kbps)\n"
	"\tuplink     : uplink bandwidth (kbps)\n"
	"\tmin_tx_bk  : min. guaranteed tx bandwidth percentage for BK (kbps)\n"
	"\tmin_tx_be  : min. guaranteed tx bandwidth percentage for BE (kbps)\n"
	"\tmin_tx_vi  : min. guaranteed tx bandwidth percentage for VI (kbps)\n"
	"\n(min_tx_bo + min_tx_be + min_tx_vi) must equal 100.\n"
	"\tmin_rx_bk  : min. guaranteed rx bandwidth percentage for BK (kbps)\n"
	"\tmin_rx_be  : min. guaranteed rx bandwidth percentage for BE (kbps)\n"
	"\tmin_rx_vi  : min. guaranteed rx bandwidth percentage for VI (kbps)\n"
	"\n(min_rx_bk + min_rx_be + min_rx_vi) must equal 100."
	"\nIf no rx gandwidth arguments are entered, tx bandwidth is used for rx."
	"\nIf no arguments are entered, the current bandwidth configuration is displayed."},

	{"trf_mgmt_flags", wl_trf_mgmt_flags, WLC_GET_VAR, WLC_SET_VAR,
	"Sets/gets traffic management operational flags.\n"
	"\tUsage: wl trf_mgmt_flags [flags]\n\n"
	"\tFlag values are the following:\n"
	"\t0x0001 : Add DSCP values to tx packets\n"
	"\t0x0002 : Disable traffic shaping...just do priority classification\n"
	"\nIf no arguments are entered, the current operational flags are displayed."},

	{"trf_mgmt_stats", wl_trf_mgmt_stats, WLC_GET_VAR, -1,
	"Gets traffic management statistics.\n"
	"\tUsage: wl trf_mgmt_stats [index]\n"
	"\tindex : Queue index"},

	{"trf_mgmt_stats_clear", wl_trf_mgmt_stats_clear, -1, WLC_SET_VAR,
	"Clears traffic management statistics.\n"
	"\tUsage: wl trf_mgmt_stats_clear"},

	{"trf_mgmt_shaping_info", wl_trf_mgmt_shaping_info, WLC_GET_VAR, -1,
	"Gets traffic management shaping parameters.\n"
	"\tUsage: wl trf_mgmt_shaping_info [index]\n"
	"\tindex : Queue index"},
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_trf_mgmt_module_init(void)
{
	/* get the global buf */
	buf = wl_get_buf();

	/* register trf_mgmt commands */
	wl_module_cmds_register(wl_trf_mgmt_cmds);
}

/* Get/set traffic management configuration. */
static int
wl_trf_mgmt_config(void *wl, cmd_t *cmd, char **argv)
{
	uint		    argc = 0;
	uint32		    i;
	trf_mgmt_config_t   *ptrf_mgmt_config;
	uint8		    buf[sizeof(trf_mgmt_config_t)];
	int		    buf_len;
	char		    *endptr = NULL;
	int		    rc = -1;
	void		    *ptr = NULL;

	if (!*++argv) {
	   /*
	    * Get current traffic management configuration.
	    */
	    if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
		return rc;

	    ptrf_mgmt_config = (trf_mgmt_config_t *)ptr;

	    printf("Enabled                   : %d\n",
	        dtoh32(ptrf_mgmt_config->trf_mgmt_enabled));
	    printf("Host IP Address           : %s\n",
	        wl_iptoa((void *)&ptrf_mgmt_config->host_ip_addr));
	    printf("Host IP Subnet Mask       : %s\n",
	        wl_iptoa((void *)&ptrf_mgmt_config->host_subnet_mask));
	    printf("Downlink Bandwidth        : %d\n",
	        dtoh32(ptrf_mgmt_config->downlink_bandwidth));
	    printf("Uplink Bandwidth          : %d\n",
	        dtoh32(ptrf_mgmt_config->uplink_bandwidth));
	    printf("\n");

	    printf("Minimum Tx Bandwidth[BK]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_tx_bandwidth[0]));
	    printf("Minimum Tx Bandwidth[BE]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_tx_bandwidth[1]));
	    printf("Minimum Tx Bandwidth[VI]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_tx_bandwidth[2]));
	    printf("\n");

	    printf("Minimum Rx Bandwidth[BK]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_rx_bandwidth[0]));
	    printf("Minimum Rx Bandwidth[BE]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_rx_bandwidth[1]));
	    printf("Minimum Rx Bandwidth[VI]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_rx_bandwidth[2]));
	    printf("\n");

	    printf("Flags                     : 0x%04X\n",
	        dtoh32(ptrf_mgmt_config->flags));
	}
	else {
	    /* arg count */
	    while (argv[argc])
		argc++;

	    /* required	arguments */
	    if ((argc != 1) && (argc != 5) && (argc != 6)) {
		fprintf(stderr,	"Too few/many arguments	(require 1 or 5 or 6 , got %d)\n", argc);
		return BCME_USAGE_ERROR;
	    }

	    ptrf_mgmt_config = (trf_mgmt_config_t *)buf;
	    buf_len	     = sizeof(trf_mgmt_config_t);
	    memset((uint8 *)buf, 0, buf_len);

	    ptrf_mgmt_config->trf_mgmt_enabled = htod32((int32)strtol(*argv++, &endptr,	0));
	    if (*endptr	!= '\0') {
		return BCME_USAGE_ERROR;
	    }

	    if (argc > 1) {
		if (ptrf_mgmt_config->trf_mgmt_enabled)	{
		    if (!wl_atoip(*argv++, (void *)&ptrf_mgmt_config->host_ip_addr)) {
			return BCME_USAGE_ERROR;
		    }
		    if (!wl_atoip(*argv++, (void *)&ptrf_mgmt_config->host_subnet_mask)) {
			return BCME_USAGE_ERROR;
		    }
		    ptrf_mgmt_config->downlink_bandwidth =
		        htod32((int32)strtol(*argv++, &endptr, 0));
		    ptrf_mgmt_config->uplink_bandwidth =
		        htod32((int32)strtol(*argv++, &endptr, 0));

		    /*
		     * Zero-fill min bandwidth based. This will	cause the driver to use
		     * defult settings
		     */
		    for	(i = 0;	i < TRF_MGMT_MAX_PRIORITIES; i++) {
			ptrf_mgmt_config->min_tx_bandwidth[i] =	0;
			ptrf_mgmt_config->min_rx_bandwidth[i] =	0;
		    }

		    if (argc ==	6) {
			ptrf_mgmt_config->flags	= htod32((int32)strtol(*argv++,	&endptr, 0));
		    }
		} else {
		    return BCME_BADARG;
		}
	    }

	    rc = wlu_var_setbuf(wl, cmd->name, ptrf_mgmt_config, buf_len);
	}
	return rc;
}

/* Sets a traffic management filter. */
static int
wl_trf_mgmt_filters_add(void *wl, cmd_t *cmd, char **argv)
{
	uint                    argc = 0;
	trf_mgmt_filter_list_t  *ptrf_mgmt_filter_list;
	trf_mgmt_filter_t       *ptrf_mgmt_filter;
	uint8                   buf[sizeof(trf_mgmt_filter_list_t)];
	int                     buf_len;
	char                    *param;
	char                    *endptr = NULL;
	int                     rc = -1;

	(void)param;
	/* arg count */
	param = *++argv;
	while (argv[argc])
	    argc++;

	/* required arguments */
	if (argc != 4) {
	    fprintf(stderr, "Too few/many arguments (require %d, got %d)\n", 4, argc);
	    return BCME_USAGE_ERROR;
	}

	ptrf_mgmt_filter_list = (trf_mgmt_filter_list_t *)buf;
	buf_len               = sizeof(trf_mgmt_filter_list_t);
	memset((uint8 *)buf, 0, buf_len);

	ptrf_mgmt_filter_list->num_filters = 1;
	ptrf_mgmt_filter                   = &ptrf_mgmt_filter_list->filter[0];

	ptrf_mgmt_filter->dst_port = htod16((int16)strtol(*argv++, &endptr, 0));
	if (*endptr != '\0')
	    return BCME_USAGE_ERROR;

	ptrf_mgmt_filter->src_port = htod16((int16)strtol(*argv++, &endptr, 0));
	if (*endptr != '\0')
	    return BCME_USAGE_ERROR;

	ptrf_mgmt_filter->prot = htod16((int16)strtol(*argv++, &endptr, 0));
	if (*endptr != '\0')
	    return BCME_USAGE_ERROR;

	ptrf_mgmt_filter->priority = htod16((int16)strtol(*argv++, &endptr, 0));
	if (*endptr != '\0')
	    return BCME_USAGE_ERROR;

	rc = wlu_var_setbuf(wl, cmd->name, ptrf_mgmt_filter_list, buf_len);

	return rc;
}
/* Sets a traffic management filter L2/L3/L4 */
static int
wl_trf_mgmt_filters_addex(void *wl, cmd_t *cmd, char **argv)
{
	uint                    argc = 0;
	trf_mgmt_filter_list_t  *ptrf_mgmt_filter_list;
	trf_mgmt_filter_t       *ptrf_mgmt_filter;
	uint8                   buf[sizeof(trf_mgmt_filter_list_t)];
	int                     buf_len;
	char                    *param;
	char                    *endptr = NULL;
	int                     rc = -1;

	(void)param;
	(void)cmd;
	/* arg count */
	param = *++argv;
	while (argv[argc])
	    argc++;

	/* required arguments */
	if (argc < 3) {
		fprintf(stderr, "Too few arguments (require > 3  got %d)\n", argc);
		return BCME_USAGE_ERROR;
	}

	ptrf_mgmt_filter_list = (trf_mgmt_filter_list_t *)buf;
	buf_len               = sizeof(trf_mgmt_filter_list_t);
	memset((uint8 *)buf, 0, buf_len);

	ptrf_mgmt_filter_list->num_filters = 1;
	ptrf_mgmt_filter                   = &ptrf_mgmt_filter_list->filter[0];

	ptrf_mgmt_filter->flags = htod16((int16)strtol(*argv++, &endptr, 0));
	if (*endptr != '\0')
		return BCME_USAGE_ERROR;

	if (ptrf_mgmt_filter->flags & TRF_FILTER_MAC_ADDR) {

		if (argc != 3) {
			fprintf(stderr, "Too many arguments (require 3 got %d)\n", argc);
			return BCME_USAGE_ERROR;
		}

		if (!wl_ether_atoe(*argv++, &ptrf_mgmt_filter->dst_ether_addr))
			return BCME_USAGE_ERROR;

		ptrf_mgmt_filter->priority = htod16((int16)strtol(*argv++, &endptr, 0));
			if (*endptr != '\0')
				return BCME_USAGE_ERROR;
	} else {
		/* required arguments */
		if (argc != 5) {
			fprintf(stderr, "Too few/many arguments (require 5 got %d)\n", argc);
			return BCME_USAGE_ERROR;
		}

		ptrf_mgmt_filter->dst_port = htod16((int16)strtol(*argv++, &endptr, 0));
			if (*endptr != '\0')
				return BCME_USAGE_ERROR;

		ptrf_mgmt_filter->src_port = htod16((int16)strtol(*argv++, &endptr, 0));
			if (*endptr != '\0')
			    return BCME_USAGE_ERROR;

		ptrf_mgmt_filter->prot = htod16((int16)strtol(*argv++, &endptr, 0));
			if (*endptr != '\0')
			    return BCME_USAGE_ERROR;

		ptrf_mgmt_filter->priority = htod16((int16)strtol(*argv++, &endptr, 0));
			if (*endptr != '\0')
			    return BCME_USAGE_ERROR;
	}

	rc = wlu_var_setbuf(wl, "trf_mgmt_filters_add", ptrf_mgmt_filter_list, buf_len);

	return rc;
}

/* Removes a traffic management filter. */
static int
wl_trf_mgmt_filters_remove(void *wl, cmd_t *cmd, char **argv)
{
	uint                    argc = 0;
	trf_mgmt_filter_list_t  *ptrf_mgmt_filter_list;
	trf_mgmt_filter_t       *ptrf_mgmt_filter;
	uint8                   buf[sizeof(trf_mgmt_filter_list_t)];
	int                     buf_len;
	char                    *endptr = NULL;
	char                    *param;
	int                     rc = -1;

	(void)param;
	/* arg count */
	param = *++argv;
	while (argv[argc])
	    argc++;

	/* required arguments */
	if (argc != 3) {
	    fprintf(stderr, "Too few/many arguments (require %d, got %d)\n", 3, argc);
	    return BCME_USAGE_ERROR;
	}

	ptrf_mgmt_filter_list = (trf_mgmt_filter_list_t *)buf;
	buf_len               = sizeof(trf_mgmt_filter_list_t);

	memset((uint8 *)buf, 0, buf_len);

	ptrf_mgmt_filter_list->num_filters = 1;
	ptrf_mgmt_filter                   = &ptrf_mgmt_filter_list->filter[0];

	ptrf_mgmt_filter->dst_port = htod16((int16)strtol(*argv++, &endptr, 0));
	if (*endptr != '\0')
	    return BCME_USAGE_ERROR;
	ptrf_mgmt_filter->src_port = htod16((int16)strtol(*argv++, &endptr, 0));
	if (*endptr != '\0')
	    return BCME_USAGE_ERROR;
	ptrf_mgmt_filter->prot = htod16((int16)strtol(*argv++, &endptr, 0));
	if (*endptr != '\0')
	    return BCME_USAGE_ERROR;
	rc = wlu_var_setbuf(wl, cmd->name, ptrf_mgmt_filter_list, buf_len);

	return rc;
}

/* Removes a traffic management filter for L2/L3/L4 */
static int
wl_trf_mgmt_filters_removeex(void *wl, cmd_t *cmd, char **argv)
{
	uint                    argc = 0;
	trf_mgmt_filter_list_t  *ptrf_mgmt_filter_list;
	trf_mgmt_filter_t       *ptrf_mgmt_filter;
	uint8                   buf[sizeof(trf_mgmt_filter_list_t)];
	int                     buf_len;
	char                    *endptr = NULL;
	char                    *param;
	int                     rc = -1;

	(void)param;
	(void)cmd;
	/* arg count */
	param = *++argv;
	while (argv[argc])
	    argc++;

	/* required arguments */
	if (argc < 2) {
	    fprintf(stderr, "Too few/many arguments (require %d, got %d)\n", 2, argc);
	    return BCME_USAGE_ERROR;
	}

	ptrf_mgmt_filter_list = (trf_mgmt_filter_list_t *)buf;
	buf_len               = sizeof(trf_mgmt_filter_list_t);

	memset((uint8 *)buf, 0, buf_len);

	ptrf_mgmt_filter_list->num_filters = 1;
	ptrf_mgmt_filter                   = &ptrf_mgmt_filter_list->filter[0];

	ptrf_mgmt_filter->flags = htod16((int16)strtol(*argv++, &endptr, 0));
	if (*endptr != '\0') {
		return BCME_USAGE_ERROR;
	}
	if (ptrf_mgmt_filter->flags & TRF_FILTER_MAC_ADDR) {

		if (argc != 2) {
			fprintf(stderr, "Too many arguments (require 2 got %d)\n", argc);
			return BCME_USAGE_ERROR;
		}

		if (!wl_ether_atoe(*argv++, &ptrf_mgmt_filter->dst_ether_addr)) {
			return BCME_USAGE_ERROR;
		}

	} else {
		if (argc < 4) {
			fprintf(stderr, "Too few/many arguments (require %d, got %d)\n", 4, argc);
			return BCME_USAGE_ERROR;
		}
		ptrf_mgmt_filter->dst_port = htod16((int16)strtol(*argv++, &endptr, 0));
		if (*endptr != '\0')
		    return BCME_USAGE_ERROR;

		ptrf_mgmt_filter->src_port = htod16((int16)strtol(*argv++, &endptr, 0));
		if (*endptr != '\0')
		    return BCME_USAGE_ERROR;

		ptrf_mgmt_filter->prot = htod16((int16)strtol(*argv++, &endptr, 0));
		if (*endptr != '\0')
		    return BCME_USAGE_ERROR;
	}

	rc = wlu_var_setbuf(wl, "trf_mgmt_filters_remove", ptrf_mgmt_filter_list, buf_len);

	return rc;
}

/* lists the current traffic management filters. */
static int
wl_trf_mgmt_filters_list(void *wl, cmd_t *cmd, char **argv)
{
	trf_mgmt_filter_list_t  *ptrf_mgmt_filter_list;
	trf_mgmt_filter_t       *ptrf_mgmt_filter;
	uint                    i;
	int                     rc = -1;
	void                    *ptr = NULL;

	UNUSED_PARAMETER(argv);

	/*
	 * Get current traffic management filters.
	 */
	if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
	    return rc;

	ptrf_mgmt_filter_list = (trf_mgmt_filter_list_t *)ptr;

	printf("Number of filters : %d\n", dtoh32(ptrf_mgmt_filter_list->num_filters));

	for (i = 0; i < ptrf_mgmt_filter_list->num_filters; i++) {
	    ptrf_mgmt_filter = &ptrf_mgmt_filter_list->filter[i];

		if (ptrf_mgmt_filter->flags & TRF_FILTER_MAC_ADDR) {
			printf("\n");
			printf("Filter #%d\n", i);
			printf("Flags    : 0x%02x\n", dtoh32(ptrf_mgmt_filter->flags));
			printf("Dst EtherAddr    : %s\n",
				wl_ether_etoa(&ptrf_mgmt_filter->dst_ether_addr));
			printf("Priority : %d\n", dtoh32(ptrf_mgmt_filter->priority));
		} else {
			printf("\n");
			printf("Filter #%d\n", i);
			printf("Dst Port : %d\n", dtoh32(ptrf_mgmt_filter->dst_port));
			printf("Src Port : %d\n", dtoh32(ptrf_mgmt_filter->src_port));
			printf("Protocol : %d\n", dtoh32(ptrf_mgmt_filter->prot));
			printf("Flags    : 0x%02x\n", dtoh32(ptrf_mgmt_filter->flags));
			printf("Priority : %d\n", dtoh32(ptrf_mgmt_filter->priority));
		}
	}

	return rc;
}

/* Clears the traffic management filters. */
static int
wl_trf_mgmt_filters_clear(void *wl, cmd_t *cmd, char **argv)
{
	int rc = -1;

	UNUSED_PARAMETER(argv);

	rc = wlu_var_setbuf(wl, cmd->name, NULL, 0);

	return rc;
}

/*
 * Get/set traffic management bandwidth configuration. We support the ability to get/set just the
 * bandwidth parameters in the global trf_mgmt_config_t structure.
 */
static int
wl_trf_mgmt_bandwidth(void *wl, cmd_t *cmd, char **argv)
{
	uint                argc = 0;
	trf_mgmt_config_t   *ptrf_mgmt_config;
	uint8               buf[sizeof(trf_mgmt_config_t)];
	int                 buf_len;
	char                *endptr = NULL;
	int                 i, total_bandwidth;
	int                 rc = -1;
	void                *ptr = NULL;

	if (!*++argv) {
	   /*
	    * Get current traffic management bandwidth settings.
	    */
	    if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
		return rc;

	    ptrf_mgmt_config = (trf_mgmt_config_t *)ptr;

	    printf("Downlink Bandwidth        : %d\n",
	        dtoh32(ptrf_mgmt_config->downlink_bandwidth));
	    printf("Uplink Bandwidth          : %d\n",
	        dtoh32(ptrf_mgmt_config->uplink_bandwidth));
	    printf("\n");

	    printf("Minimum Tx Bandwidth[BK]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_tx_bandwidth[0]));
	    printf("Minimum Tx Bandwidth[BE]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_tx_bandwidth[1]));
	    printf("Minimum Tx Bandwidth[VI]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_tx_bandwidth[2]));
	    printf("\n");

	    printf("Minimum Rx Bandwidth[BK]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_tx_bandwidth[0]));
	    printf("Minimum Rx Bandwidth[BE]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_tx_bandwidth[1]));
	    printf("Minimum Rx Bandwidth[VI]  : %d\n",
	        dtoh32(ptrf_mgmt_config->min_tx_bandwidth[2]));
	}
	else {
	    /* arg count */
	    while (argv[argc])
		argc++;

	    /* required arguments */
	    if (argc < 5) {
		fprintf(stderr, "Too few/many arguments (require %d, got %d)\n", 5, argc);
		return BCME_USAGE_ERROR;
	    }

	    if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
		return rc;

	    ptrf_mgmt_config = (trf_mgmt_config_t *)buf;
	    buf_len          = sizeof(trf_mgmt_config_t);

	    memcpy(buf, ptr, buf_len);

	    ptrf_mgmt_config->downlink_bandwidth = htod32((int32)strtol(*argv++, &endptr, 0));
	    if (*endptr != '\0')
		return BCME_USAGE_ERROR;
	    ptrf_mgmt_config->uplink_bandwidth = htod32((int32)strtol(*argv++, &endptr, 0));
	    if (*endptr != '\0')
		return BCME_USAGE_ERROR;
	    for (i = 0, total_bandwidth = 0; i < TRF_MGMT_MAX_PRIORITIES; i++) {
		ptrf_mgmt_config->min_tx_bandwidth[i] =
		    htod32((int32)strtol(*argv++, &endptr, 0));

		if (*endptr != '\0')
		   return BCME_USAGE_ERROR;
		total_bandwidth += ptrf_mgmt_config->min_tx_bandwidth[i];
	    }

	    if (total_bandwidth != 100) {
		fprintf(stderr,
		    "Sum of gauranteed bandwidth levels must equal 100 (got %d)\n",
		    total_bandwidth);
		return BCME_BADARG;
	    }

	    if (argc > 5) {
		for (i = 0, total_bandwidth = 0; i < TRF_MGMT_MAX_PRIORITIES; i++) {
		    ptrf_mgmt_config->min_rx_bandwidth[i] =
		        htod32((int32)strtol(*argv++, &endptr, 0));

		    if (*endptr != '\0')
			return BCME_USAGE_ERROR;
		    total_bandwidth += ptrf_mgmt_config->min_rx_bandwidth[i];
		}

		if (total_bandwidth != 100) {
		    fprintf(stderr,
		        "Sum of gauranteed rx bandwidth levels must equal 100 (got %d)\n",
		        total_bandwidth);
		    return BCME_BADARG;
		}
	    } else {
		for (i = 0, total_bandwidth = 0; i < TRF_MGMT_MAX_PRIORITIES; i++) {
		    ptrf_mgmt_config->min_rx_bandwidth[i] = ptrf_mgmt_config->min_tx_bandwidth[i];
		}
	    }

	    rc = wlu_var_setbuf(wl, cmd->name, ptrf_mgmt_config, buf_len);
	}

	return rc;
}

/*
 * Get/set traffic management operational flags. We use this to change flags that
 * can't be set by GUI. This allows us to configure certain options that we may want to
 * enable/disable in the shipping product.
 */
static int
wl_trf_mgmt_flags(void *wl, cmd_t *cmd, char **argv)
{
	uint                argc = 0;
	uint32              flags;
	char                *endptr = NULL;
	int                 rc = -1;
	void                *ptr = NULL;

	if (!*++argv) {
	   /*
	    * Get current traffic management bandwidth settings.
	    */
	    if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
		return rc;

	    flags = *(uint32 *)ptr;

	    printf("Flags : 0x%04X\n", flags);
	}
	else {
	    /* arg count */
	    while (argv[argc])
		argc++;

	    /* required arguments */
	    if (argc != 1) {
		fprintf(stderr, "Too few/many arguments (require %d, got %d)\n", 1, argc);
		return BCME_USAGE_ERROR;
	    }

	    flags = htod32((int32)strtol(*argv++, &endptr, 0));
	    if (*endptr != '\0') {
		return BCME_USAGE_ERROR;
	    }
	    rc = wlu_var_setbuf(wl, cmd->name, &flags, sizeof(uint32));
	}

	return rc;
}

/* Print traffic management statistics. */
static void
wl_trf_mgmt_print_stats(void *ptr, uint index)
{
	trf_mgmt_stats_array_t  *ptrf_mgmt_statistics_array;
	trf_mgmt_stats_t        *ptrf_mgmt_statistics;

	ptrf_mgmt_statistics_array = (trf_mgmt_stats_array_t *)ptr;

	ptrf_mgmt_statistics = &ptrf_mgmt_statistics_array->tx_queue_stats[index];

	printf("Statistics for Tx Queue[%d]\n", index);
	printf("\n");
	printf("Num. packets processed : %d\n",
	       dtoh32(ptrf_mgmt_statistics->num_processed_packets));
	printf("Num. bytes processed   : %d\n",
	       dtoh32(ptrf_mgmt_statistics->num_processed_bytes));
	printf("Num. packets discarded : %d\n",
	       dtoh32(ptrf_mgmt_statistics->num_discarded_packets));

	ptrf_mgmt_statistics = &ptrf_mgmt_statistics_array->rx_queue_stats[index];

	printf("\n");
	printf("Statistics for Rx Queue[%d]\n", index);
	printf("\n");
	printf("Num. packets processed : %d\n",
	       dtoh32(ptrf_mgmt_statistics->num_processed_packets));
	printf("Num. bytes processed   : %d\n",
	       dtoh32(ptrf_mgmt_statistics->num_processed_bytes));
	printf("Num. packets discarded : %d\n",
	       dtoh32(ptrf_mgmt_statistics->num_discarded_packets));

	printf("\n");
}

/* Get traffic management statistics. */
static int
wl_trf_mgmt_stats(void *wl, cmd_t *cmd, char **argv)
{
	uint    argc = 0;
	uint    i;
	int     rc = -1;
	char    *endptr = NULL;
	void    *ptr = NULL;

	/*
	 * Get current traffic management statistics.
	 */
	if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
	    return rc;

	if (!*++argv) {
	    /*
	     * Print all of the current traffic management statistics.
	     */
	    for (i = 0; i < TRF_MGMT_MAX_PRIORITIES; i++) {
		wl_trf_mgmt_print_stats(ptr, i);
	    }
	}
	else {
	    /* arg count */
	    while (argv[argc])
		argc++;

	    /* required arguments */
	    if (argc != 1) {
		fprintf(stderr, "Too few/many arguments (require %d, got %d)\n", 1, argc);
		return BCME_USAGE_ERROR;
	    }

	    i = htod16((int16)strtol(*argv, &endptr, 0));
	    if (i >= TRF_MGMT_MAX_PRIORITIES) {
		fprintf(stderr, "Index must be < %d)\n", TRF_MGMT_MAX_PRIORITIES);
		return BCME_BADARG;
	    }

	    /* Print the current traffic management statistics for the specified queue index. */
	    wl_trf_mgmt_print_stats(ptr, i);
	}


	return rc;
}

/* Clears the traffic management statistics. */
static int
wl_trf_mgmt_stats_clear(void *wl, cmd_t *cmd, char **argv)
{
	int rc = -1;

	UNUSED_PARAMETER(argv);

	rc = wlu_var_setbuf(wl, cmd->name, NULL, 0);

	return rc;
}

/* Print traffic management shaping info. */
static void
wl_trf_mgmt_print_global_shaping_info(void *ptr)
{
	trf_mgmt_shaping_info_array_t   *ptrf_mgmt_shaping_info_array;
	trf_mgmt_global_info_t          *ptrf_mgmt_global_info;

	ptrf_mgmt_shaping_info_array = (trf_mgmt_shaping_info_array_t *)ptr;

	ptrf_mgmt_global_info = &ptrf_mgmt_shaping_info_array->tx_global_shaping_info;

	printf("Global shaping info. for Tx Queues\n");
	printf("\n");
	printf("Maximum bytes/second                      : %d\n",
	    ptrf_mgmt_global_info->maximum_bytes_per_second);
	printf("Maximum bytes/sampling period             : %d\n",
	    ptrf_mgmt_global_info->maximum_bytes_per_sampling_period);
	printf("Total bytes consumed per second           : %d\n",
	    ptrf_mgmt_global_info->total_bytes_consumed_per_second);
	printf("Total bytes consumed per sampling period  : %d\n",
	    ptrf_mgmt_global_info->total_bytes_consumed_per_sampling_period);
	printf("Unused bytes for current sampling period  : %d\n",
	    ptrf_mgmt_global_info->total_unused_bytes_per_sampling_period);

	printf("\n");

	ptrf_mgmt_global_info = &ptrf_mgmt_shaping_info_array->rx_global_shaping_info;

	printf("Global shaping info. for Rx Queues\n");
	printf("\n");
	printf("Maximum bytes/second                      : %d\n",
	    ptrf_mgmt_global_info->maximum_bytes_per_second);
	printf("Maximum bytes/sampling period             : %d\n",
	    ptrf_mgmt_global_info->maximum_bytes_per_sampling_period);
	printf("Total bytes consumed per second           : %d\n",
	    ptrf_mgmt_global_info->total_bytes_consumed_per_second);
	printf("Total bytes consumed per sampling period  : %d\n",
	    ptrf_mgmt_global_info->total_bytes_consumed_per_sampling_period);
	printf("Unused bytes for current sampling period  : %d\n",
	    ptrf_mgmt_global_info->total_unused_bytes_per_sampling_period);

	printf("\n");
}

static void
wl_trf_mgmt_print_shaping_info(void *ptr, uint index)
{
	trf_mgmt_shaping_info_array_t   *ptrf_mgmt_shaping_info_array;
	trf_mgmt_shaping_info_t         *ptrf_mgmt_shaping_info;

	ptrf_mgmt_shaping_info_array = (trf_mgmt_shaping_info_array_t *)ptr;

	ptrf_mgmt_shaping_info = &ptrf_mgmt_shaping_info_array->tx_queue_shaping_info[index];

	printf("Shaping info. for Tx Queue[%d]\n", index);
	printf("\n");
	printf("Gauranteed bandwidth percentage  : %d%%\n",
	    dtoh32(ptrf_mgmt_shaping_info->gauranteed_bandwidth_percentage));
	printf("Guaranteed bytes/second          : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->guaranteed_bytes_per_second));
	printf("Guaranteed bytes/sampling period : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->guaranteed_bytes_per_sampling_period));
	printf("Num. bytes produced per second   : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->num_bytes_produced_per_second));
	printf("Num. bytes consumed per second   : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->num_bytes_consumed_per_second));
	printf("Num. packets pending             : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->num_queued_packets));
	printf("Num. bytes pending               : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->num_queued_bytes));

	ptrf_mgmt_shaping_info = &ptrf_mgmt_shaping_info_array->rx_queue_shaping_info[index];

	printf("\n");
	printf("Shaping info. for Rx Queue[%d]\n", index);
	printf("\n");
	printf("Gauranteed bandwidth percentage  : %d%%\n",
	    dtoh32(ptrf_mgmt_shaping_info->gauranteed_bandwidth_percentage));
	printf("Guaranteed bytes/second          : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->guaranteed_bytes_per_second));
	printf("Guaranteed bytes/sampling period : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->guaranteed_bytes_per_sampling_period));
	printf("Num. bytes produced per second   : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->num_bytes_produced_per_second));
	printf("Num. bytes consumed per second   : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->num_bytes_consumed_per_second));
	printf("Num. packets pending             : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->num_queued_packets));
	printf("Num. bytes pending               : %d\n",
	    dtoh32(ptrf_mgmt_shaping_info->num_queued_bytes));

	printf("\n");
}

/* Get traffic management shaping info. */
static int
wl_trf_mgmt_shaping_info(void *wl, cmd_t *cmd, char **argv)
{
	uint    argc = 0;
	uint    i;
	int     rc = -1;
	char    *endptr = NULL;
	void    *ptr = NULL;

	/*
	 * Get current traffic management shaping info.
	 */
	if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
	    return rc;

	if (!*++argv) {
	    /*
	     * Print all of the current traffic management shaping info.
	     */
	    wl_trf_mgmt_print_global_shaping_info(ptr);

	    for (i = 0; i < TRF_MGMT_MAX_PRIORITIES; i++) {
		wl_trf_mgmt_print_shaping_info(ptr, i);
	    }
	}
	else {
	    /* arg count */
	    while (argv[argc])
		argc++;

	    /* required arguments */
	    if (argc != 1) {
		fprintf(stderr, "Too few/many arguments (require %d, got %d)\n", 1, argc);
		return BCME_USAGE_ERROR;
	    }

	    i = htod16((int16)strtol(*argv, &endptr, 0));
	    if (i >= TRF_MGMT_MAX_PRIORITIES) {
		fprintf(stderr, "Index must be < %d)\n", TRF_MGMT_MAX_PRIORITIES);
		return BCME_BADARG;
	    }

	    /* Print the current traffic management shaping info for the specified queue index. */
	    wl_trf_mgmt_print_global_shaping_info(ptr);
	    wl_trf_mgmt_print_shaping_info(ptr, i);
	}


	return rc;
}
