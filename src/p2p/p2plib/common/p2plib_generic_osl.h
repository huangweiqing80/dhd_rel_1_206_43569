/* P2P Library OS-specific Layer definitions for Linux
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_generic_osl.h,v 1.16 2011-01-11 02:08:21 $
 */
#ifndef _P2PLIB_GENERIC_OSL_H_
#define _P2PLIB_GENERIC_OSL_H_

#include <p2posl.h>

/* NOTE: Any file that #includes this file must first #include the appropriate
 * OS-specific p2posl_<os-name>.h.  eg.
 *     #include <p2posl_linux.h>
 */


/* P2P Library Linux OSL instance data */
typedef struct p2papi_osl_instance_s {

	/* Magic # to verify our struct type */
	uint32				osl_magic;
#define P2PAPI_OSL_HDL_MAGIC_NUMBER 0xa2d2 /* 41682 decimal */

	/* Pointer back to the object that contains this OSL instance */
	void*				app_hdl;

	/* SoftAP bsscfg data */
	struct {
		char	ifname[BCM_MSG_IFNAME_MAX];	/* softap's ifname */
		int	bssidx;				/* softap's bssidx */
	} softap;


	/* WL driver handle for calling wlu*() fns */
	void*				wl;

	/* mutex to ensure atomic access to instance data */
	p2posl_mutex_t		instance_data_mutex;

	/* Semaphore to wait for Group Owner negotiation during link creation */
	p2posl_sem_t		*go_negotiation_sem;

	/* Semaphore to wait for BSS create. */
	p2posl_sem_t		*bss_create_sem;

	/* Semaphore for sync escan complete */
	p2posl_sem_t		*escan_sem;

	p2posl_sem_t		*tx_af_sem;

	/* Semaphore to wait for STA assoc/disassoc at an AP. */
	p2posl_sem_t		*client_assoc_sem;

	/* Semaphore to wait for secured join at a STA. */
	p2posl_sem_t		*secure_join_sem;

	/* Discovery thread data */
	p2posl_thread_t		discovery_thread_hdl;
	bool				is_discovery_thread_running;

	/* Connection thread data */
	p2posl_thread_t		connect_thread_hdl;
	bool				is_connect_thread_running;

	/* Inocoming Connection thread data */
	p2posl_thread_t		incoming_thread_hdl;
	bool				is_incoming_thread_running;

	/* Group Owner Creation thread data */
	p2posl_thread_t		group_thread_hdl;
	bool				is_group_thread_running;

	/* DHCP server thread data */
	p2posl_thread_t		dhcp_thread_hdl;
	bool				is_dhcpd_thread_running;
	void				*dhcpd_hdl;	/* DHCP server handle */

	/* Raw frame rx thread data */
	bool				rx_thread_running;
	p2posl_thread_t		rx_thread_hdl;
	int					brcm_sock;
	int					fd_pipe[2];
	p2posl_rx_frame_hdlr_t rx_frame_cb;
	void				*rx_frame_cb_param;

#ifdef _MACOSX_
	int	bpf_buf_len;
#endif
} p2papi_osl_instance_t;


#endif /* _P2PLIB_GENERIC_OSL_H_ */
