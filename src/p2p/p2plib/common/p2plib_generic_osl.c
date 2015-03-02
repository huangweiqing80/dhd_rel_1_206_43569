/*
 * P2P Library OS-specific Layer (OSL) - generic RTOS version
 * This implements the Linux version of the functions defined by p2plib_osl.h.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_generic_osl.c,v 1.78 2011-01-08 01:42:00 $
 */
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

/* WPS include files */
#include <wpscli_api.h>

#if P2PAPI_ENABLE_DHCPD
#include <dhcp.h>
#endif /* P2PAPI_ENABLE_DHCPD */

/* P2P Library include files */
#include <BcmP2PAPI.h>
	#include <sys/types.h>
	#include <unistd.h>
	#include <pthread.h>
	#include <signal.h>
	#include <errno.h>
	#include <sys/timeb.h>
	#include <sys/time.h>
	#include <syslog.h>
	#include <p2posl_linux.h>
	#define RANDOM	random
#ifdef TARGETENV_android
	#define LOG_TAG "P2P"
	#include <android/log.h>
#endif
#include <p2posl.h>
#include <p2plib_osl.h>
#include <p2plib_generic_osl.h>
#include <p2plib_api.h>
#include <p2plib_int.h>
#include <p2pwl.h>

/* WL driver include files */
#include <proto/ethernet.h>
#include <bcmip.h>
#include <bcmendian.h>
#include <wlioctl.h>
#include <bcmutils.h>


/* Maximum # of seconds to wait for the WL driver to do the WPA2-PSK 4-way
 * handshake and compute the WPA2-PSK keys after the initial 802.11 connection
 * has been established.
 */
#define P2PAPI_WPA2PSK_TIMEOUT 10

#ifndef SOFTAP_ONLY
/* P2P Discovery thread parameters */
typedef struct {
	void *p2pHdl;
	BCMP2P_DISCOVER_PARAM discov_params;
} discov_thread_param_t;

/* P2P Connect thread parameters */
typedef struct {
	void *p2pHdl;
	uint32 timeout;
	p2papi_peer_info_t peer;

	/* If 'have_peer_dev_addr' is TRUE, the following parameters instead of
	 * 'peer' specify the peer to connect to.
	 */
	BCMP2P_BOOL have_peer_dev_addr;
	struct ether_addr peer_dev_addr;
	BCMP2P_CHANNEL peer_listen_channel;
	BCMP2P_BOOL is_peer_go;
	struct ether_addr peer_int_addr;
} conn_thread_param_t;

/* P2P Incoming Connection thread parameters */
typedef struct {
	void *p2pHdl;
	uint32 timeout_secs;
} incoming_thread_param_t;
#endif /* SOFTAP_ONLY */

/* P2P Group Create thread parameters */
typedef struct {
	void *p2pHdl;
	uint8 ssid[DOT11_MAX_SSID_LEN+1];
	bool auto_restart_wps;
	BCMP2P_CONFIG config;
} grp_thread_param_t;


/* Check if a WL driver handle is valid */
bool
p2papi_osl_wl_chk_hdl(void* wl_hdl, const char *file, int line)
{
	return p2posl_wl_chk_hdl(wl_hdl, file, line);
}


#if P2PLOGGING
/*
 * Debug Logging functions
 */
static FILE *p2papi_log_file = NULL;

/* Print a timestamped debug log at the given log level */
void
p2papi_osl_log(BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp,
	char *log_str)
{
#ifdef TARGETENV_android
	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "%s", log_str);
#else
	FILE *stream = (p2papi_log_file != NULL) ? p2papi_log_file : stdout;
	if (print_timestamp)
		p2posl_print_timestamp(level, stream);

	fputs(log_str, stream);
#endif
}

/* Initialize the debug logging system */
static void
p2papi_osl_log_init(void)
{
	p2posl_init_timestamp();
}

/* Redirect debug logs to a file */
void
p2papi_osl_set_log_file(const char *filename)
{
	FILE *cur_log_file = p2papi_log_file;

	p2papi_log_file = NULL;

	/* We may (sequentially) open multiple log files per session. If a log
	 * file is already open, close it first.
	 */
	if (cur_log_file != NULL) {
		fclose(cur_log_file);
	}

	cur_log_file = fopen(filename, "w");
	if (cur_log_file == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_dbg_set_log_file: error opening log file %s\n", filename));
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_dbg_set_log_file: opened log file %s\n", filename));
	}

	p2papi_log_file = cur_log_file;
}

#endif /* P2PLOGGING */


/*
 * OSL replacer functions for selected P2P Library API functions.
 * These allow an OSL to supplement or replace the core OS-independent
 * functionality of each API fn.
 * These must be implemented by every OSL.
 */
#ifndef SOFTAP_ONLY
/* thread invoked by the BCMP2PDiscover() OS replacer fn */
static void
p2papi_discovery_thread(void* arg)
{
	discov_thread_param_t *thread_params = (discov_thread_param_t*) arg;
	p2papi_instance_t *hdl = (p2papi_instance_t*) thread_params->p2pHdl;
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	osl_hdl->is_discovery_thread_running = TRUE;
	P2PLOG("p2papi_discovery_thread: enter\n");

	p2papi_discover(thread_params->p2pHdl,
		&thread_params->discov_params);
	P2PAPI_FREE(thread_params);

	P2PLOG("p2papp_discovery_thread: exit\n");
	osl_hdl->is_discovery_thread_running = FALSE;
}

/* OSL replacer fn for the P2P Library BCMP2PDiscover() API */
BCMP2P_STATUS
p2papi_osl_BCMP2PDiscover(BCMP2PHandle p2pHandle,
	PBCMP2P_DISCOVER_PARAM params)
{
	discov_thread_param_t *thread_params;
	p2papi_instance_t *hdl = (p2papi_instance_t*) p2pHandle;
	p2papi_osl_instance_t *osl_hdl;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_BCMP2PDiscover\n"));
	if (!P2PAPI_CHECK_P2PHDL(p2pHandle))
		return BCMP2P_INVALID_HANDLE;
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	if (params == NULL) {
		P2PERR("osl_BCMP2PDiscover: no params\n");
		return BCMP2P_INVALID_PARAMS;
	}

	if (BCMP2PIsDiscovering(p2pHandle)) {
		P2PERR("osl_BCMP2PDiscover: already in progress\n");
		return BCMP2P_DISCOVERY_ALREADY_IN_PROGRESS;
	}

	/* Create a thread parameter structure to pass to the thread.  The
	 * thread is responsible for freeing this memory.
	 */
	thread_params = P2PAPI_MALLOC(sizeof(*thread_params));
	if (thread_params == NULL) {
		P2PERR("osl_BCMP2PDiscover: thread param malloc failed\n");
		return BCMP2P_NOT_ENOUGH_SPACE;
	}
	thread_params->p2pHdl = p2pHandle;
	memcpy(&thread_params->discov_params, params,
		sizeof(thread_params->discov_params));

	/* Create a background thread to do the P2P discovery scan.
	 * This is necessary because p2p_discover() does not return until
	 * the social timeout has expired or BCMP2PCancelDiscover() is called.
	 */
	if (0 != p2posl_create_thread(p2papi_discovery_thread, thread_params,
		&osl_hdl->discovery_thread_hdl)) {
		P2PERR("osl_BCMP2PDiscover: thread creation failed\n");
		P2PAPI_FREE(thread_params);
		return BCMP2P_FAIL_TO_START_DISCOVER_PROCESS;
	}
	P2PLOG("osl_BCMP2PDiscover: created discovery thread\n");

	return BCMP2P_SUCCESS;
}

/* OSL replacer fn for the P2P Library BCMP2PCancelDiscover() API */
BCMP2P_STATUS
p2papi_osl_BCMP2PCancelDiscover(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t *hdl = (p2papi_instance_t*) p2pHandle;
	p2papi_osl_instance_t *osl_hdl;
	BCMP2P_STATUS ret;
	int i;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	/* Signal the thread to exit */
	ret = p2papi_discover_cancel(hdl);

	/* Wait up to 3 seconds for the discovery thread to exit */
	for (i = 0; i < 120; i++) {
		if (!osl_hdl->is_discovery_thread_running)
			break;
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 25);
	}
	if (osl_hdl->is_discovery_thread_running) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_CancelDiscover: discovery thread did not exit!\n"));
		ret = BCMP2P_ERROR;
	}


	P2PLOG("p2papi_osl_CancelDiscover: done\n");
	return ret;
}


/* thread invoked by the BCMP2PCreateLink() OS replacer fn */
static void
p2papi_connect_thread(void* arg)
{
	conn_thread_param_t *par = (conn_thread_param_t*) arg;
	p2papi_instance_t *hdl = (p2papi_instance_t*) par->p2pHdl;
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	osl_hdl->is_connect_thread_running = TRUE;
	P2PLOG("p2papi_connect_thread: enter\n");

	if (par->have_peer_dev_addr) {
		p2papi_link_create_to_devaddr(hdl, par->timeout, &par->peer_dev_addr,
			&par->peer_listen_channel, par->is_peer_go, &par->peer_int_addr);
	} else {
		p2papi_link_create(hdl, par->timeout, &par->peer);
	}
	P2PAPI_FREE(par);

	P2PLOG("p2papi_connect_thread: exit\n");
	osl_hdl->is_connect_thread_running = FALSE;
}

/* OSL replacer fn for the P2P Library BCMP2PCreateLink() API */
BCMP2P_STATUS
p2papi_osl_BCMP2PCreateLink(BCMP2PHandle p2pHandle,
	PBCMP2P_DISCOVER_ENTRY pPeerInfo, uint32 timeout)
{
	p2papi_instance_t *hdl = (p2papi_instance_t*) p2pHandle;
	p2papi_osl_instance_t *osl_hdl;
	conn_thread_param_t *thr_param;
	p2papi_peer_info_t *peer;

	P2PLOG("p2papi_osl_BCMP2PCreateLink: begin\n");
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	if (BCMP2PIsConnecting(p2pHandle)) {
		P2PERR("osl_BCMP2PCreateLink: end, connect already in progress\n");
		return BCMP2P_CONNECT_ALREADY_IN_PROGRESS;
	}

	peer = p2papi_find_peer(p2pHandle, pPeerInfo->mac_address);
	if (peer) {
		/* Create a thread parameter structure to pass to the thread.  The
		 * thread is responsible for freeing this memory.
		 */
		thr_param = P2PAPI_MALLOC(sizeof(*thr_param));
		if (thr_param == NULL) {
			P2PERR("osl_BCMP2PCreateLink: end, thread param malloc failed!\n");
			return BCMP2P_NOT_ENOUGH_SPACE;
		}
		memset(thr_param, 0, sizeof(*thr_param));
		thr_param->p2pHdl = p2pHandle;
		thr_param->timeout = timeout;
		memcpy(&thr_param->peer, peer, sizeof(thr_param->peer));
		thr_param->have_peer_dev_addr = FALSE;

		/* Create a background thread to do the connection creation */
		if (0 != p2posl_create_thread(p2papi_connect_thread, thr_param,
			&osl_hdl->connect_thread_hdl)) {
			P2PERR("osl_BCMP2PCreateLink: end, thread creation failed!\n");
/*			p2papi_do_link_create_cb(BCMP2P_NOTIF_CREATE_LINK_FAIL); */
			P2PAPI_FREE(thr_param);
			return BCMP2P_FAIL_TO_START_CONNECT_PROCESS;
		}
		P2PLOG("osl_BCMP2PCreateLink: end, created connection thread.\n");
		return BCMP2P_SUCCESS;
	} else {
		P2PERR("osl_BCMP2PCreateLink: end, peer not found!\n");
		return BCMP2P_PEER_NOT_FOUND;
	}
}

/* OSL replacer fn for the P2P Library BCMP2PCancelCreateLink() API */
BCMP2P_STATUS
p2papi_osl_BCMP2PCancelCreateLink(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t *hdl = (p2papi_instance_t*) p2pHandle;
	p2papi_osl_instance_t *osl_hdl;
	BCMP2P_STATUS ret;
	int i;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	/* Tear down connection, signal the thread to exit */
	ret = p2papi_teardown(hdl);

	/* Wait up to 10 seconds for the connect thread to exit */
	for (i = 0; i < 100; i++) {
		if (!osl_hdl->is_connect_thread_running)
			break;
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 100);
	}
	if (osl_hdl->is_connect_thread_running) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_CancelCreateGroup: connect thread did not exit!\n"));
		ret = BCMP2P_ERROR;
	}

	P2PLOG("p2papi_osl_CancelCreateLink: done\n");
	return ret;
}

/* OSL replacer fn for the P2P Library BCMP2PCreateLinkToDevAddr() API */
BCMP2P_STATUS
p2papi_osl_BCMP2PCreateLinkToDevAddr(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *peerDevAddr, BCMP2P_CHANNEL *peerListenChannel,
	BCMP2P_BOOL isPeerGo, BCMP2P_ETHER_ADDR *peerIntAddr,
	BCMP2P_UINT32 timeout)
{
	p2papi_instance_t *hdl = (p2papi_instance_t*) p2pHandle;
	p2papi_osl_instance_t *osl_hdl;
	conn_thread_param_t *thr_param;

	P2PLOG("p2papi_osl_BCMP2PCreateLinkToDA: begin\n");
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	if (BCMP2PIsConnecting(p2pHandle)) {
		P2PERR("osl_BCMP2PCreateLinkToDA: end, connect already in progress\n");
		return BCMP2P_CONNECT_ALREADY_IN_PROGRESS;
	}

	/* Create a thread parameter structure to pass to the thread.  The
	 * thread is responsible for freeing this memory.
	 */
	thr_param = P2PAPI_MALLOC(sizeof(*thr_param));
	if (thr_param == NULL) {
		P2PERR("osl_BCMP2PCreateLinkToDA: end, malloc failed!\n");
		return BCMP2P_NOT_ENOUGH_SPACE;
	}
	memset(thr_param, 0, sizeof(*thr_param));
	thr_param->p2pHdl = p2pHandle;
	thr_param->timeout = timeout;
	thr_param->have_peer_dev_addr = TRUE;
	memcpy(&thr_param->peer_dev_addr, peerDevAddr,
		sizeof(thr_param->peer_dev_addr));
	memcpy(&thr_param->peer_listen_channel, peerListenChannel,
		sizeof(thr_param->peer_listen_channel));
	thr_param->is_peer_go = isPeerGo;
	if (peerIntAddr != 0) {
		memcpy(&thr_param->peer_int_addr, peerIntAddr,
			sizeof(thr_param->peer_int_addr));
	}

	/* Create a background thread to do the connection creation */
	if (0 != p2posl_create_thread(p2papi_connect_thread, thr_param,
		&osl_hdl->connect_thread_hdl)) {
		P2PERR("osl_BCMP2PCreateLinkToDA: end, thread creation failed!\n");
/*			p2papi_do_link_create_cb(BCMP2P_NOTIF_CREATE_LINK_FAIL); */
		P2PAPI_FREE(thr_param);
		return BCMP2P_FAIL_TO_START_CONNECT_PROCESS;
	}
	P2PLOG("osl_BCMP2PCreateLinkToDA: end, created connection thread.\n");
	return BCMP2P_SUCCESS;
}

/* Thread invoked by the BCMP2PProcessIncomingConnection() OSL replacer fn */
static void
p2papi_incoming_thread(void* arg)
{
	incoming_thread_param_t *par = (incoming_thread_param_t*) arg;
	p2papi_instance_t *hdl = (p2papi_instance_t*) par->p2pHdl;
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	P2PLOG("p2papi_incoming_thread: enter\n");
	osl_hdl->is_incoming_thread_running = TRUE;

	p2papi_process_incoming_conn(hdl, par->timeout_secs);
	P2PAPI_FREE(par);

	P2PLOG("p2papi_incoming_thread: exit\n");
	osl_hdl->is_incoming_thread_running = FALSE;
}


/* OSL replacer fn for the P2P Library BCMP2PProcessIncomingConnection() API */
BCMP2P_STATUS
p2papi_osl_BCMP2PProcessIncoming(BCMP2PHandle p2pHandle,
	BCMP2P_UINT32 timeout_secs)
{
	p2papi_instance_t *hdl = (p2papi_instance_t*) p2pHandle;
	p2papi_osl_instance_t *osl_hdl;
	incoming_thread_param_t *thr_param;

	P2PLOG("p2papi_osl_BCMP2PProcessIncoming\n");
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	if (BCMP2PIsConnecting(p2pHandle)) {
		return BCMP2P_CONNECT_ALREADY_IN_PROGRESS;
	}

	/* Create a thread parameter structure to pass to the thread.  The
	 * thread is responsible for freeing this memory.
	 */
	thr_param = P2PAPI_MALLOC(sizeof(*thr_param));
	if (thr_param == NULL) {
		P2PERR("Process Incoming Connection thread param malloc failed\n");
		return BCMP2P_NOT_ENOUGH_SPACE;
	}
	memset(thr_param, 0, sizeof(*thr_param));
	thr_param->p2pHdl = p2pHandle;
	thr_param->timeout_secs = timeout_secs;

	/* Create a background thread to run the group owner */
	if (0 != p2posl_create_thread(p2papi_incoming_thread, thr_param,
		&osl_hdl->incoming_thread_hdl)) {
		P2PERR("Process Incoming Connection thread creation failed\n");
/*			p2papi_do_link_create_cb(BCMP2P_NOTIF_CREATE_LINK_FAIL); */
		P2PAPI_FREE(thr_param);
		return BCMP2P_FAIL_TO_START_CONNECT_PROCESS;
	}
	P2PLOG("p2papi_osl_BCMP2PProcessIncoming: created thread\n");
	return BCMP2P_SUCCESS;
}
#endif  /* SOFTAP_ONLY */

/* Thread invoked by the BCMP2PCreateGroup() OSL replacer fn */
static void
p2papi_group_thread(void* arg)
{
	grp_thread_param_t *par = (grp_thread_param_t*) arg;
	p2papi_instance_t *hdl = (p2papi_instance_t*) par->p2pHdl;
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	P2PLOG("p2papi_group_thread: enter\n");
	osl_hdl->is_group_thread_running = TRUE;

	p2papi_group_create(hdl, par->ssid, par->auto_restart_wps);
	P2PAPI_FREE(par);

	P2PLOG("p2papi_group_thread: exit\n");
	osl_hdl->is_group_thread_running = FALSE;
}

/* OSL replacer fn for the P2P Library BCMP2PCreateGroup() API */
BCMP2P_STATUS
p2papi_osl_BCMP2PCreateGroup(BCMP2PHandle p2pHandle, uint8 *ssid,
	bool bAutoRestartWPS)
{
	p2papi_instance_t *hdl = (p2papi_instance_t*) p2pHandle;
	p2papi_osl_instance_t *osl_hdl;
	grp_thread_param_t *thr_param;

	P2PLOG("p2papi_osl_BCMP2PCreateGroup\n");
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

#ifndef SOFTAP_ONLY
	if (BCMP2PIsConnecting(p2pHandle)) {
		return BCMP2P_CONNECT_ALREADY_IN_PROGRESS;
	}
#endif

	/* Create a thread parameter structure to pass to the thread.  The
	 * thread is responsible for freeing this memory.
	 */
	thr_param = P2PAPI_MALLOC(sizeof(*thr_param));
	if (thr_param == NULL) {
		P2PERR("Group owner thread param malloc failed\n");
		return BCMP2P_NOT_ENOUGH_SPACE;
	}
	memset(thr_param, 0, sizeof(*thr_param));
	thr_param->p2pHdl = p2pHandle;
	strncpy((char*)thr_param->ssid, (char*)ssid, sizeof(thr_param->ssid));
	thr_param->auto_restart_wps = bAutoRestartWPS;

	/* Create a background thread to run the group owner */
	if (0 != p2posl_create_thread(p2papi_group_thread, thr_param,
		&osl_hdl->group_thread_hdl)) {
		P2PERR("Group owner thread creation failed\n");
/*			p2papi_do_link_create_cb(BCMP2P_NOTIF_CREATE_LINK_FAIL); */
		P2PAPI_FREE(thr_param);
		return BCMP2P_FAIL_TO_START_CONNECT_PROCESS;
	}
	P2PLOG("BCMP2PCreateGroup: created group owner thread\n");
	return BCMP2P_SUCCESS;
}

/* OSL replacer fn for the P2P Library BCMP2PCancelCreateGroup() API */
BCMP2P_STATUS
p2papi_osl_BCMP2PCancelCreateGroup(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t *hdl = (p2papi_instance_t*) p2pHandle;
	p2papi_osl_instance_t *osl_hdl;
	BCMP2P_STATUS ret;
	int i;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	/* Signal the thread to exit */
	ret = p2papi_group_cancel(hdl);

	/* Wait up to 10 seconds for the group thread to exit */
	for (i = 0; i < 100; i++) {
		if (!osl_hdl->is_group_thread_running)
			break;
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 100);
	}
	if (osl_hdl->is_group_thread_running) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_CancelCreateGroup: group thread did not exit!\n"));
		ret = BCMP2P_ERROR;
	}

	P2PLOG("p2papi_osl_CancelCreateGroup: done\n");
	return ret;
}


/*
 * Functions related to receiving action frames and WLC events using an
 * ETHER_TYPE_BRCM raw socket.
 */

/* Parameter-conversion stub for calling p2papi_process_raw_rx_frame */
static void
proc_raw_rx_frm(void *hdl, uint8 *frame, uint32 frame_bytes)
{
	p2papi_process_raw_rx_frame((p2papi_instance_t*)hdl, frame, frame_bytes);
}

/* Start the raw frame receiver/manager which allows us to receive Wifi
 * action frames and WL driver dongle events.
 */
int
p2papi_osl_start_raw_rx_mgr(p2papi_instance_t *hdl)
{
	P2PAPI_CHECK_P2PHDL(hdl);
	return p2posl_start_raw_rx_mgr(hdl->osl_hdl, proc_raw_rx_frm, hdl);
}

/* Stop the raw frame receiver/manager */
int
p2papi_osl_stop_raw_rx_mgr(p2papi_instance_t *hdl)
{
	P2PAPI_CHECK_P2PHDL(hdl);
	return p2posl_stop_raw_rx_mgr(hdl->osl_hdl);
}

/* Refesh timers */
int
p2papi_osl_timer_refresh(p2papi_instance_t *hdl)
{
	P2PAPI_CHECK_P2PHDL(hdl);
	return p2posl_timer_refresh(hdl->osl_hdl);
}

/* Initialize the high level p2plib OSL */
bool
p2papi_osl_init(void)
{
	/* Initialize the low level p2plib OSL */
	if (!p2posl_init())
		return FALSE;

#if P2PLOGGING
	/* Initialize the logging mechanism */
	p2papi_osl_log_init();
#endif /* P2PLOGGING */

#ifndef SOFTAP_ONLY
	/* Register our BCMP2P API override functions */
	p2papi_register_discover_override(p2papi_osl_BCMP2PDiscover);
	p2papi_register_cancel_discover_override(
		p2papi_osl_BCMP2PCancelDiscover);
	p2papi_register_create_link_override(p2papi_osl_BCMP2PCreateLink,
		p2papi_osl_BCMP2PCreateLinkToDevAddr);
	p2papi_register_cancel_create_link_override(
		p2papi_osl_BCMP2PCancelCreateLink);
	p2papi_register_process_incoming_override(p2papi_osl_BCMP2PProcessIncoming);
#endif
	p2papi_register_create_group_override(p2papi_osl_BCMP2PCreateGroup);
	p2papi_register_cancel_create_group_override(
		p2papi_osl_BCMP2PCancelCreateGroup);

	return TRUE;
}

/* Deinitialize the high level p2plib OSL */
bool
p2papi_osl_deinit(void)
{
#if P2PLOGGING
	if (p2papi_log_file != NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_deinit: closing log file\n"));
		fclose(p2papi_log_file);
		p2papi_log_file = NULL;
	}
#endif /* P2PLOGGING */

	return p2posl_deinit();
}


/* Open a new instance of the high level OSL.
 * Returns a ptr to the allocated and initialized OSL data, or NULL if error.
 */
void*
p2papi_osl_open(p2papi_instance_t* hdl, const char *if_name,
	const char *primary_if_name)
{
	p2papi_osl_instance_t *osl_hdl;
	P2PWL_HDL wl;
	struct ether_addr my_mac_addr;

	(void) if_name;
	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) p2posl_open(hdl, if_name, primary_if_name);

	if (osl_hdl != NULL) {
		osl_hdl->softap.bssidx = -1;
		wl = p2posl_get_wl_hdl(osl_hdl);

		/* Get our wireless chip's primary MAC address and use it to generate
		 * our P2P Device Address and P2P Interface Address.
		 *
		 * Note: In the WL driver, P2P Discovery uses our primary MAC address
		 * with the locally administered bit set.  We cannot use the same MAC
		 * address for the connection BSS's P2P Interface Address.
		 */
		p2pwl_get_mac_addr(wl, &my_mac_addr);
		p2papi_generate_bss_mac(hdl->use_same_int_dev_addrs, &my_mac_addr,
			&hdl->p2p_dev_addr, &hdl->conn_ifaddr);

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_open: P2P Device addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
			hdl->p2p_dev_addr.octet[0], hdl->p2p_dev_addr.octet[1],
			hdl->p2p_dev_addr.octet[2], hdl->p2p_dev_addr.octet[3],
			hdl->p2p_dev_addr.octet[4], hdl->p2p_dev_addr.octet[5]));
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"              P2P Interface addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
			hdl->conn_ifaddr.octet[0], hdl->conn_ifaddr.octet[1],
			hdl->conn_ifaddr.octet[2], hdl->conn_ifaddr.octet[3],
			hdl->conn_ifaddr.octet[4], hdl->conn_ifaddr.octet[5]));
	}

	/* SoftAP BSSCFG index */
	hdl->default_bsscfg_idx = 1;

	return osl_hdl;
}

/* Close an instance of the high level OSL and free the OSL data */
void
p2papi_osl_close(p2papi_instance_t* hdl, void* osl_handle)
{
	p2posl_close(osl_handle);
}


/* Obtain a P2P Library handle from an OSL handle */
p2papi_instance_t*
p2papi_osl_get_p2p_hdl(void* osl_handle)
{
	p2papi_osl_instance_t *osl_hdl = (p2papi_osl_instance_t*) osl_handle;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	return (p2papi_instance_t*) osl_hdl->app_hdl;
}

/* Obtain a WL handle from an OSL handle */
void* p2posl_get_wl_hdl(P2POSL_HDL oslHdl)
{
	p2papi_osl_instance_t *osl_hdl = (p2papi_osl_instance_t*) oslHdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	return osl_hdl->wl;
}

/* Obtain a WL driver handle from a P2P OSL handle */
void*
p2papi_osl_get_wl_hdl(p2papi_instance_t* hdl)
{
	P2PAPI_CHECK_P2PHDL(hdl);
	return p2posl_get_wl_hdl(hdl->osl_hdl);
}

/* Obtain the WL driver handle of the primary interface from a P2P OSL handle */
void*
p2papi_osl_get_primary_wl_hdl(p2papi_instance_t* p2pHdl)
{
	return p2papi_osl_get_wl_hdl(p2pHdl);
}


/* Do an application notification callback */
void
p2papi_osl_do_notify_cb(p2papi_instance_t* hdl,
	BCMP2P_NOTIFICATION_TYPE type, BCMP2P_NOTIFICATION_CODE code)
{
	p2papi_common_do_notify_cb(hdl, type, code);
}

/* Sleep */
void
p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_REASON reason, uint32 ms)
{
#if TARGETENV_android
	switch (reason)
	{
	case P2PAPI_OSL_SLEEP_WAIT_BSS_START:
		ms = 500;
		break;
	default:
		break;
	}
#else
	(void) reason;
#endif 
	p2posl_sleep_ms(ms);
}


/* Random number generation - return number between 0 and RAND_MAX */
long int p2papi_osl_random(void)
{
	return RANDOM();
}

/* Generate num_bytes random bytes */
void
p2papi_osl_rand_bytes(unsigned char *buf, int num_bytes)
{
	int i;
	for (i = 0;  i < num_bytes;  i++) {
		buf[i] = RANDOM() & 0xff;
	}
}


/* Invoke a WL driver ioctl */
int
p2papi_osl_wl_ioctl(p2papi_instance_t* hdl, int bsscfg_idx, int cmd, void *buf,
	int len, bool set)
{
	p2posl_wl_hdl_t *wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2posl_wl_ioctl_bss(wl, cmd, buf, len, set, bsscfg_idx);
}

/* Invoke a WL driver ioctl on primary wl interface given a WL driver handle */
int
p2papi_osl_wl_primary_ioctl(void* wl_hdl, int cmd, void *buf, int len, bool set)
{
	return p2posl_wl_ioctl_bss(wl_hdl, cmd, buf, len, set, 0);
}


/*
 * Miscellaneous functions
 */

/* Check if an OSL handle is valid */
bool
p2papi_osl_chk_hdl(void* osl_hdl, const char *file, int line)
{
	p2papi_osl_instance_t* hdl = (p2papi_osl_instance_t*) osl_hdl;
	if (hdl == NULL || hdl->osl_magic != P2PAPI_OSL_HDL_MAGIC_NUMBER) {
		P2PERR("Bad osl_hdl %p\n");
		P2PERR2("at %s:%d\n", file, line);
		return FALSE;
	}
	return TRUE;
}

/* Lock/Unlock a P2P Library instance for mutually exclusive access to its
 * ioctl mutex.  Returns 0 if successful.
 */
int
p2papi_osl_ioctl_lock(p2papi_instance_t* hdl)
{
	p2papi_osl_instance_t *osl_hdl;
	void *wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2posl_ioctl_lock(wl);
}

int
p2papi_osl_ioctl_unlock(p2papi_instance_t* hdl)
{
	p2papi_osl_instance_t *osl_hdl;
	void *wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2posl_ioctl_unlock(wl);
}


/* Lock/Unlock a P2P Library instance for mutually exclusive access to its
 * data.  Returns 0 if successful.
 */
int
p2papi_osl_data_lock(p2papi_instance_t* hdl)
{
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;

	return p2posl_data_lock(osl_hdl);
}

int
p2papi_osl_data_unlock(p2papi_instance_t* hdl)
{
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	return p2posl_data_unlock(osl_hdl);
}


int
p2papi_osl_signal_secure_join(p2papi_instance_t* hdl)
{
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_signal_secure_join\n"));
	return p2posl_sem_signal(osl_hdl->secure_join_sem);
}

/*
 * Join this STA device to a BSS with the given security credentials.
 */
int
p2papi_osl_sta_join_with_security(p2papi_instance_t* hdl, char in_ssid[],
	brcm_wpscli_authtype in_authType, brcm_wpscli_encrtype in_encrType,
	char in_nwKey[], uint16 in_wepIndex,
	struct ether_addr *in_bssid)
{
	int ret = 0;
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	/* Apply STA security credentials */
	/* in-driver and external supplicant _almost_ the same */
	p2papi_common_apply_sta_security(hdl, in_ssid, in_authType, in_encrType,
		in_nwKey, in_wepIndex);

#if P2PAPI_USE_IDSUP
	p2posl_sem_reset(osl_hdl->secure_join_sem);
#endif /* P2PAPI_USE_IDSUP */

	/* Join to the AP peer's BSS with retries */
	if (0 != p2papi_common_do_sta_join(hdl, in_ssid, in_bssid)) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_sta_join_with_security: unable to join AP\n"));
		ret = -1;
		goto join_ret;
	}

	/* Wait for the WPA/WPA2-PSK secure join to complete */
	if (in_authType == BRCM_WPS_AUTHTYPE_WPAPSK ||
		in_authType == BRCM_WPS_AUTHTYPE_WPA2PSK) {
#if P2PAPI_USE_IDSUP
		P2POSL_STATUS status;
		status = p2posl_sem_wait(osl_hdl->secure_join_sem,
			P2PAPI_WPA2PSK_TIMEOUT * 1000, BCMP2P_LOG_MED);
		if (P2POSL_SUCCESS == status) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_osl_sta_join: STA secure join keys plumbed\n"));
		} else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_osl_sta_join: STA secure join timed out\n"));
			ret = -2;
		}
#else /* !P2PAPI_USE_IDSUP */
		/* Poll for the connection secured event from the WL driver */
		int i;
		for (i = 0; i < P2PAPI_WPA2PSK_TIMEOUT; i++) {
			if (hdl->cancel_link_create) {
				P2PLOG("p2papi_osl_sta_join: aborting WPA2-PSK wait loop\n");
				break;
			}
			if (hdl->is_connection_secured) {
				P2PLOG("p2papi_osl_sta_join: STA WPA2-PSK keys plumbed\n");
				break;
			}
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_STA_JOINED_POLL, 500);
		}
		if (i >= P2PAPI_WPA2PSK_TIMEOUT) {
			/* connection failed */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_osl_sta_join: conn secured poll timed out\n"));
			ret = -2;
		}

		/* Cleanup external security context. */
		hslif_deinit_ctx(hdl->ext_auth_supp_ctx);
		hdl->ext_auth_supp_ctx = NULL;

#endif /* P2PAPI_USE_IDSUP */
	}

join_ret:
	return ret;
}


/*
 * Apply BSS security credentials
 */
int
p2papi_osl_apply_ap_security(p2papi_instance_t* hdl, char in_ssid[],
	brcm_wpscli_authtype in_authType, brcm_wpscli_encrtype in_encrType,
	char in_nwKey[], uint16 in_wepIndex)
{
	/* internal and external auth procedure _almost_ identical */
	return p2papi_common_apply_ap_security(hdl, in_ssid, in_authType,
		in_encrType, in_nwKey, in_wepIndex);
}

/* Get the AP mode network interface name */
char*
p2papi_osl_get_ap_mode_ifname(p2papi_instance_t* hdl)
{
	return hdl->conn_ifname;
}

/* Get the STA mode network interface name */
char*
p2papi_osl_get_sta_mode_ifname(p2papi_instance_t* hdl)
{
	return hdl->conn_ifname;
}


/* Open firewall ports needed for DHCP:
 * - allow incoming packets from 0.0.0.0 or dhcp-pool to dhcp-ip
 * - allow incoming packets from any address to 255.255.255.255
 * - allow outgoing packets from dhcp-ip to dhcp-pool or 255.255.255.255
 * where dhcp-ip is the IP address of the dhcp server host and dhcp-pool
 * is the address pool from which the DHCP server assigns addresses.
 */
bool
p2papi_osl_dhcp_open_firewall(p2papi_instance_t* hdl)
{
	P2PAPI_CHECK_P2PHDL(hdl);

	/* Not implemented yet */
	(void) hdl;
	return TRUE;
}

/* Close firewall ports previously opened for DHCP */
bool
p2papi_osl_dhcp_close_firewall(p2papi_instance_t* hdl)
{
	P2PAPI_CHECK_P2PHDL(hdl);

	/* Not implemented yet */
	(void) hdl;
	return TRUE;
}

/* Set a static IP addr/netmask for this AP peer device's P2P network
 * interface.
 */
bool
p2papi_osl_set_ap_ipaddr(p2papi_instance_t* hdl, uint32 ip, uint32 netmask)
{
#ifdef TARGETOS_symbian
	extern uint32 osl_ext_set_ap_ipaddr(bool aDhcp, uint32 aIpAddr, uint32 aNetmask);
	extern void socketSetIapId(uint32 aIapId);

	uint32 iapId = osl_ext_set_ap_ipaddr(FALSE, ip, netmask);
	socketSetIapId(iapId);
	return TRUE;
#endif

	char cmd[128];
	(void) hdl;

	/* Note: Two ifconfig commands are used here instead of a single
	 * "ifconfig wl0.1 netmask 255.255.255.0 192.168.16.1 up" command
	 * because a single command will cause Linux errors like
	 * "SIOCSIFNETMASK: Cannot assign requested address".
	 */
#ifdef TARGETENV_android
	snprintf(cmd, sizeof(cmd), "/system/bin/ifconfig %s %d.%d.%d.%d up\n",
#elif defined(TARGETENV_BCMSTB)
	snprintf(cmd, sizeof(cmd), "/bin/ifconfig %s %d.%d.%d.%d up\n",
#else
	snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s %d.%d.%d.%d up\n",
#endif /* TARGETENV_android */
		p2papi_osl_get_ap_mode_ifname(hdl),
		(ip & 0xff000000) >> 24,
		(ip & 0x00ff0000) >> 16,
		(ip & 0x0000ff00) >> 8,
		(ip & 0x000000ff));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_set_ap_ipaddr: %s\n", cmd));
	system(cmd);

#ifdef TARGETENV_android
	snprintf(cmd, sizeof(cmd), "/system/bin/ifconfig %s netmask %d.%d.%d.%d\n",
#elif defined(TARGETENV_BCMSTB)
	snprintf(cmd, sizeof(cmd), "/bin/ifconfig %s netmask %d.%d.%d.%d\n",
#else
	snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s netmask %d.%d.%d.%d\n",
#endif /* TARGETENV_android */
		p2papi_osl_get_ap_mode_ifname(hdl),
		(netmask & 0xff000000) >> 24,
		(netmask & 0x00ff0000) >> 16,
		(netmask & 0x0000ff00) >> 8,
		(netmask & 0x000000ff));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_set_ap_ipaddr: %s\n", cmd));
	system(cmd);

#ifdef TARGETENV_android
	snprintf(cmd, sizeof(cmd), "/system/bin/route add default gw %d.%d.%d.1 dev %s \n",
		(ip & 0xff000000) >> 24,
		(ip & 0x00ff0000) >> 16,
		(ip & 0x0000ff00) >> 8,
		p2papi_osl_get_ap_mode_ifname(hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_set_ap_ipaddr: %s\n", cmd));
	system(cmd);
#endif /* TARGETENV_android */
	return TRUE;
}

/* Clear the static IP addr of the AP peer device's network interface */
bool
p2papi_osl_clear_ap_ipaddr(struct p2papi_instance_s* hdl)
{
	char cmd[128];
	(void) hdl;

#ifdef TARGETENV_android
	snprintf(cmd, sizeof(cmd), "/system/bin/ifconfig %s 0.0.0.0 down\n",
#elif defined(TARGETENV_BCMSTB)
	snprintf(cmd, sizeof(cmd), "/bin/ifconfig %s 0.0.0.0 down\n",
#else
	snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s 0.0.0.0 down\n",
#endif /* TARGETENV_android */
		p2papi_osl_get_ap_mode_ifname(hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_clear_ap_ipaddr: %s\n", cmd));
	system(cmd);

	return TRUE;
}

#if P2PAPI_ENABLE_DHCPD
/* DHCP thread created by p2papi_osl_dhcp_run_server() */
static void
p2papi_dhcpd_thread(void* arg)
{
	p2papi_instance_t *hdl;
	p2papi_osl_instance_t *osl_hdl = (p2papi_osl_instance_t*) arg;

	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	hdl = p2papi_osl_get_p2p_hdl(osl_hdl);
	P2PAPI_CHECK_P2PHDL(hdl);

	osl_hdl->is_dhcpd_thread_running = TRUE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_dhcpd_thread: enter\n"));

	/* Invoke the DHCP library function to run the DHCP server.
	 * This call blocks until the DHCP server exits.
	 */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_dhcpd_thread: running dhcpd\n"));
	DHCP_main(hdl->dhcpd_hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_dhcpd_thread: exit\n"));
	osl_hdl->is_dhcpd_thread_running = FALSE;
}
#endif /* P2PAPI_ENABLE_DHCPD */

/* Run the DHCP server asynchronously */
bool
p2papi_osl_dhcp_run_server(p2papi_instance_t* hdl, void *dhcpd_hdl)
{
	p2papi_osl_instance_t *osl_hdl;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_dhcp_run_server\n"));
	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

#if P2PAPI_ENABLE_DHCPD
	/* Create a thread that calls DHCP_Main() to run the DHCP server */
	osl_hdl->dhcpd_hdl = dhcpd_hdl;
	if (0 != p2posl_create_thread(p2papi_dhcpd_thread, osl_hdl,
		&osl_hdl->dhcp_thread_hdl)) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "DHCP thread creation failed\n"));
		return FALSE;
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_osl_dhcp_run_server: created DHCP thread\n"));
#endif /* P2PAPI_ENABLE_DHCPD */

	return TRUE;
}

/* Stop the asynchronous DHCP server */
bool
p2papi_osl_dhcp_end_server(p2papi_instance_t* hdl, void *dhcpd_hdl)
{
#if P2PAPI_ENABLE_DHCPD
	p2papi_osl_instance_t *osl_hdl;
	void *ret;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_osl_dhcp_end_server: calling DHCP_Shutdown()\n"));
	ret = DHCP_Shutdown();

	return (ret == (void*)DDOK) ? TRUE : FALSE;
#else /* P2PAPI_ENABLE_DHCPD */
	return TRUE;
#endif /* P2PAPI_ENABLE_DHCPD */
}


/* Wait for the Group Owner Negotiation handshake to complete.
 * This potentially blocks the caller, typically for 0 to 2 seconds.
 * Returns BCMP2P_SUCCESS if the GO negotiation is complete.
 * Returns BCMP2P_GO_NEGOTIATE_TIMEOUT on a timeout.
 */
int
p2papi_osl_wait_for_go_negotiation(p2papi_instance_t* hdl, int timeout_ms)
{
	p2papi_osl_instance_t *osl_hdl;
	P2POSL_STATUS ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_wait_for_go_neg: %d ms\n",
		timeout_ms));
	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	ret = p2posl_sem_wait(osl_hdl->go_negotiation_sem, timeout_ms,
		BCMP2P_LOG_MED);
	if (ret == P2POSL_SUCCESS) {
		return BCMP2P_SUCCESS;
	} else if (ret == P2POSL_TIMEOUT) {
		return BCMP2P_GO_NEGOTIATE_TIMEOUT;
	} else {
		return BCMP2P_ERROR;
	}
}

/* Signal that the Group Owner Negotiation handshake has started or is done.
 * - Signalling DONE unblocks any thread blocked on
 *   p2papi_osl_wait_for_go_negotiation().
 * - Signalling DONE can occur before p2papi_osl_wait_for_go_negotiation()
 *   is called, in which case p2papi_osl_wait_for_go_negotiation() returns
 *   SUCCESS immediately when it is called.
 */
int
p2papi_osl_signal_go_negotiation(struct p2papi_instance_s *hdl,
	P2PAPI_OSL_GO_STATE go_state)
{
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	switch (go_state) {
	case P2PAPI_OSL_GO_STATE_START:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_go_neg: START\n"));
		return (p2posl_sem_reset(osl_hdl->go_negotiation_sem) == 0)
			? BCMP2P_SUCCESS : BCMP2P_ERROR;
	case P2PAPI_OSL_GO_STATE_DONE:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_go_neg: DONE\n"));
		return (p2posl_sem_signal(osl_hdl->go_negotiation_sem) == 0)
			? BCMP2P_SUCCESS : BCMP2P_ERROR;
	case P2PAPI_OSL_GO_STATE_CANCEL:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_go_neg: CANCEL\n"));
		return (p2posl_sem_signal(osl_hdl->go_negotiation_sem) == 0)
			? BCMP2P_SUCCESS : BCMP2P_ERROR;
	default:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_go_neg: bad go_state %d\n", go_state));
		break;
	}
	return BCMP2P_ERROR;
}


/* Delete a P2P connection BSS */
int
p2papi_osl_delete_bss(p2papi_instance_t* hdl, int bssidx)
{
	int ret = 0;
	p2papi_osl_instance_t *osl_hdl;
	void *wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_delete_bss: bssidx=%d\n",
		bssidx));

	if (bssidx == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_delete_bss: no bss.\n"));
		return ret;
	}

	if (hdl->enable_p2p) {
		/* For P2P mode, use P2P-specific driver features to delete the
		 * bss: "wl p2p_ifdel"
		 */
		ret = p2pwl_p2p_ifdel(wl, &hdl->conn_ifaddr);

		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_WAIT_BSS_STOP, 100);
	} else {
		/* For SoftAP-only mode, use only non-P2P driver features to delete
		 * the bss: do nothing.  Currently there is no way to delete an
		 * implicitly created BSS.
		 * Save connection bssidx/ifname to softap bssidx/ifname
		 * and resuse them later if needed.
		 */
		osl_hdl->softap.bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];
		strncpy(osl_hdl->softap.ifname, hdl->conn_ifname,
			sizeof(osl_hdl->softap.ifname));
	}

	/* Clear the saved bsscfg index of the connection BSSCFG to indicate we
	 * have no connection BSS.
	 */
	p2papi_save_bssidx(hdl, P2PAPI_BSSCFG_CONNECTION, 0);

	return ret;
}

/* Create a P2P connection BSSCFG */
int
p2papi_osl_create_bss(p2papi_instance_t* hdl, BCMP2P_BOOL is_ap)
{
	int ret = 0;
	int index = 0;
	chanspec_t chspec;
	p2papi_osl_instance_t *osl_hdl;
	void *wl;
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	/* If a leftover P2P connection BSS already exists, delete it */
	if (bssidx != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_create_bss: conn bss %u already exists! Deleting.\n",
			bssidx));
		p2papi_osl_delete_bss(hdl, bssidx);
	}

	if (hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_create_bss: P2P ch=%d:%d\n",
			hdl->op_channel.channel_class, hdl->op_channel.channel));

		/* For P2P mode, use P2P-specific driver features to create the
		 * bss: "wl p2p_ifadd"
		 */

		/* Create a chspec from the operating channel */
#ifdef BCM_P2P_OPTEXT
		if (hdl->opch_force)
			p2papi_channel_to_chspec(&hdl->opch_force_store, &chspec);
		else if (hdl->opch_high)
			p2papi_channel_to_high_chspec(hdl, &hdl->op_channel, &chspec);
		else
#endif
			p2papi_channel_to_chspec(&hdl->op_channel, &chspec);

		/* Setting this flag causes the WLC event handler to save the next
		 * WLC_E_IF event's network interface name into hdl->conn_ifname.
		 */
		hdl->conn_bsscfg_create_ack_wait = TRUE;
		p2posl_sem_reset(osl_hdl->bss_create_sem);

		/* Create the new BSS */
/*
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_create_bss: before p2p_ifadd, bcaw=%d\n",
			hdl->conn_bsscfg_create_ack_wait ));
*/
		ret = p2pwl_p2p_ifadd(wl, &hdl->conn_ifaddr,
			is_ap ? WL_P2P_IF_GO : WL_P2P_IF_CLIENT, chspec);
/*
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_create_bss: after p2p_ifadd, bcaw=%d\n",
			hdl->conn_bsscfg_create_ack_wait ));
*/

		if (ret != 0) {
			hdl->conn_bsscfg_create_ack_wait = FALSE;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_osl_create_bss: p2p_ifadd failed with %d\n", ret));
		}
		else {
			/* Wait for the WLC_E_IF event from the driver which
			 * carries the name of the created OS network interface.
			 */
			ret = p2posl_sem_wait(osl_hdl->bss_create_sem, 3000,
				BCMP2P_LOG_MED);
			if (ret != 0) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_osl_create_bss: sem_wait failed with %d\n", ret));
			}
		}

		if (ret == 0) {
			/* Get the bsscfg index of the created BSS */
			ret = p2pwl_p2p_ifidx(wl, &hdl->conn_ifaddr, &index);
			if (ret == 0) {
					p2papi_save_bssidx(hdl, P2PAPI_BSSCFG_CONNECTION, index);
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_osl_create_bss: created bss %u\n",
					hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]));
			}
		} else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_osl_create_bss: create bss failed, ret=%d\n", ret));
		}
	} else if (osl_hdl->softap.bssidx == -1) {
		chanspec_t chspec;

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_create_bss: softAP, bsscfg idx=%d\n",
			hdl->default_bsscfg_idx));

		/* Setting this flag causes the WLC event handler to save the next
		 * WLC_E_IF event's network interface name into hdl->conn_ifname.
		 */
		p2posl_sem_reset(osl_hdl->bss_create_sem);
		hdl->conn_bsscfg_create_ack_wait = TRUE;

		index = hdl->default_bsscfg_idx;
		p2papi_save_bssidx(hdl, P2PAPI_BSSCFG_CONNECTION, index);

		/* For non-P2P SoftAP mode, use only non-P2P driver features to
		 * create the bss: the first iovar/ioctl set applied to the non-existent BSS 1
		 * will implicitly create the BSS.
		 */
		(void) p2pwl_set_ssid(wl, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION],
			hdl->fname_ssid, hdl->fname_ssid_len);

		/* Before we issue any more ioctls on the new BSS, wait for the
		 * completion of the internal exchange of BSS bringup messages
		 * between DHD and dongle.
		 */
		ret = p2posl_sem_wait(osl_hdl->bss_create_sem, 1000, BCMP2P_LOG_MED);

		/* Set the BSS channel */
		p2papi_channel_to_chspec(&hdl->op_channel, &chspec);
		(void) p2pwlu_set_chanspec(hdl, chspec,
			hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"softap has been created before, bsscfg idx=%d\n",
			osl_hdl->softap.bssidx));

		/* Reuse previously cached softap bss */
		index = osl_hdl->softap.bssidx;

		/* Copy interface name and bssidx of softap to connection bss */
		p2posl_save_bssname(wl, P2PAPI_BSSCFG_CONNECTION, osl_hdl->softap.ifname);
		p2papi_save_bssidx(hdl, P2PAPI_BSSCFG_CONNECTION, index);

		strncpy(hdl->conn_ifname,
			osl_hdl->softap.ifname,
			sizeof(hdl->conn_ifname) - 1);

		(void) p2papi_osl_ap_mode_ifup(hdl, hdl->conn_ifname);
	}

	return ret;
}


/* Do any OS-specific actions needed to complete bringing up the connection BSS
 */
static int
p2papi_osl_connection_ifup(p2papi_instance_t* hdl, char *ifname,
	bool is_ap_mode)
{
	p2papi_osl_instance_t *osl_hdl;
	void *wl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	wl_hdl = P2PAPI_GET_WL_HDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_osl_connection_mode_ifup: ifname=%s\n",
		ifname ? ifname : "NULL"));

	/* Prepare the ioctl interface to operate on the network interface */
	if (is_ap_mode)
		p2posl_set_netif_for_ap_mode(wl_hdl, TRUE, hdl->conn_ifname);
	else
		p2posl_set_netif_for_sta_mode(wl_hdl, TRUE, hdl->conn_ifname);

	/* Bring up the network interface if not already up */
	p2posl_ifup(hdl->conn_ifname, (void *)hdl);

	/* Signal waiting thread that interface is up. */
	p2posl_sem_signal(osl_hdl->bss_create_sem);

	return 0;
}

/* Do any OS-specific actions needed to complete bringing up the AP BSS */
int
p2papi_osl_ap_mode_ifup(p2papi_instance_t* hdl, char *ifname)
{
	return p2papi_osl_connection_ifup(hdl, ifname, TRUE);
}

/* Do any OS-specific actions needed to complete bringing up the STA BSS */
int
p2papi_osl_sta_mode_ifup(p2papi_instance_t* hdl, char *ifname)
{
	return p2papi_osl_connection_ifup(hdl, ifname, FALSE);
}

/* Do any OS-specific actions needed prior to bringing down the connection BSS.
 */
static int
p2papi_osl_connection_ifdown(p2papi_instance_t* hdl, bool is_ap_mode)
{
	void *wl;
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = (p2papi_osl_instance_t*) hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_connection_ifdown\n"));

	/* Do any necessary OS-specific actios before bringing down the connection
	 * network interface.
	 */
	if (is_ap_mode)
		p2posl_set_netif_for_ap_mode(wl, FALSE, NULL);
	else
		p2posl_set_netif_for_sta_mode(wl, FALSE, NULL);

	/* Bring down the connection network interface */
	p2posl_ifdown(p2papi_osl_get_ap_mode_ifname(hdl));

	return 0;
}

/* Do any OS-specific actions needed prior to bringing down the AP BSS */
int
p2papi_osl_ap_mode_ifdown(p2papi_instance_t* hdl)
{
	return p2papi_osl_connection_ifdown(hdl, TRUE);
}

/* Do any OS-specific actions needed prior to bringing down the STA BSS */
int
p2papi_osl_sta_mode_ifdown(p2papi_instance_t* hdl)
{
	return p2papi_osl_connection_ifdown(hdl, FALSE);
}


/* Check if we are connected to a BSS on the connection (virtual) BSS.
 * Call this only on the peer acting as a STA.
 */
bool
p2papi_osl_is_associated(p2papi_instance_t *hdl, struct ether_addr *out_bssid)
{
	P2PWL_HDL wl_hdl = P2PAPI_GET_WL_HDL(hdl);

	return p2pwl_is_associated_bss(wl_hdl, out_bssid,
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
}

/* Check if we are associated on the primary BSS
 * (Check if we have an existing concurrent connection in addition to the new
 * P2P connection we are going to create on a virtual BSS.)
 */
bool
p2papi_osl_is_primary_bss_assoc(struct p2papi_instance_s *hdl,
	struct ether_addr *out_bssid)
{
	P2PWL_HDL wl = P2PAPI_GET_WL_HDL(hdl);
	bool ret;

	P2PAPI_WL_CHECK_HDL(wl);
	ret = p2pwl_is_associated_bss(wl, out_bssid, 0);
	return ret;
}

/* Get the current channel of the primary (non-P2P) BSS.
 * ie. if we have an existing concurrent connection in addition to the
 * new P2P connection we are going to create on the virtual BSS, this call
 * gets the existing connection's channel.
 */
int
p2papi_osl_get_primary_bss_channel(struct p2papi_instance_s *hdl,
	int *out_channel)
{
	channel_info_t ci;
	int ret;
	P2PWL_HDL wl = P2PAPI_GET_WL_HDL(hdl);

	P2PAPI_WL_CHECK_HDL(wl);
	memset(&ci, 0, sizeof(ci));

	/* Get the channel of BSS 0 */
	ret = p2posl_wl_ioctl_bss(wl, WLC_GET_CHANNEL, &ci, sizeof(ci), FALSE, 0);
	if (ret == 0) {
		ci.hw_channel = dtoh32(ci.hw_channel);
		ci.scan_channel = dtoh32(ci.scan_channel);
		ci.target_channel = dtoh32(ci.target_channel);

		*out_channel = ci.hw_channel;

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s channel   ==> %d\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, 0), *out_channel));
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_get_primary_bss_chan: macch=%d targch=%d scanch=%d\n",
			ci.hw_channel, ci.target_channel, ci.scan_channel));
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"---wl%s%s channel   ==> error %d\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, 0), ret));
	}

	return ret;
}


int
p2papi_osl_signal_escan_state(struct p2papi_instance_s *hdl,
	P2PAPI_OSL_ESCAN_STATE escan_state)
{
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	switch (escan_state) {
	case P2PAPI_OSL_ESCAN_STATE_START:
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_osl_signal_escan: START\n"));
		return (p2posl_sem_reset(osl_hdl->escan_sem) == 0)
			? BCMP2P_SUCCESS : BCMP2P_ERROR;
	case P2PAPI_OSL_ESCAN_STATE_DONE:
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_osl_signal_escan: DONE\n"));
		return (p2posl_sem_signal(osl_hdl->escan_sem) == 0)
			? BCMP2P_SUCCESS : BCMP2P_ERROR;
	case P2PAPI_OSL_ESCAN_STATE_ABORT:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_escan: ABORT\n"));
		return (p2posl_sem_signal(osl_hdl->escan_sem) == 0)
			? BCMP2P_SUCCESS : BCMP2P_ERROR;
	default:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_escan: bad escan_state %d\n", escan_state));
		break;
	}
	return BCMP2P_ERROR;

}

int
p2papi_osl_wait_for_escan_complete(p2papi_instance_t* hdl, int timeout_ms)
{
	p2papi_osl_instance_t *osl_hdl;
	P2POSL_STATUS ret;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	ret = p2posl_sem_wait(osl_hdl->escan_sem, timeout_ms, BCMP2P_LOG_MED);
	if (ret == P2POSL_SUCCESS) {
		return BCMP2P_SUCCESS;
	} else {
		return BCMP2P_ERROR;
	}
}


int
p2papi_osl_signal_client_assoc_state(struct p2papi_instance_s *hdl,
	P2PAPI_OSL_CLIENT_ASSOC_STATE client_assoc_state)
{
	p2papi_osl_instance_t *osl_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	switch (client_assoc_state) {
	case P2PAPI_OSL_CLIENT_ASSOC_STATE_START:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_client_assoc_state: START\n"));
		return (p2posl_sem_reset(osl_hdl->client_assoc_sem) == 0)
			? BCMP2P_SUCCESS : BCMP2P_ERROR;
	case P2PAPI_OSL_CLIENT_ASSOC_STATE_ASSOC:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_client_assoc_state: ASSOC\n"));
		return (p2posl_sem_signal(osl_hdl->client_assoc_sem) == 0)
			? BCMP2P_SUCCESS : BCMP2P_ERROR;
	case P2PAPI_OSL_CLIENT_ASSOC_STATE_DISASSOC:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_client_assoc_state: DISASSOC\n"));
		return (p2posl_sem_signal(osl_hdl->client_assoc_sem) == 0)
			? BCMP2P_SUCCESS : BCMP2P_ERROR;
	case P2PAPI_OSL_CLIENT_ASSOC_STATE_ABORT:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_client_assoc_state: ABORT\n"));
		return (p2posl_sem_signal(osl_hdl->client_assoc_sem) == 0)
			? BCMP2P_SUCCESS : BCMP2P_ERROR;
	default:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_osl_signal_client_assoc_state: bad client state %d\n",
			client_assoc_state));
		break;
	}
	return BCMP2P_ERROR;

}

int
p2papi_osl_wait_for_client_assoc_or_disassoc(p2papi_instance_t* hdl,
	int timeout_ms)
{
	p2papi_osl_instance_t *osl_hdl;
	P2POSL_STATUS ret;

	P2PAPI_CHECK_P2PHDL(hdl);
	osl_hdl = hdl->osl_hdl;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_osl_wait_for_client_assoc_or_disassoc: tmo=%d ms\n",
		timeout_ms));
	ret = p2posl_sem_wait(osl_hdl->client_assoc_sem, timeout_ms,
		BCMP2P_LOG_VERB);
	if (ret == P2POSL_SUCCESS) {
		return BCMP2P_SUCCESS;
	} else {
		return BCMP2P_ERROR;
	}
}

/* Signal the OSL that this STA device is about to send a provdis-request
 *     or has received a provdis-response
 * -- signalling PROVDIS-RESPONSE-RECEIVED unblocks any threads that have
 *    blocked on p2papi_osl_wait_for_rx_provdis_response().
 */
int
p2papi_osl_signal_provdis_state(struct p2papi_instance_s *p2pHdl, 
	P2PAPI_OSL_PROVDIS_STATE provdis_state)
{
	return BCMP2P_ERROR;		/* for caller to use a polling mechanism */
}

int
p2papi_osl_wait_for_rx_provdis_response(p2papi_instance_t* hdl, 
	int timeout_ms)
{
	int nRet = BCMP2P_ERROR;	/* not implemented */
}

/* Get time since process start in millisec */
unsigned int p2papi_osl_gettime(void)
{
	return p2posl_gettime();
}

/* Diff newtime and oldtime in ms */
unsigned int p2papi_osl_difftime(unsigned int newtime, unsigned int oldtime)
{
	return p2posl_difftime(newtime, oldtime);
}

#if P2PAPI_ENABLE_WPS
/* Get the driver's cached rx probe request wps ie and deliver it to WPSCLI.
 * For Linux and RTOS this is an empty stub because in these OSes, the p2plib
 * can receive WLC_E_* driver events.  In these OSes the common code's
 * p2papi_rx_wl_event() event handler will parse and deliver probe req wps ies
 * to WPSCLI.
 */
int p2papi_osl_get_probereq_wpsie(struct p2papi_instance_s *hdl,
	uint8 *mac, uint8 *bufdata, int *buflen)
{
/*
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_osl_get_probereq_wpsie: do nothing\n"));
*/
	(void) hdl;
	(void) mac;
	(void) bufdata;
	(void) buflen;
	return BCME_ERROR;
}
#endif /* P2PAPI_ENABLE_WPS */
