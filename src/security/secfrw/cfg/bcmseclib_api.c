/*
 * cfg_api.c
 * Platform independent configuration interface
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcmseclib_api.c,v 1.3 2010-12-11 00:06:33 $
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <typedefs.h>
#include <bcmsec_types.h>
#include <proto/ethernet.h>
#include <proto/802.11.h>

#include <bcmseclib_api.h>
#include <methods.h>
#include <debug.h>

#include <typedefs.h>
#include <bcm_osl.h>
#include <dispatcher.h>
#include <cfg.h>

#include <bcmseclib_timer.h>
#include <wpa_cfg.h>

#include <bcm_lbuf.h>


/* this is a tunable parameter
 * TODO: setup a cfg file for this stuff
 */
#define BCMSECLIB_MAX_TIMERS	32


/* startup
 * register callback functions
 * setup timers, allocate data structures ...
 * returns zero if successful, non-zero otherwise
 */

int bcmseclib_init(struct maincbs* cbfns)
{
	int status;


	/* init osl & utilities (including lbufs) */
	osl_init();

	/* init timers */
	bcmseclib_init_timer_utilities(BCMSECLIB_MAX_TIMERS);

	/* init dispatcher */
	status = disp_lib_init(cfg_process_cfgmsg);
	if (status) {
		PRINT_ERR(("bcmseclib_init: failed to init dispatcher, bailing\n"));
		return -1;
	}

	/* init methods */
	wpa_auth_init();
	wpa_sup_init();

	return 0;
}

/* run it:
 * This is the thread containing the dispatch loop.
 * Blocks on [io descriptors]
 * Only returns if error or terminated by bcmseclib_deinit
 */

int bcmseclib_run()
{
	PRINT(("%s: entry\n", __FUNCTION__));
	disp_lib_run();
	return 0;
}

/* shutdown: terminate everything
 * disconnect, close descriptors, free memory, ...
 * Returns zero for success, non-zero otherwise
 * User should de-init all contexts allocated before calling this fn.
 *
 */

int bcmseclib_deinit(void)
{
	cfg_terminate_t msg;

	memset(&msg, 0, sizeof(msg));

	msg.hdr.type = CFG_TERMINATE_REQUEST;
	disp_lib_cfg((char *)&msg, sizeof(msg));

	return 0;
}

void bcmseclib_ctx_init(clientdata_t *client, struct ctxcbs *cbfns)
{
	cfg_ctx_init_t msg;

	memset(&msg, 0, sizeof(msg));

	/* ctx, version already zero */
	msg.hdr.type = CFG_CTX_INIT;
	memcpy(&msg.cbfns, cbfns, sizeof(struct ctxcbs));
	msg.client = client;

	disp_lib_cfg((char *)&msg, sizeof(msg));
}

void bcmseclib_ctx_cleanup(bcmseclib_ctx_t *ctx)
{
	cfg_ctx_deinit_t msg;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = CFG_CTX_DEINIT;
	msg.hdr.ctx = ctx;

	disp_lib_cfg((char *)&msg, sizeof(msg));
}

void bcmseclib_set_config(struct sec_args *args, bcmseclib_ctx_t *ctx)
{
	cfg_ctx_set_cfg_t msg;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = CFG_CTX_SET_CFG;
	msg.hdr.ctx = ctx;

	memcpy(&msg.args, args, sizeof(struct sec_args));

	disp_lib_cfg((char *)&msg, sizeof(msg));
}
