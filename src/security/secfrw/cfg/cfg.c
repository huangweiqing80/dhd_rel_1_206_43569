/*
 * cfg.c
 * Platform independent internal configuration functions
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: cfg.c,v 1.4 2010-12-11 00:06:33 $
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <typedefs.h>
#include <bcmsec_types.h>
#include <ctype.h>

#include <proto/802.11.h>
#include <bcmutils.h>
#include <wlioctl.h>

#include <bcmseclib_api.h>
#include <cfg.h>
#include <pp_cfg.h>
#include <methods.h>
#include <wpa_svc.h>
#include <dispatcher.h>
#include <bcm_osl.h>
#include <bcm_lbuf.h>
#include <debug.h>
#include <bcm_llist.h>
#include <dev.h>
#include <bta_svc.h>

#if defined(WPS)
#include <wps_svc.h>
#endif /* defined(WPS) */

typedef struct cfg_ctx cfg_ctx_t;

/* We manage our whole enterprise out of this data structure!
 * Well, not quite. The dispatcher & timer modules maintain their
 * own too.
 * This one holds config info for all interfaces registered with us.
 */
static struct cfg_wksp {

	/* workspace callbacks */
	struct maincbs wksp_cb;

	/* List of active contexts */
	cfg_ctx_t *ctx_list;

}cfg_workspace;

struct svc {
	int role;
	int service;
	int (*init)(struct cfg_ctx *);
	int (*deinit)(struct cfg_ctx *);
	int (*cfg)(struct cfg_ctx *, const cfg_ctx_set_cfg_t *);
};

/* These role, service pairs MUST be unique! */
static struct svc sg_service[] = {
{ 0, /* wpa supplicant */
  0, /* wlan */
  wpa_sup_svc_init,
  wpa_sup_svc_deinit,
  wpa_svc_cfg,
},
{ 1, /* wpa authenticator */
  0, /* wlan */
  wpa_auth_svc_init,
  wpa_auth_svc_deinit,
  wpa_svc_cfg,
},
{ 2, /* bta parent */
  0, /* wlan */
  btaparent_svc_init,
  btaparent_svc_deinit,
  btaparent_svc_cfg,
},
{ 0, /* bta child sup */
  1, /* btamp */
  btachild_svc_sup_init,
  btachild_svc_sup_deinit,
  btachild_svc_cfg,
},
{ 1, /* bta child auth */
  1, /* btamp */
  btachild_svc_auth_init,
  btachild_svc_auth_deinit,
  btachild_svc_cfg,
},
#if defined(WPS)
{ 3, /* wps-sup */
  0, /* wlan */
  wps_sup_svc_init,
  wps_sup_svc_deinit,
  wps_sup_svc_cfg,
},
{ 4, /* wps-auth */
  0, /* wlan */
  wps_auth_svc_init,
  wps_auth_svc_deinit,
  wps_auth_svc_cfg,
},
#endif /* defined(WPS) */
};

/* forward */
void cfg_shutdown();
cfg_ctx_t * cfg_allocate_new_ctx(void *pkt);
int cfg_config_ctx(void *pkt);
int cfg_util_hash_psk(uint8 *psk, int psk_len, uint8 *pmk, int *pmk_len,
	uint8 *ssid, int ssid_len, char *ifname);
void cfg_cleanup_ctx(cfg_ctx_t *ctx);

bool
cfg_validate_ctx(void *ctx)
{
	cfg_ctx_t *plist;

	for (plist = cfg_workspace.ctx_list ; plist; plist = plist->next) {
		if (plist == (cfg_ctx_t *)ctx)
			return TRUE;
	}
	return FALSE;
}

/* Discussion and Limitations
 * This design works in a multi-threaded SINGLE process environment.
 * Communicating with outside processes requires considerably more work.
 * We'll need to marshal args at both ends, establish some kind of api for
 * the communications channel, etc. Anyone for RPC?
 * In the meantime, try to make everything modular enough so that if the need
 * arises we can add this in with minimal injury.
 */

/* Process [de]configuration requests
 * Issue callback function (previously registered by cfg api)
 * upon completion
 */
void
cfg_process_cfgmsg(void *pkt)
{

	cfg_msg_t *p = (cfg_msg_t *)PKTDATA(NULL, pkt);
	static char *funstr = "cfg_process_cfgmsg";
	int len;

	PRINT(("%s: cfg_process_cfgmsg: entry\n", funstr));
	/* printf("Received: %s\n", PKTDATA(NULL, pkt)); */

	/* if ctx is NULL:
	 * check if this is a new config OR a TERMINATE request
	 * if not, error out
	 *
	 * For new config:
	 * Allocate a ctx and return it in the [newly] registered callback fn
	 * For TERMINATE:
	 * call shutdown procedure
	 */
	len = PKTLEN(NULL, pkt);
	if (p == NULL || len < sizeof(cfg_msg_t)) {
		PRINT_ERR(("%s: bad args pkt %p pktlen %d\n", funstr, p, len));
		goto done;
	}
	if ((char *)p->ctx == NULL) {
		if (p->type != CFG_CTX_INIT && p->type != CFG_TERMINATE_REQUEST) {
			PRINT_ERR((
			"%s: bad args: NULL ctx with msgtype %d\n, bailing", funstr, p->type));
			goto done;
		}

		if (p->type == CFG_TERMINATE_REQUEST) {
			/* Can NOT go through done label:
			 * shutdown procedure de-inits lbufs etc
			 * Free the pkt here and now.
			 */
			PRINT(("%s: Processing terminate request\n", funstr));
			PKTFREE(NULL, pkt, FALSE);
			/* call shutdown procedure */
			cfg_shutdown();
			return;
		}

		if (p->type == CFG_CTX_INIT) {
			cfg_allocate_new_ctx(PKTDATA(NULL, pkt));
			goto done;
		}

	} /* END NULL ctx processing */

	/* If a valid ctx:
	 * Call helper functions to validate request and [re]config as required
	 * Helper funs return results (success/failure) in registered cb fun
	 */

	/* Validate the ctx pointer */
	if (cfg_validate_ctx(p->ctx) == FALSE) {
		PRINT_ERR(("%s: invalid ctx pointer (0x%p)! Bailing ...\n", funstr, p->ctx));
		goto done;
	}
	switch (p->type) {
		case CFG_CTX_SET_CFG:
			cfg_config_ctx(PKTDATA(NULL, pkt));
			break;

		case CFG_CTX_DEINIT:
		{
			struct cfg_ctx * ctx, *tmp;
			/* walk the ctx list looking for child ctx's from this ctx */
			for (ctx = cfg_workspace.ctx_list; ctx; ) {
				tmp = ctx->next;
				if (ctx->parent == p->ctx) {
					bcm_llist_del_member(&cfg_workspace.ctx_list, ctx);
					cfg_cleanup_ctx(ctx);
					OS_FREE(ctx);
				}
				ctx = tmp;
			}
			bcm_llist_del_member(&cfg_workspace.ctx_list, p->ctx);
			cfg_cleanup_ctx(p->ctx);
			OS_FREE(p->ctx);
			break;
		}

		default:
			PRINT_ERR(("%s: Unrecognized msgtype %d\n", funstr, p->type));
			break;
	}

done:
	PKTFREE(NULL, pkt, FALSE);
	return;

}

/* The end:
 * We've been told to quit
 * Unwind everything, deallocate memory, shutdown the dispatcher
 * As a final act use the registered cb fun to report success/failure
 */
void
cfg_shutdown()
{

	/* walk the list of registered ctx's
	 *
	 * call their cfg_status cb's if non-NULL
	 *
	 * Clean them up:
	 * unwind their respective supplicant/authenticator inits
	 * remove from the cfg_workspace.ctx_list
	 */
	cfg_ctx_t *ctx;

	for (ctx = cfg_workspace.ctx_list ; ctx; ctx = cfg_workspace.ctx_list) {
		bcm_llist_del_member(&cfg_workspace.ctx_list, ctx);
		cfg_cleanup_ctx(ctx);
		OS_FREE(ctx);
	}

	/* Call the dispatcher's teardown method */
	disp_lib_deinit();

	/* who else ? */

	/* call our registered cb if non-NULL */

	/* done */
}

/* Initialize ctx data structures */
static void
cfg_ctx_init(struct cfg_ctx *ctx, void *clientdata,
			 const struct ctxcbs *ctxcbs)
{
	/* zero the context data structure */
	cfg_ctx_zero(ctx);

	/* unconfigured */
	ctx->is_cfgd = 0;

	/* set common fields */
	ctx->client_data = clientdata;
	memcpy(&ctx->ctx_cb, ctxcbs, sizeof *ctxcbs);

	/* set data pointers */
	ctx->svc_dat = cfg_ctx_svc_dat(ctx);
	ctx->pp_dat = cfg_ctx_pp_dat(ctx);
}

/* Get a new ctx pointer and do basic ctx init
 * If successful return ctx in the cb fun supplied with the request
 * otherwise report failure using the supplied cb fun.
 */
cfg_ctx_t *
cfg_allocate_new_ctx(void *pkt)
{
	cfg_ctx_t *ctx;
	cfg_ctx_init_t *pmsg = (cfg_ctx_init_t *)pkt;
	int status = BCME_ERROR;

	/* allocate memory for a new context data structure */
	if (NULL == (ctx = OS_MALLOC(cfg_ctx_sizeof()))) {
		PRINT_ERR(("Failed to allocate new ctx, bailing\n"));
		status = BCME_NORESOURCE;
		goto DONE;
	}

	/* initialize context memory */
	cfg_ctx_init(ctx, pmsg->client, &pmsg->cbfns);

	/* add to the list */
	ctx->next = cfg_workspace.ctx_list;
	cfg_workspace.ctx_list = ctx;

	/* set callback error code: we passed */
	status = BCME_OK;

DONE:
	/* callback with results */
	if (pmsg->cbfns.cfg_status) {
		(*(pmsg->cbfns.cfg_status))(ctx, pmsg->client, status);
	}
	return ctx;
}

void
cfg_cleanup_ctx(cfg_ctx_t *ctx)
{
	char *funstr = "cfg_cleanup_ctx";

	PRINT(("%s: entry\n", funstr));

	if (!ctx->is_cfgd)
		goto DONE;

	/* Un-init whatever supplicant/authenticator stack we were using */
	if (NULL != ctx->svc->deinit)
		(*ctx->svc->deinit)(ctx);
	ctx->svc = NULL;

	dev_deinit(ctx);

	ctx->is_cfgd = 0;

	/* Free any memory allocated for this ctx: none thus far */

DONE:
	/* Issue the status callback */
	if (ctx->ctx_cb.cfg_status) {
		(*ctx->ctx_cb.cfg_status)(ctx, ctx->client_data, 0);
	}

}

static int
cfg_dev_init(struct cfg_ctx *ctx, const cfg_ctx_set_cfg_t *pmsg)
{
	dev_info_t info;
	int status = BCME_OK;

	/* validate arguments */
	if (pmsg->args.ifname[0] == '\0' || pmsg->args.bsscfg_index < 0)
		return BCME_BADARG;

	/* fake the private data for a new device */
	memcpy(&info, pmsg->args.ifname, sizeof(info.ifname));
	info.bsscfg_index = pmsg->args.bsscfg_index;
	info.service = pmsg->args.service;

	/* initialize */
	status = dev_init(ctx, &info);
	if (BCME_OK != status)
		goto DONE;

DONE:
	return status;
}

static int
cfg_svc_init(struct cfg_ctx *ctx, const cfg_ctx_set_cfg_t *pmsg)
{
	size_t i;
	struct svc *svc;
	int status = BCME_OK;

	/* select the requested service */
	for (i=0, svc=NULL; i<ARRAYSIZE(sg_service); i++) {
		if (sg_service[i].role == pmsg->args.role &&
			sg_service[i].service == pmsg->args.service) {
			svc = &sg_service[i];
			break;
		}
	}
	if (NULL == svc) {
		PRINT_ERR(("unsupported service 0x%x\n", pmsg->args.role));
		status = BCME_UNSUPPORTED;
		goto DONE;
	}

	/* unpack the service configuration */
	if (NULL != svc->cfg)
		status = (*svc->cfg)(ctx, pmsg);
	if (BCME_OK != status)
		goto DONE;

	/* initialize the service */
	if (NULL != svc->init)
		status = (*svc->init)(ctx);
	if (BCME_OK != status)
		goto DONE;

	ctx->svc = svc;

DONE:
	return status;
}

/* Perform the configuration request
 * Parse out the request, validate args, and apply the configuration
 * Return result via registered cb fun
 *
 * So far only two methods available:
 * WPAx-PSK authenticator and supplicant
 */
int
cfg_config_ctx(void *pkt)
{
	int status = BCME_ERROR;
	cfg_ctx_set_cfg_t *pmsg = (cfg_ctx_set_cfg_t *)pkt;
	cfg_ctx_t *ctx;
	cfg_ctx_t *plist;

	ctx = pmsg->hdr.ctx;

	/* validate the args */
	if (cfg_validate_ctx(ctx) == FALSE) {
		status = BCME_BADARG;
		goto ERR0;
	}

	/* initialize device */
	status = cfg_dev_init(ctx, pmsg);
	if (BCME_OK != status)
		goto ERR0;

	/* Walk the list of existing context configs:
	 * If the supplied ifname, bsscfg_index are already in use: error
	 * Bail out.
	 */
	for (plist = cfg_workspace.ctx_list; plist; plist = plist->next) {
		if (!dev_cmp(plist, ctx) && plist != ctx) {
			status = BCME_BADARG;
			goto ERR1;
		}
	}

	/* initialize service */
	status = cfg_svc_init(ctx, pmsg);
	if (BCME_OK != status)
		goto ERR1;

	ctx->is_cfgd = 1;

	goto ERR0;

ERR1:
	dev_deinit(ctx);
ERR0:
	/* callback with status */
	if (ctx->ctx_cb.cfg_status) {
		(*ctx->ctx_cb.cfg_status)( ctx, ctx->client_data, status);
	}

	return status;
}


char *btamp_dummy_psk =
"000102030405060708" \
"000102030405060708" \
"000102030405060708" \
"000102030405060708";
extern int
btaparent_create_child(struct cfg_ctx * ctx, uint8 bssidx, uint8 role)
{
	cfg_ctx_t *child_ctx;
	int status;
	cfg_ctx_init_t btachild_ctx_init_msg;
	cfg_ctx_set_cfg_t btachild_ctx_cfg_msg;

	CTXPRT((ctx, "btaparent_create_child:\n" ));
	memset(&btachild_ctx_init_msg, 0, sizeof(btachild_ctx_init_msg));
	memset(&btachild_ctx_cfg_msg, 0, sizeof(btachild_ctx_cfg_msg));

	/* Create a child ctx */
	btachild_ctx_init_msg.hdr.type = CFG_CTX_INIT;
	child_ctx = cfg_allocate_new_ctx(&btachild_ctx_init_msg);
	if (NULL == child_ctx) {
		CTXPRT((ctx, "btaparent_create_child: failed to init child ctx\n"));
		goto errdone;
	}

	/* Config the child ctx for wpa2-psk-aes, auth/supp per role parameter */
	btachild_ctx_cfg_msg.hdr.type = CFG_CTX_SET_CFG;
	btachild_ctx_cfg_msg.hdr.ctx = child_ctx;

	/* get the ifname of the parent */
	status = dev_ifname(ctx, btachild_ctx_cfg_msg.args.ifname, sizeof(btachild_ctx_cfg_msg.args.ifname));
	if (status) {
		CTXPRT((ctx, "btaparent_create_child: can't get parent dev ifname\n"));
		goto errdone;
	}
	btachild_ctx_cfg_msg.args.service = 1;		/* BTAMP */
	btachild_ctx_cfg_msg.args.role = role;  /* 0 supp, 1 auth */
	btachild_ctx_cfg_msg.args.WPA_auth = WPA2_AUTH_PSK;
	btachild_ctx_cfg_msg.args.wsec = CRYPTO_ALGO_AES_CCM;


	btachild_ctx_cfg_msg.args.btamp_enabled = 1;


	strncpy((void *)btachild_ctx_cfg_msg.args.ssid, "BTAMP-DUMMY", strlen("BTAMP-DUMMY"));
	btachild_ctx_cfg_msg.args.ssid_len = strlen(("BTAMP-DUMMY"));

	strncpy((void *)btachild_ctx_cfg_msg.args.psk, btamp_dummy_psk, strlen(btamp_dummy_psk));
	btachild_ctx_cfg_msg.args.psk_len = WSEC_MAX_PSK_LEN;
	btachild_ctx_cfg_msg.args.bsscfg_index = bssidx;

	/* all other args left as zero */

	status = cfg_config_ctx(&btachild_ctx_cfg_msg);
	if (status) {
		CTXPRT((ctx, "btaparent_create_child: can't ocnfig child\n"));
		goto errdone;
	}


	/* mark this ctx as a "child" ctx */
	child_ctx->parent = ctx;

	return 0;

errdone:
	/* de-init the child ctx if it exists */
	if (child_ctx) {
		bcm_llist_del_member(&cfg_workspace.ctx_list, child_ctx);
		cfg_cleanup_ctx(child_ctx);
		OS_FREE(child_ctx);
	}
	return -1;
}


extern int
btaparent_destroy_child(struct cfg_ctx * ctx, uint8 bssidx, uint8 role)
{
	cfg_ctx_t *child_ctx;
	char ifname [MAX_IF_NAME_SIZE + 1];
	int status;

	CTXPRT((ctx, "btaparent_destroy_child:\n" ));
	/* get the ifname of the parent */
	status = dev_ifname(ctx, ifname, sizeof(ifname));
	if (status) {
		CTXPRT((ctx, "btaparent_destroy_child: can't get parent dev ifname\n"));
		goto errdone;
	}

	/* walk the list of ctx's, find the one with matching parameters, destroy it */
	for (child_ctx = cfg_workspace.ctx_list ; child_ctx; child_ctx = child_ctx->next) {
		if (child_ctx->parent == ctx && !dev_match(child_ctx, ifname, bssidx)) {
			/* Clean it up ... */
			bcm_llist_del_member(&cfg_workspace.ctx_list, child_ctx);
			cfg_cleanup_ctx(child_ctx);
			OS_FREE(child_ctx);

			return 0;
		}
	} /* end for */


	/* none such: should not happen */
errdone:
	return -1;
}
