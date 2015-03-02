/*
 * bcm_authenv.c -- user space authenticator env funs
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcm_authenv.c,v 1.1.1.1 2010-02-04 00:44:37 $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <typedefs.h>
#include <bcmsec_types.h>
#include <wlioctl.h>
#include <bcm_supenv.h>
#include <proto/eapol.h>
#include <proto/eap.h>
#include <bcmwpa.h>

#include <bcmendian.h>
#include <bcmcrypto/prf.h>

#if defined(BCM_OSL)
#include "osl.h"
#else
#include <bcm_osl.h>
#endif

#include <wlc_security.h>
#include <bcmseclib_timer.h>
#include <bcm_supenv.h> /* for those pesky wlc defs in wlc_wpa.h et al */
#include <wlc_wpa.h>
#include <bcm_authenv.h>

#include <wpaif_auth.h>
#include <wlc_auth.h>
#include <bcmutils.h>
#include <bcm_llist.h>
#include <debug.h>

/* Our own pkt get:
 * setup a frame of specified len
 * leave space at head for ether header (but don't fill it in)
 * Fill in a few useful eapol key fields
 */
void *
bcm_authenv_pktget(struct sta_parms *suppctx, int len)
{
	void *p;
	eapol_header_t *eapol_hdr;

	if ((p = PKTGET(NULL, len + TXOFF, TRUE)) == NULL) {
		PRINT_ERR(("wpaif_auth_pktget: pktget of len %d failed\n", len));
		return (NULL);
	}
	ASSERT(ISALIGNED((uintptr)PKTDATA(osh, p), sizeof(uint32)));

	/* reserve TXOFF bytes of headroom */
	PKTPULL(NULL, p, TXOFF);
	PKTSETLEN(NULL, p, len);

	/* fill in common header fields */
	eapol_hdr = (eapol_header_t *) PKTDATA(NULL, p);

#if defined(BCMWPA2) && defined(BCMSUP_PSK)
	if (IS_WPA2_AUTH(suppctx->auth->WPA_auth)) {
		if ((suppctx->auth->sup_wpa2_eapver == -1) && (suppctx->auth->sup != NULL) &&
		    (suppctx->auth->sup)->ap_eapver) {
			eapol_hdr->version = (suppctx->auth->sup)->ap_eapver;
		} else if (suppctx->auth->sup_wpa2_eapver == 1) {
			eapol_hdr->version = WPA_EAPOL_VERSION;
		} else {
			eapol_hdr->version = WPA2_EAPOL_VERSION;
		}
	} else
#endif /* defined(BCMWPA2) && defined(BCMSUP_PSK) */
	eapol_hdr->version = WPA_EAPOL_VERSION;
	return p;
}

void
bcm_authenv_cleanup_wpa(osl_t *osh, wpapsk_t *wpa)
{
	/* Toss IEs if there are any */
	if (wpa->auth_wpaie != NULL) {
		MFREE(osh, wpa->auth_wpaie, wpa->auth_wpaie_len);
		wpa->auth_wpaie = NULL;
		wpa->auth_wpaie_len = 0;
	}
	if (wpa->sup_wpaie != NULL) {
		MFREE(osh, wpa->sup_wpaie, wpa->sup_wpaie_len);
		wpa->sup_wpaie = NULL;
		wpa->sup_wpaie_len = 0;
	}
	bzero((char *)wpa, sizeof(wpapsk_t));
}
