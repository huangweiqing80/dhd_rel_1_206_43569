/*****************************************************************************
 * WPA configuration
 *
 *****************************************************************************
*/

#include <string.h>				/* for memcpy */
#include <typedefs.h>
#include <bcmutils.h>			/* BCME_XXX */

#include <debug.h>

#include <proto/802.11.h>		/* for DOT11_MAX_SSID_LEN */
#include <bcmsec_types.h>		/* for clientdata_t */
#include <bcmseclib_api.h>		/* for struct ctxcbs */
#include <cfg.h>

#include <bcmwpa.h>
#include <bind_skp.h>
#define WPA_CFG_PRIVATE
#include <wpa_cfg.h>


static int
hash_psk(struct cfg_ctx *, const uint8 *psk, int psk_len, uint8 *pmk,
		 int *pmk_len, const uint8 *ssid, int ssid_len);

/* This function is a bridge between an inbound configuration and the
 * private data used by the adaptation layer (AL).  The private data should be
 * configured to a point that permits the AL to initialize.  The AL treats
 * the configuration as read-only data.
 *
 * The implementation of this function depends on the transport mechanism
 * selected for the configuration.  For example, out-of-process clients will
 * "(un)pack" this configuration differently from in-process clients.
*/
extern int
wpa_cfg(struct cfg_ctx *ctx, struct wpa_dat *dat,
		const struct cfg_ctx_set_cfg *pmsg)
{
	int status, psk_len;

	psk_len = pmsg->args.psk_len;

	dat->WPA_auth = pmsg->args.WPA_auth;
	dat->wsec = pmsg->args.wsec;
	
	if (psk_len > 0) {
		/* calculate a PMK from a PSK */
		status = hash_psk(ctx, pmsg->args.psk, psk_len, dat->pmk,
						  &dat->pmk_len, pmsg->args.ssid, pmsg->args.ssid_len);
		if (BCME_OK != status)
			return status;

	} else {
		dat->pmk_len = 0;
	}

	dat->result = pmsg->args.result;

	dat->role = pmsg->args.role;
	dat->btamp_enabled = pmsg->args.btamp_enabled;

	return BCME_OK;
}

/* inline? */
extern void
wpa_set_ctx(struct wpa_dat *dat, struct cfg_ctx *ctx)
{
	dat->ctx = ctx;
}

/* inline? */
extern struct cfg_ctx *
wpa_get_ctx(struct wpa_dat *dat)
{
	return dat->ctx;
}

/* set eapol tx context */
extern void
wpa_set_eapol_tx(struct wpa_dat *dat, void *tx)
{
	dat->eapol_tx = tx;
}

#include <stdlib.h>				/* strtoul */
#include <ctype.h>				/* isxdigit */
#include <bcmcrypto/sha1.h>

/* forward passhash function to get constness right */
extern int
passhash(const char *password, int passlen, const unsigned char *ssid,
		 int ssidlen, unsigned char *output);
		 
/* Given a pre-shared key psk, ssid
 * Apply passhash as appropriate, deposit result in parameter pmk
 * Return BCME_OK for ok, non-zero for failure
 * Adapted from nas procedure nas_wksp.c:nas_init_nas
 *
 */
static int
hash_psk(struct cfg_ctx *ctx, const uint8 *psk, int psk_len, uint8 *pmk,
		 int *pmk_len, const uint8 *ssid, int ssid_len)
{
#ifdef DEBUG
		char *funstr = "hash_psk";
#endif


		if (psk == NULL || psk_len < WPA_MIN_PSK_LEN) {
			CTXERR((ctx, "%s: insufficient key material for psk\n", \
						 funstr));
			return BCME_BADARG;
		}
		/* numeric key must be 256-bit. */
		/* allow leading hex radix for a proper size number */
		if ((psk_len == WSEC_MAX_PSK_LEN + 2) &&
			 (!strncmp((char *)psk, "0x", 2) || !strncmp((char *)psk, "0X", 2))) {
			psk += 2;
			psk_len -=2;
		}

		/* Exactly 256 bits: verify contents */
		if (psk_len == WSEC_MAX_PSK_LEN) {
			int j = 0;
			char hex[] = "XX";
			do {
				hex[0] = *psk++;
				hex[1] = *psk++;
				if (!isxdigit((int)hex[0]) ||
				    !isxdigit((int)hex[1])) {
					CTXERR((ctx, "%s: numeric PSK not 256-bit hex number\n",
								 funstr));
					return BCME_BADARG;
				}
				*pmk++ = (uint8)strtoul(hex, NULL, 16);
			} while (++j < DOT11_MAX_KEY_SIZE);
		} else if (psk_len < WSEC_MAX_PSK_LEN) {
			/* hash it */
			unsigned char output[2*SHA1HashSize];

			/* perform password to hash conversion */
			if (passhash((char *)psk, psk_len, ssid, ssid_len, output)) {
				CTXERR((ctx, "%s: PSK password hash failed\n", funstr));
				return BCME_ERROR;
			}
			memcpy(pmk, output, PMK_LEN);
		} else {
			CTXERR((ctx, "%s: illegal PSK length\n", funstr));
			return BCME_BADARG;
		}
		*pmk_len = PMK_LEN;

	return BCME_OK;
}
