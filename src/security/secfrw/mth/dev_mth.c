/*****************************************************************************
 * Wireless User Tools
 *
 * Wireless helpers
 *****************************************************************************
*/

/*
 * common includes
*/

#include <stdio.h>	/* size_t */


#include <proto/802.11.h>	/* for DOT11_MAX_SSID_LEN */
#include <bcmsec_types.h>	/* for clientdata_t */
#include <bcmseclib_api.h>	/* for struct ctxcbs */
#include <cfg.h>

#include <devp.h>


/*
 * wlss_xxx
*/

#include <proto/ethernet.h>		/* for struct ether_addr */

#include <wlss.h>
#include <wlssb.h>

#include "iwlss.h"

#define IWLSS(ctx) (((struct cfg_ctx *)(ctx))->dev->iwlss)


extern void *
wlss_bind(void *ctx, void (*interest_vector)(void *ctx, void *priv), \
		  int (*rx)(void *arg, void *event, int), void *arg)
{
	return (*IWLSS(ctx)->bind)(ctx, interest_vector, rx, arg);
}

extern int
wlss_unbind(void *ctx, void *priv)
{
	return (*IWLSS(ctx)->unbind)(ctx, priv);
}

extern int
wlss_get_key_seq(void *ctx, void *buf, int buflen)
{
	return (*IWLSS(ctx)->get_key_seq)(ctx, buf, buflen);
}

extern int
wlss_authorize(void *ctx, struct ether_addr *ea)
{
	return (*IWLSS(ctx)->authorize)(ctx, ea);
}

extern int
wlss_deauthorize(void *ctx, struct ether_addr *ea)
{
	return (*IWLSS(ctx)->deauthorize)(ctx, ea);
}

extern int
wlss_deauthenticate(void *ctx, struct ether_addr *ea, int reason)
{
	return (*IWLSS(ctx)->deauthenticate)(ctx, ea, reason);
}

extern int
wlss_get_group_rsc(void *ctx, uint8 *buf, int index)
{
	return (*IWLSS(ctx)->get_group_rsc)(ctx, buf, index);
}

extern int
wlss_plumb_ptk(void *ctx, struct ether_addr *ea, uint8 *tk, int tk_len,
			   int cipher)
{
	return (*IWLSS(ctx)->plumb_ptk)(ctx, ea, tk, tk_len, cipher);
}

extern void
wlss_plumb_gtk(void *ctx, uint8 *gtk, uint32 gtk_len, uint32 key_index,
			   uint32 cipher, uint16 rsc_lo, uint32 rsc_hi, bool primary_key)
{
	return (*IWLSS(ctx)->plumb_gtk)(ctx, gtk, gtk_len, key_index, cipher, \
									rsc_lo, rsc_hi, primary_key);
}

extern int
wlss_wl_tkip_countermeasures(void *ctx, int enable)
{
	return (*IWLSS(ctx)->wl_tkip_countermeasures)(ctx, enable);
}

extern int
wlss_set_ssid(void *ctx, char *ssid)
{
	return (*IWLSS(ctx)->set_ssid)(ctx, ssid);
}

extern int
wlss_disassoc(void *ctx)
{
	return (*IWLSS(ctx)->disassoc)(ctx);
}

extern int
wlss_get_wpacap(void *ctx, uint8 *cap)
{
	return (*IWLSS(ctx)->get_wpacap)(ctx, cap);
}

extern int
wlss_get_stainfo(void *ctx, char *macaddr, int len, char *ret_buf,
				 int ret_buf_len)
{
	return (*IWLSS(ctx)->get_stainfo)(ctx, macaddr, len, ret_buf, ret_buf_len);
}

extern int
wlss_send_frame(void *ctx, void *pkt, int len)
{
	return (*IWLSS(ctx)->send_frame)(ctx, pkt, len);
}

extern int
wlss_get_bssid(void *ctx, char *ret_buf, int ret_buf_len)
{
	return (*IWLSS(ctx)->get_bssid)(ctx, ret_buf, ret_buf_len);
}

extern int
wlss_get_assoc_info(void *ctx, unsigned char *buf, int length)
{
	return (*IWLSS(ctx)->get_assoc_info)(ctx, buf, length);
}

extern int
wlss_get_assoc_req_ies(void *ctx, unsigned char *buf, int length)
{
	return (*IWLSS(ctx)->get_assoc_req_ies)(ctx, buf, length);
}

extern int
wlss_get_cur_etheraddr(void *ctx, uint8 *ret_buf, int ret_buf_len)
{
	return (*IWLSS(ctx)->get_cur_etheraddr)(ctx, ret_buf, ret_buf_len);
}

extern int
wlss_get_wpaie(void *ctx, uint8 *ret_buf, int ret_buf_len,
			   struct ether_addr *ea)
{
	return (*IWLSS(ctx)->get_wpaie)(ctx, ret_buf, ret_buf_len, ea);
}

extern int
wlss_get_btampkey(void *ctx, uint8 *ret_buf, int ret_buf_len,
				struct ether_addr *ea)
{
	return (*IWLSS(ctx)->get_btampkey)(ctx, ret_buf, ret_buf_len, ea);
}

extern int
wlss_add_wpsie(void *ctx, void *ie, int ie_len, unsigned type)
{
	return (*IWLSS(ctx)->add_wpsie)(ctx, ie, ie_len, type);
}
	
extern int
wlss_del_wpsie(void *ctx, unsigned type)
{
	return (*IWLSS(ctx)->del_wpsie)(ctx, type);
}


/*
 * l2_xxx
*/

#include <l2.h>
#include <l2b.h>

#include "il2.h"

#define IL2(ctx) (((struct cfg_ctx *)(ctx))->dev->il2)


extern void *
l2_bind(void *ctx, const struct l2 *l2,
		int (*rx)(void *arg, void *frame, int), void *arg)
{
	return (*IL2(ctx)->bind)(ctx, l2, rx, arg);
}
			 
extern int
l2_unbind(void *ctx, void *ref, void *svc_ctx)
{
	return (*IL2(ctx)->unbind)(ctx, ref, svc_ctx);
}

extern int
l2_tx(void *ctx, const void *data, const size_t datasz)
{
	return (*IL2(ctx)->tx)(ctx, data, datasz);
}
