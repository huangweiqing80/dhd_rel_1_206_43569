/*****************************************************************************
 * cfg (per-port)
 *
 *****************************************************************************
*/

#include <typedefs.h>
#include <string.h>

typedef struct cfg_ctx cfg_ctx_t;

#include <proto/802.11.h>	/* for DOT11_MAX_SSID_LEN */
#include <bcmsec_types.h>	/* for clientdata_t */
#include <bcmseclib_api.h>	/* for cfg_ctx_set_cfg_t */
#include <proto/eapol.h>
#include <bcmwpa.h>			/* for PMK_LEN and WPA_MAX_PSK_LEN */

#include <bind_skp.h>
#define WPA_CFG_PRIVATE
#include <wpa_cfg.h>
#define WPA_SVC_PRIVATE
#include <wpa_svcp.h>
#define WPS_CFG_PRIVATE
#include <wps_al.h>
#define WPS_SVC_PRIVATE
#include <wps_svcp.h>

#include <bcmsec_types.h>	/* for clientdata_t */
#include <bcmseclib_api.h>	/* for struct ctxcbs */
#include "pp_dat.h"			/* need bcmseclib_api.h for MAX_IF_NAME_SIZE */

#define CFG_CTX_PRIVATE
#include <cfg.h>

#include <pp_cfg.h>


struct cfg_ctx_pp {
	struct cfg_ctx base;
	struct pp_dat _pp_dat;
};

extern struct pp_dat *
cfg_ctx_pp_dat(struct cfg_ctx *ctx)
{
	return &((struct cfg_ctx_pp *)ctx)->_pp_dat;
}

extern void *
cfg_ctx_svc_dat(struct cfg_ctx *ctx)
{
	return &ctx->u_svc_dat;
}

extern void
cfg_ctx_zero(struct cfg_ctx *ctx)
{
	/* portable zero'ing */
	const static struct cfg_ctx_pp ctx_zero;
	memcpy(ctx, &ctx_zero, sizeof ctx_zero);
}

extern size_t
cfg_ctx_sizeof(void)
{
	return sizeof(struct cfg_ctx_pp);
}
