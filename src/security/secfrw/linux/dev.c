/*****************************************************************************
 *
 *****************************************************************************
*/

#include <string.h>			/* for strcmp */

#include <typedefs.h>
#include <bcmutils.h>

#include <proto/802.11.h>	/* for DOT11_MAX_SSID_LEN */
#include <bcmsec_types.h>	/* for clientdata_t */
#include <bcmseclib_api.h>	/* for struct ctxcbs */
#include <cfg.h>

#include <dev.h>
#include <devp.h>
#include <bcm_osl.h>

struct dev_svc_tbl 
{
	const struct dev *(*devtype)(void);
}device_tbl [] =
{
{dev_wlan},
{dev_btamp},

};
extern int
dev_init(struct cfg_ctx *ctx, const void *priv)
{
	const struct dev *dev;
	int status = BCME_OK;
	dev_info_t *pdevinfo = (dev_info_t *)priv;

	/* determine device type from private data */
	ASSERT(pdevinfo->service < ARRAYSIZE(device_tbl));
	dev = (*device_tbl[pdevinfo->service].devtype)();

	/* perform device specific initialization */
	if (NULL != dev->init)
		status = (*dev->init)(ctx, priv);
	if (BCME_OK != status)
		goto DONE;

	ctx->dev = dev;

DONE:
	return status;
}

extern void
dev_deinit(struct cfg_ctx *ctx)
{
	const struct dev *dev = ctx->dev;
	
	if (NULL != dev->deinit)
		(*dev->deinit)(ctx);

	ctx->dev = NULL;
}

#include <wlioctl.h>		/* WL_EVENTING_MASK_LEN */
#include "pp_dat.h"
extern int
dev_cmp(const struct cfg_ctx *ctx1, const struct cfg_ctx *ctx2)
{
#define PP_DAT(ctx) ((ctx)->pp_dat)
	if (   !strcmp(PP_DAT(ctx1)->ifname, PP_DAT(ctx2)->ifname)
		&& PP_DAT(ctx1)->bsscfg_index == PP_DAT(ctx2)->bsscfg_index
	   )
	{
		return 0;
	}
	return -1;
}

extern int
dev_ifname(const struct cfg_ctx *ctx1, char *namebuf, int buflen)
{
	if (buflen < strlen(PP_DAT(ctx1)->ifname) + 1)
		return -1;

	strcpy(namebuf, PP_DAT(ctx1)->ifname);
	return 0;
}

extern int
dev_match(const struct cfg_ctx *ctx1, char *ifname, int bsscfg_index)
{
	if ( !strcmp(PP_DAT(ctx1)->ifname, ifname) &&
		PP_DAT(ctx1)->bsscfg_index == bsscfg_index)
		return 0;

	return -1;
}
