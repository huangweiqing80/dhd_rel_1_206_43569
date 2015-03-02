/*****************************************************************************
 * Wireless User Tools
 *
 * Per-port events
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *****************************************************************************
*/

#include <typedefs.h>
#include <bcmutils.h>

#include <proto/ethernet.h>
#include <proto/bcmeth.h>
#include <proto/bcmevent.h>


extern void
wpa_events(void *ctx, void *priv)
{
	uint8 *bitvec = priv;
	
	UNUSED_PARAMETER(ctx);
	
	setbit(bitvec, WLC_E_LINK);
	setbit(bitvec, WLC_E_ASSOC_IND);
	setbit(bitvec, WLC_E_REASSOC_IND);
	setbit(bitvec, WLC_E_DISASSOC_IND);

	clrbit(bitvec, 53);

}

extern void
bta_events(void *ctx, void *priv)
{
	uint8 *bitvec = priv;
	
	UNUSED_PARAMETER(ctx);
	
	setbit(bitvec, WLC_E_IF);
	setbit(bitvec, WLC_E_LINK);
	setbit(bitvec, WLC_E_ASSOC_IND);
	setbit(bitvec, WLC_E_REASSOC_IND);
	setbit(bitvec, WLC_E_DISASSOC_IND);

	clrbit(bitvec, 53);
}

extern void
bta_parent_events(void *ctx, void *priv)
{
	uint8 *bitvec = priv;
	
	UNUSED_PARAMETER(ctx);
	
	setbit(bitvec, WLC_E_IF);

	clrbit(bitvec, 53);
}

extern void
wps_events(void *ctx, void *priv)
{
	uint8 *bitvec = priv;
	
	UNUSED_PARAMETER(ctx);
	
	setbit(bitvec, WLC_E_LINK);
}
