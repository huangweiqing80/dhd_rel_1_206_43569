/*
 * mth_events.h
 * Helper macros for broadcom events
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: mth_events.h,v 1.2 2010-05-05 21:02:59 $
*/

#ifndef _mth_events_h_
#define _mth_events_h_


struct seclib_ev;
struct wpa_dat;

extern int
wpa_auth_process_event(struct wpa_dat *, struct seclib_ev *pkt, int len);

extern void
wpaif_auth_dispatch(struct ctx *ctx, void *pkt, int len);

extern void
wpa_plumb_ptk(void *arg, uint8 *key, uint32 keylen, uint32 algo,
			  struct ether_addr *ea);

extern void
wpa_plumb_gtk(void *arg, uint8 *key, uint32 keylen, uint32 index, uint32 algo,
			  uint16 rsc_lo, uint32 rsc_hi, bool primary);

extern void wpa_tx_frame(void *arg, void *pkt, int len);

extern void wpa_plumb_gtk(void *arg, uint8 *key, uint32 keylen, uint32 index,
						  uint32 algo, uint16 rsc_lo, uint32 rsc_hi,
						  bool primary);


#endif /* _mth_events_h_ */
