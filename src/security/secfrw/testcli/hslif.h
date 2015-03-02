/*
 * hslif.h
 * Interface to HSL
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: hslif.h,v 1.1 2010-08-31 17:22:51 $
*/

#ifndef _hslif_h_
#define _hslif_h_

void hslif_init();
void hslif_deinit();
void * hslif_init_ctx();
void hslif_deinit_ctx(void *ctx);
int hslif_set_cfg(void *ctx, char if_name[], int bsscfg_index, int role,
	char in_ssid[], int WPA_auth, int wsec, char key[]);

#endif /* _hslif_h_ */
