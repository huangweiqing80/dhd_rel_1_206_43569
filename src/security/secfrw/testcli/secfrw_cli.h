/*
 * Entry points for security framework command line interface.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 * $Id: secfrw_cli.h,v 1.1 2010-08-31 17:22:51 $
 */


#ifndef secfrw_cli_h
#define secfrw_cli_h

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Include Files ---------------------------------------------------- */
/* ---- Constants and Types ---------------------------------------------- */
/* ---- Variable Externs ------------------------------------------------- */
/* ---- Function Prototypes ---------------------------------------------- */


int secfrw_main_str(char *str);
int secfrw_main_args(int argc, char **argv);


#ifdef __cplusplus
	}
#endif

#endif  /* secfrw_cli_h  */
