/*
 * NSA generic application API
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: $
 */
#ifndef APP_GENERIC_H
#define APP_GENERIC_H

#include "data_types.h"

/* Init NSA application
 * Returns: 0 if successful, error code otherwise
 */
int app_nsa_gen_init(void);

/* This function is used to close application
 * Returns: void
 */
void app_nsa_end(void);

/*
 * Enable NSA
 * Returns: 0 if successful, error code otherwise
 */
int app_nsa_dm_enable(void);

/* Disable NSA
 * Returns: 0 if successful, error code otherwise
 */
int app_nsa_dm_disable(void);


/* NSA RW command */
int app_nsa_rw_write_wps(UINT8 *payload, UINT32 payload_size);
int app_nsa_rw_read(void);
int app_nsa_rw_format(void);
int app_nsa_rw_stop(void);

/* NSA CHO command */
int app_nsa_cho_start(BOOLEAN cho_as_server, UINT8 *payload, UINT32 payload_size);
int app_nsa_cho_stop(void);
int app_nsa_cho_send(void);

#endif /* APP_GENERIC_H */
