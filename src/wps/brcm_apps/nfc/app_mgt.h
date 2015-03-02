/*
 * NSA generic application management API
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
#ifndef APP_MGT_H
#define APP_MGT_H

/*
 * Definitions
 */
#ifndef APP_DEFAULT_UIPC_PATH
#define APP_DEFAULT_UIPC_PATH "./"
#endif

/* Management Custom Callback */
typedef BOOLEAN(tAPP_MGT_CUSTOM_CBACK)(tNSA_MGT_EVT event, tNSA_MGT_MSG *p_data);

typedef struct
{
	tAPP_MGT_CUSTOM_CBACK* mgt_custom_cback;
} tAPP_MGT_CB;

extern tAPP_MGT_CB app_mgt_cb;

/*
 * Init management
 * Returns: 0 if success / -1 otherwise
*/
int app_mgt_init(void);

/*
 * Open communication to NSA Server
 * Parameters      uipc_path: path to UIPC channels
 *                      p_mgt_callback: Application's custom callback
 *                      bsa mgt already opened so GKI and UIPC already init
 * Returns: 0 if success / -1 otherwise
*/
int app_mgt_open(const char *p_uipc_path, tAPP_MGT_CUSTOM_CBACK *p_mgt_callback,
	BOOLEAN bsa_mgt_already_opened);

/*
 * This function is used to closes the NSA connection
 * Returns: 0 if success / -1 otherwise
*/
int app_mgt_close(void);

/*
 *
 * This function is used to kill the server
 * Returns: 0 if success / -1 otherwise
*/
int app_mgt_kill_server(void);

#endif /* APP_MGT_H_ */
