/* P2P app.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2p_app.h,v 1.27 2011-01-18 17:53:34 $
 */
#ifndef P2P_APP_H
#define P2P_APP_H

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Include Files ---------------------------------------------------- */

#include "BcmP2PAPI.h"


/* ---- Constants and Types ---------------------------------------------- */
/* 8-character app version string required by Sigma */
extern const char *P2PAPP_VERSION_STR;

/* ---- Variable Externs ------------------------------------------------- */

/* Instance handle for P2P device. */
extern BCMP2PHandle p2papp_dev_hdl;

extern BCMP2P_BOOL p2papp_enable_persistent;

extern char p2papp_ssid[];

extern BCMP2P_BOOL p2papp_invoke_client_discovery_connection;

/* ---- Function Prototypes ---------------------------------------------- */

int bcmp2p_main(int argc, char* argv[]);
int bcmp2p_main_str(char *str);
BCMP2P_STATUS bcmp2p_event_process(BCMP2P_BOOL non_blocking);
void p2papp_shutdown(void);


BCMP2P_STATUS p2papp_enable_discovery(BCMP2P_BOOL is_listen_only,
	int timeout_secs);
BCMP2P_STATUS p2papp_disable_discovery(void);
BCMP2P_STATUS p2papp_suspend_discovery(void);
BCMP2P_STATUS p2papp_resume_discovery(void);
void p2papp_print_peers_list(const char *line_prefix, BCMP2P_BOOL dbg);
void p2papp_print_peer_names(const char *prefix, BCMP2P_BOOL dbg);
BCMP2P_STATUS p2papp_connect(const char *device_id);
BCMP2P_STATUS p2papp_delay(int msec);
BCMP2P_STATUS p2papp_wait_for_provision_discovery_complete(int timeout_ms);
BCMP2P_STATUS p2papp_wait_for_discover_disable(int timeout_msec);
BCMP2P_STATUS p2papp_wait_for_connect_complete(int timeout_ms);
BCMP2P_STATUS p2papp_wait_for_group_create_complete(int timeout_msec);
BCMP2P_STATUS p2papp_macaddr_aton(const char *mac_addr_str, BCMP2P_UINT8 *mac_addr);
void p2papp_display_status(void);
void p2papp_set_link_config(BCMP2P_BOOL softap_only);
BCMP2P_STATUS p2papp_disconnect(void);
BCMP2P_STATUS p2papp_create_group(char *ssid);
BCMP2P_STATUS set_provision_config_method(char *val);
BCMP2P_STATUS set_wps_config_method(char *val);
BCMP2P_STATUS p2papp_send_provision_discovery(const char *name,
	BCMP2P_WPS_CONFIG_METHODS config_method);
BCMP2P_STATUS p2papp_device_reset(void);
BCMP2P_STATUS p2papp_get_group_id(BCMP2P_ETHER_ADDR *dst_dev_addr, char *dst_ssid);
BCMP2P_STATUS p2papp_enable_connect_ping(BCMP2P_BOOL enable);
BCMP2P_STATUS p2papp_wait_to_discover_peer(const char *peer_dev_id, unsigned int timeout_sec,
	BCMP2P_BOOL *is_client, int *go_idx, int *client_idx);
BCMP2P_STATUS p2papp_clear_gon_waiting(void);
BCMP2PHandle p2papp_get_hdl(void);
void p2papp_random_pin(char *pin);
char *p2papp_get_pin(void);
BCMP2P_STATUS p2papp_send_service_discovery_from_name(const char *name);

int p2papp_cli(char **argv, int max_args, int *argcp, BCMP2P_BOOL non_blocking);
int p2papp_read_console_input(char *buf, int buf_size, int *bytes_read);
int p2papp_read_console_input_timeout(char *buf, int buf_size, int *bytes_read, int timeout);
BCMP2P_STATUS p2papp_tx_dev_discb_req_to_go(int go_peer_index, int client_number);
BCMP2P_STATUS p2papp_set_listen_channel(BCMP2P_INT32 channel);
BCMP2P_INT32 p2papp_get_listen_channel(void);
void p2papp_set_log_file(const char *filename);

/* Get the wireless network interface name */
int p2papp_get_wlan_ifname(char *dst_name, unsigned int max_name_len);

/* Output a timestamped debug log to the HSL log system */
extern void p2papi_log(BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp,
	const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* P2P_APP_H */
