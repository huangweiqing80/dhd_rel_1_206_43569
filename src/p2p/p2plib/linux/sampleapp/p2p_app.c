/*
 * Broadcom P2P Library Sample App
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2p_app.c,v 1.333 2011-02-09 18:06:23 $
 */
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* WL driver include files */
#include <802.11.h>
#include <wlioctl.h>
/* #include <bcmip.h> */
#include <bcmutils.h>
/* #include <bcmendian.h> */

/* WPS device password modes */
#include <reg_prototlv.h>

/* P2P API */
#include <BcmP2PAPI.h>
#include <BcmP2PDbg.h>
#include <p2p.h>
#include <p2p_app.h>
#include <p2papp_osl.h>
#include <p2plib_api.h>


#include "p2papp_persist.h"
#if P2P_UPNP_DISCOVERY
#include <p2papp_upnp.h>
#endif

//#ifndef SOFTAP_ONLY
#include <p2papp_wfd.h>
//#endif  /* not SOFTAP_ONLY */

/* Debug logging macros.
 * Use the internal debug logging functions from the HSL so that app logs and
 * HSL can be correctly interleaved.
 */
#define P2PLOGGING 1
#if P2PLOGGING
#define P2PVERB(fmt)		p2papi_log(BCMP2P_LOG_VERB, TRUE, fmt)
#define P2PLOG(fmt)			p2papi_log(BCMP2P_LOG_MED, TRUE, fmt)
#define P2PLOG1(fmt, a)		p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a)
#define P2PLOG2(fmt, a, b)	p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a, b)
#else /* !P2PLOGGING */
#define P2PVERB(fmt)
#define P2PLOG(fmt)
#define P2PLOG1(fmt, a)
#define P2PLOG2(fmt, a, b)
#endif /* P2PLOGGING */


#define P2PAPP_DISCOVER_TMO_SECS 3600
/* #define P2PAPP_DISCOVER_ITERATION_SECS 20 */
#define P2PAPP_DISCOVER_ITERATION_SECS 3600
#define P2PAPP_CONNECT_TMO_SECS 60
#define P2PAPP_DEFAULT_PASSPHRASE "helloworld"
#define P2PAPP_DEFAULT_WPS_PIN "12345670"
#ifndef SOFTAP_ONLY
#define P2PAPP_DEFAULT_CONFIG_METHODS \
	(BCMP2P_WPS_DISPLAY | BCMP2P_WPS_KEYPAD | BCMP2P_WPS_PUSHBUTTON)
#else
#define P2PAPP_DEFAULT_CONFIG_METHODS \
	(BCMP2P_WPS_LABEL | BCMP2P_WPS_DISPLAY | BCMP2P_WPS_KEYPAD | BCMP2P_WPS_PUSHBUTTON)
#endif /* SOFTAP_ONLY */

/* service discovery test data size */
#define SD_TEST_DATA_SIZE	256

const struct ether_addr P2PAPP_NULL_BSSID = { {0, 0, 0, 0, 0, 0} };

/* 8-character app version string required by Sigma */
const char *P2PAPP_VERSION_STR = "R21-0";

/* STATIC IP INTERFACE */
#ifdef TARGETENV_android
#define GO_IP_ADDRESS 0xc0a82B01
#else
#define GO_IP_ADDRESS 0xc0a81001
#endif /* TARGETENV_android */
#define GO_NETMASK    0xffffff00

/* Forward declarations */
BCMP2P_BOOL p2papp_process_cmd(uint8 key);
BCMP2P_BOOL p2papp_process_cmd_ex(int argc, char* argv[]);
void p2papp_run_conn_script(void);
static void p2papp_redraw(char *str1, char *str2, char *str3);
static void p2papp_redraw_ex(char *str1, char *str2, char *str3, BCMP2P_BOOL display_cmds);

#ifndef SOFTAP_ONLY
static BCMP2P_STATUS p2papp_init_service_discovery(void);
static BCMP2P_STATUS p2papp_deinit_service_discovery(void);
static BCMP2P_STATUS p2papp_send_service_discovery(unsigned int peer_idx);
BCMP2P_STATUS p2papp_get_peer_idx_from_name(const char *name, unsigned int *peer);
#endif /* not SOFTAP_ONLY */
static BCMP2P_STATUS p2papp_update_conn_complete(BCMP2P_NOTIFICATION_CODE notification);
void p2papp_run_disc_script(void);
static void p2papp_get_timestamped_log_name(char *buf, int buf_size, const char *prefix);
BCMP2P_BOOL p2papp_disable_sigint();
BCMP2P_STATUS p2papp_iterate_discovery(void);
/*
 * Global variables
 */

/* command line options */
static BCMP2P_BOOL p2papp_is_ap = FALSE;
static BCMP2P_BOOL p2papp_is_softap_ready = FALSE;
static BCMP2P_BOOL p2papp_stay_connected = FALSE;
static BCMP2P_BOOL p2papp_disable_wps = FALSE;
static BCMP2P_UINT8 p2papp_auto_responder_mode = FALSE;
static BCMP2P_BOOL p2papp_auto_softap_mode = FALSE;
static BCMP2P_BOOL p2papp_auto_go_mode = FALSE;
static BCMP2P_BOOL p2papp_auto_pbc_mode = FALSE;
static char p2papp_phys_if_name[10] = { '\0' };
static BCMP2P_BOOL p2papp_is_created_grp_owner = FALSE;
static BCMP2P_BOOL p2papp_is_created_softap = FALSE;
static int32 p2papp_discovery_iteration_secs = P2PAPP_DISCOVER_ITERATION_SECS;
static BCMP2P_CHANNEL p2papp_listen_channel =
	{BCMP2P_LISTEN_CHANNEL_CLASS, 11};
static BCMP2P_CHANNEL p2papp_operating_channel =
	{ BCMP2P_DEFAULT_OP_CHANNEL_CLASS, 0};
#ifdef BCM_P2P_OPTEXT
static BCMP2P_BOOL p2papp_opch_force = FALSE;
static BCMP2P_BOOL p2papp_opch_high = FALSE;
#endif
static BCMP2P_LOG_LEVEL p2papp_log_level = BCMP2P_LOG_ERR;
static BCMP2P_BOOL p2papp_changed_log_level = FALSE;
static char p2papp_security_type[10] = "wpa2";
static BCMP2P_BOOL p2papp_override_passphrase = FALSE;
static BCMP2P_PASSPHRASE p2papp_passphrase = P2PAPP_DEFAULT_PASSPHRASE;
static BCMP2P_BOOL p2papp_override_wps_pin = FALSE;
static BCMP2P_WPS_PIN p2papp_wps_pin = P2PAPP_DEFAULT_WPS_PIN;
static BCMP2P_BOOL p2papp_do_startup_init = TRUE;
static BCMP2P_BOOL p2papp_override_go_intent = TRUE;
static BCMP2P_BOOL p2papp_disable_pbc_overlap = TRUE;
static BCMP2P_BOOL p2papp_disable_sigint_exit = FALSE;
static BCMP2P_UINT8 p2papp_go_intent = 8;
static BCMP2P_BOOL p2papp_override_wps_config_methods = FALSE;
static uint32 p2papp_wps_config_methods =
	P2PAPP_DEFAULT_CONFIG_METHODS;
static uint32 p2papp_provision_config_methods =
	P2PAPP_DEFAULT_CONFIG_METHODS;
BCMP2P_UINT8 p2papp_discov_filt_devtype = 0;
BCMP2P_UINT8 p2papp_discov_filt_subcat = 0;
BCMP2P_UINT8 p2papp_pri_devtype = BCMP2P_DEVICE_TYPE_CAT_COMPUTER;
BCMP2P_UINT8 p2papp_pri_subcat = BCMP2P_DEVICE_TYPE_SUB_CAT_COMP_NOTEBOOK;
static char p2papp_log_filename[128] = { 0 };
static char p2papp_log_filename_prefix[32] = { 0 };
static BCMP2P_BOOL p2papp_is_syslog = FALSE;
#define PEER_WAIT_TIMEOUT 15
/* product information */
static char	p2papp_manufacturer[WPS_IE_MANUF_NAME_LEN + 1]="";
static char	p2papp_modelName[WPS_IE_MODEL_NAME_LEN + 1]="";
static char	p2papp_modelNumber[WPS_IE_MODEL_NUM_LEN + 1]="";
static char	p2papp_serialNumber[WPS_IE_SERIAL_NUM_LEN + 1]="";
static uint32	p2papp_osVersion = FALSE;


#ifndef SOFTAP_ONLY

BCMP2P_BOOL p2papp_enable_persistent = FALSE;
BCMP2P_BOOL p2papp_enable_wfdisp = FALSE;

static BCMP2P_BOOL p2papp_is_gon_waiting = FALSE;
static BCMP2P_DISCOVER_ENTRY p2papp_gon_info;
static BCMP2P_BOOL p2papp_same_int_dev_addr = FALSE;
static BCMP2P_ETHER_ADDR p2papp_target_client_addr;
static int p2papp_num_add_services = 0;
static BCMP2P_INT32 p2papp_af_retry_count = -1;
static BCMP2P_UINT32 p2papp_af_retry_ms = -1;

/* managed p2p device */
static BCMP2P_BOOL p2papp_enable_managed = FALSE;
static BCMP2P_BOOL p2papp_auto_disassoc_mode = FALSE;
#endif /* not SOFTAP_ONLY */

static BCMP2P_BOOL p2papp_no_evt_loop = FALSE;

/* discover disabled status */
static BCMP2P_BOOL p2papp_is_discover_disabled = BCMP2P_TRUE;

/* connect complete and status for synchronous connection */
static BCMP2P_BOOL p2papp_is_connect_complete = FALSE;
static BCMP2P_STATUS p2papp_connect_status = BCMP2P_ERROR;

/* Enable/disable post connection ping test. */
static BCMP2P_BOOL p2papp_enable_ping = TRUE;


static BCMP2P_CONFIG p2papp_bss_config;
BCMP2PHandle p2papp_dev_hdl = NULL;

/* Our P2P friendly name */
char p2papp_friendly_name[DOT11_MAX_SSID_LEN+1] = "Broadcom";

/* Our SSID */
char p2papp_ssid[DOT11_MAX_SSID_LEN+1] = "";

/* UI state */
char *p2papp_status_str = "";
char *p2papp_status_str2 = "";
char *p2papp_status_str3 = "";
char p2papp_msg_buf[100];
char p2papp_msg_buf2[100];
char p2papp_msg_buf3[100];

/* Discovery state variables */
BCMP2P_BOOL p2papp_discovery_timed_out = BCMP2P_FALSE;
#ifndef SOFTAP_ONLY
BCMP2P_BOOL p2papp_discovery_failed = FALSE;
BCMP2P_BOOL p2papp_is_listen_only = FALSE;
uint32 p2papp_peer_count = 0;
BCMP2P_DISCOVER_ENTRY p2papp_peers_list[64 /* P2PAPI_MAX_PEERS */];
static uint32 p2papp_client_count = 0;
static BCMP2P_CLIENT_LIST p2papp_client_list[BCMP2P_MAX_SOFTAP_CLIENTS];
static BCMP2P_CHANNEL p2papp_target_client_channel = {BCMP2P_DEFAULT_OP_CHANNEL_CLASS, 0};
static BCMP2P_BOOL p2papp_received_go_discoverability_req = FALSE;
BCMP2P_BOOL p2papp_invoke_client_discovery_connection = FALSE;
static BCMP2P_DISCOVER_PARAM p2papp_discovery_params;
static int p2papp_discovery_iteration = 0;


#endif /* SOFTAP_ONLY */

/* Connection state variables */
#ifndef SOFTAP_ONLY
BCMP2P_DISCOVER_ENTRY *p2papp_peer;	/* peer we are initiating connection to */
#endif /* SOFTAP_ONLY */

/* Flags for monitoring a connection attempt */
BCMP2P_BOOL p2papp_is_connected = FALSE;
#ifndef SOFTAP_ONLY
static BCMP2P_BOOL p2papp_initiated_conn = FALSE;
#endif

/* event structure */
#define MAX_NOTIFICATION_SIZE	(5 * 1024)
typedef struct {
	void *context;
	BCMP2P_NOTIFICATION_CODE code;
	int notificationDataLength;
	BCMP2P_UINT8 notificationData[MAX_NOTIFICATION_SIZE];
} p2papp_event_t;

/* Link configuration for testing open security */
static BCMP2P_CONFIG p2papp_open_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_OFF,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{ "", "", "", "" },		/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 20, 40 },			/* DHCPConfig: on, range 20...39 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    2,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WPA2-PSK AES security, WPS PIN mode */
static BCMP2P_CONFIG p2papp_wpa2_aes_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_AES,		/* encryption */
	BCMP2P_WPA_AUTH_WPA2PSK, /* authentication */
	P2PAPP_DEFAULT_PASSPHRASE, /* keyWPA[64] */
	{ "", "", "", "" },		/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 171, 180 },		/* DHCPConfig: on, range 171...179 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WPA2-PSK TKIP security, WPS PIN mode */
static BCMP2P_CONFIG p2papp_wpa2_tkip_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
/*	BCMP2P_ALGO_TKIP | BCMP2P_ALGO_AES, */		/* encryption */
	BCMP2P_ALGO_TKIP,		/* encryption */
	BCMP2P_WPA_AUTH_WPA2PSK, /* authentication */
	P2PAPP_DEFAULT_PASSPHRASE, /* keyWPA[64] */
	{ "", "", "", "" },		/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 171, 180 },		/* DHCPConfig: on, range 171...179 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    1,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WPA-PSK/WPA2-PSK TKIP/AES security, WPS PIN mode */
static BCMP2P_CONFIG p2papp_wpa_wpa2_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_TKIP_AES, 		/* encryption */
	BCMP2P_WPA_AUTH_WPAPSK_WPA2PSK, /* authentication */
	P2PAPP_DEFAULT_PASSPHRASE, /* keyWPA[64] */
	{ "", "", "", "" },		/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 171, 180 },		/* DHCPConfig: on, range 171...179 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    1,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WPA-PSK TKIP security, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wpa_tkip_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_TKIP,		/* encryption */
	BCMP2P_WPA_AUTH_WPAPSK,	/* authentication */
	P2PAPP_DEFAULT_PASSPHRASE, /* keyWPA[64] */
	{ "", "", "", "" },		/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 40, 50 },			/* DHCPConfig: on, range 40...49 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    2,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WPA-PSK AES security, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wpa_aes_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_AES,		/* encryption */
	BCMP2P_WPA_AUTH_WPAPSK,	/* authentication */
	P2PAPP_DEFAULT_PASSPHRASE, /* keyWPA[64] */
	{ "", "", "", "" },		/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 60, 70 },			/* DHCPConfig: on, range 60...79 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    1,						/* enableWMM */
    1,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP/Open, 1 40-bit key, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{ "ED91FE1952", "", "", "" }, /* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP, 1 128 bit key index 0, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep10_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{
		"012233445566778899AABBCCDE",
		"",
		"",
		""
	},						/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP, 1 128 bit key, index 3, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep11_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{
		"",
		"FEDCBA9876AAAAAAAAABBBBBBB",
		"",
		""
	},						/* WEPKey[4][] */
	1,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP, 1 128 bit key, index 3, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep13_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{
		"",
		"",
		"",
		"123456789ABCDEF0123456789A"
	},						/* WEPKey[4][] */
	3,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP, 2 128 bit keys index 0, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep20_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	1},						/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{
		"012233445566778899AABBCCDE",
		"FEDCBA9876AAAAAAAAABBBBBBB",
		"",
		""
	},						/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP, 2 128 bit keys index 1, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep21_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	1},						/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{
		"012233445566778899AABBCCDE",
		"FEDCBA9876AAAAAAAAABBBBBBB",
		"",
		""
	},						/* WEPKey[4][] */
	1,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP, 2 128 bit keys index 1, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep22_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	1},						/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{
		"",
		"FEDCBA9876AAAAAAAAABBBBBBB",
		"30405060708090A0B0C0D0E0F0",
		""
	},						/* WEPKey[4][] */
	2,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP, 4 128 bit keys index 0, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep40_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	1},						/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{
		"012233445566778899AABBCCDE",
		"FEDCBA9876AAAAAAAAABBBBBBB",
		"30405060708090A0B0C0D0E0F0",
		"123456789ABCDEF0123456789A"
	},						/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP, 4 128 bit keys, index 1, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep41_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{
		"012233445566778899AABBCCDE",
		"FEDCBA9876AAAAAAAAABBBBBBB",
		"30405060708090A0B0C0D0E0F0",
		"123456789ABCDEF0123456789A"
	},						/* WEPKey[4][] */
	1,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP, 4 128 bit keys, index 2, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep42_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{
		"012233445566778899AABBCCDE",
		"FEDCBA9876AAAAAAAAABBBBBBB",
		"30405060708090A0B0C0D0E0F0",
		"123456789ABCDEF0123456789A"
	},						/* WEPKey[4][] */
	2,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing WEP, 4 128 bit keys, index 3, WPS PBC mode */
static BCMP2P_CONFIG p2papp_wep43_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_WEP128,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{
		"012233445566778899AABBCCDE",
		"FEDCBA9876AAAAAAAAABBBBBBB",
		"30405060708090A0B0C0D0E0F0",
		"123456789ABCDEF0123456789A"
	},						/* WEPKey[4][] */
	3,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    0						/* hideSSID */
};

/* Link configuration for testing hidden SSID, open security */
static BCMP2P_CONFIG p2papp_hidden_open_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_OFF,		/* encryption */
	BCMP2P_WPA_AUTH_NONE,	/* authentication */
	"",						/* keyWPA[64] */
	{ "", "", "", "" },		/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    1						/* hideSSID */
};

/* Link configuration for testing hidden SSID, WPA2-PSK AES security */
static BCMP2P_CONFIG p2papp_hidden_wpa2_aes_link_config = {
	{BCMP2P_DEFAULT_OP_CHANNEL_CLASS,
	11},					/* operatingChannel */
	BCMP2P_ALGO_AES,		/* encryption */
	BCMP2P_WPA_AUTH_WPA2PSK, /* authentication */
	P2PAPP_DEFAULT_PASSPHRASE, /* keyWPA[64] */
	{ "", "", "", "" },		/* WEPKey[4][] */
	0,						/* WEPKeyIndex */
	{ BCMP2P_DHCP_ON, 160, 200 },		/* DHCPConfig: on, range 160...199 */
	{ TRUE, P2PAPP_DEFAULT_CONFIG_METHODS,
	P2PAPP_DEFAULT_WPS_PIN },	/* WPSConfig */
	GO_IP_ADDRESS, 			/* ip_addr */
	GO_NETMASK, 			/* netmask */
    0,						/* allow11b */
    0,						/* enableWMM */
    0,						/* enableWMM_PS */
    0,						/* maxClients */
    1						/* hideSSID */
};

/*
 * P2P internal tests.
 */
void p2papp_test_ioctl(BCMP2PHandle* hdl)
{
	int val;
	int wsec;
	int bi;
	P2PLOG("Test ioctl\n");
	if (BCMP2PIoctlGet(hdl, WLC_GET_MAGIC, &val, sizeof(int)) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIoctlGet failed\n");
	P2PLOG2("BCMP2PIoctlGet read=0x%x expect=0x%x\n", val, WLC_IOCTL_MAGIC);
	if (val != WLC_IOCTL_MAGIC)
		P2PLOG("BCMP2PIoctlGet value failed\n");
	val = 0;
	wsec = 0x8;
	if (BCMP2PIoctlSet(hdl, WLC_SET_WSEC, &wsec, sizeof(int)) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIoctlSet failed\n");
	if (BCMP2PIoctlGet(hdl, WLC_GET_WSEC, &val, sizeof(int)) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIoctlGet failed\n");
	P2PLOG2("BCMP2PIoctlGet read=0x%x expect=0x%x\n", val, wsec);
	if (val != wsec)
		P2PLOG("BCMP2PIoctlGet value failed\n");
	wsec = 0;
	if (BCMP2PIoctlSet(hdl, WLC_SET_WSEC, &wsec, sizeof(int)) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIoctlSet failed\n");

	/* beacon interval */
	val = 0;
	bi = 200;
	if (BCMP2PIoctlSet(hdl, WLC_SET_BCNPRD, &bi, sizeof(int)) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIoctlSet failed\n");
	if (BCMP2PIoctlGet(hdl, WLC_GET_BCNPRD, &val, sizeof(int)) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIoctlGet failed\n");
	if (val != bi)
		P2PLOG("BCMP2PIoctlGet value failed\n");
	bi = 100;
	if (BCMP2PIoctlSet(hdl, WLC_SET_BCNPRD, &bi, sizeof(int)) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIoctlSet failed\n");

	P2PLOG("Test ioctl done\n");
}

void p2papp_test_iovar(BCMP2PHandle* hdl)
{
	int val;
	int msglevel;
	int wsec;
	char buf[128];
	int *p;
	wl_rssi_event_t rssi, *rssi_read;
	int i;

	P2PLOG("Test iovar\n");

	val = 0;
	msglevel = 0xaaaa5555;
	p = (int *)buf;
	p[0] = msglevel;
	if (BCMP2PIovarSet(hdl, "msglevel", buf, 128) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIovarSet failed");
	if (BCMP2PIovarGet(hdl, "msglevel", &val, sizeof(int)) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIovarGet failed");
	P2PLOG2("BCMP2PIovarGet read=0x%x expect=0x%x\n", val, msglevel);
	if (val != msglevel)
		P2PLOG("BCMP2PIovarGet value failed");
	msglevel = 0;
	p = (int *)buf;
	p[0] = msglevel;
	if (BCMP2PIovarSet(hdl, "msglevel", buf, 128))
		P2PLOG("BCMP2PIovarSet failed");

	val = 0;
	wsec = 3;
	if (BCMP2PIovarIntegerSet(hdl, "wsec", wsec) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIovarIntegerSet failed");
	if (BCMP2PIovarIntegerGet(hdl, "wsec", &val) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIovarIntegerGet failed");
	P2PLOG2("BCMP2PIovarIntegerGet read=0x%x expect=0x%x\n", val, wsec);
	if (val != wsec)
		P2PLOG("BCMP2PIovarIntegerGet value failed");
	msglevel = 0;
	if (BCMP2PIovarIntegerSet(hdl, "wsec", wsec) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIovarIntegerSet failed");

	rssi.rate_limit_msec = 100;
	rssi.num_rssi_levels = MAX_RSSI_LEVELS;
	for (i = 0; i < MAX_RSSI_LEVELS; i++)
		rssi.rssi_levels[i] = 0x11 * (i + 1);
	if (BCMP2PIovarBufferSet(hdl, "rssi_event", &rssi, sizeof(rssi), buf, 128)
		!= BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIovarBufferSet failed");
	if (BCMP2PIovarBufferGet(hdl, "rssi_event", NULL, 0, buf, 128) != BCMP2P_SUCCESS)
		P2PLOG("BCMP2PIovarBufferGet failed");
	rssi_read = (wl_rssi_event_t *)buf;
	P2PLOG2("BCMP2PIovarBufferGet read=0x%x expect=0x%x\n",
		rssi.rate_limit_msec, rssi_read->rate_limit_msec);
	if (rssi.rate_limit_msec != rssi_read->rate_limit_msec)
		P2PLOG("rate_limit_msec value failed");
	P2PLOG2("BCMP2PIovarBufferGet read=0x%x expect=0x%x\n",
		rssi.num_rssi_levels, rssi_read->num_rssi_levels);
	if (rssi.num_rssi_levels != rssi_read->num_rssi_levels)
		P2PLOG("num_rssi_levels value failed");
	for (i = 0; i < MAX_RSSI_LEVELS; i++) {
		P2PLOG2("BCMP2PIovarBufferGet read=0x%x expect=0x%x\n",
			rssi.rssi_levels[i], rssi_read->rssi_levels[i]);
		if (rssi.rssi_levels[i] != rssi_read->rssi_levels[i])
			P2PLOG("rssi_levels value failed");
	}

	P2PLOG("Test iovar done\n");
}

BCMP2P_BOOL p2papp_disable_sigint()
{
	return  p2papp_disable_sigint_exit;
}

static int
print_usage()
{
	printf("Usage : bcmp2papp [options]...\n");
	printf("Options:\n");
#ifndef SOFTAP_ONLY
	printf("  -c or --channel <channel>\n");
	printf("     Set the listen channel: 1, 6, or 11. (default 11)\n");
#endif /* SOFTAP_ONLY */
	printf("  -o or --opch <channel>\n");
	printf("     Set the operating channel (default 0=auto-select)\n");
	printf("  -d\n");
	printf("     Set the debug log level: -de, -d, -di, or -dv\n");
	printf("    -de=errors only, -d=medium, -di=info, -dv=verbose\n");
#ifdef SOFTAP_ONLY
	printf("  -n or --name <ssid>: \n");
	printf("     Set this device's SSID. (default %s)\n",
		p2papp_friendly_name);
#else
	printf("  -n or --name <friendly_name>: \n");
	printf("     Set this device's P2P friendly name. (default %s)\n",
		p2papp_friendly_name);
	printf("  -t or --timeout <seconds>: \n");
	printf("     Set the discovery iteration time. (default %d)\n",
		P2PAPP_DISCOVER_ITERATION_SECS);
#endif /* SOFTAP_ONLY */
	printf("  -i: skip initialization\n");
	printf("     For resuming app after detaching with 'z' key cmd.\n");
	printf("  -b or --batch <key cmds>\n");
	printf("     Batch mode.  Runs the specified key cmds as if those keys\n");
	printf("     were pressed.\n");
	printf("     eg. -b i,s,,,,rz  will init the HSL, create a soft AP,\n");
	printf("         wait 4 seconds, redraw the screen, then exit the app\n");
	printf("         without soft AP teardown or HSL cleanup.\n");
	printf("     eg. -b rz  will start the app with no HSL init, redraw the\n");
	printf("         screen, and exit the app without teardown/HSL cleanup.\n");
	printf("  --intent <X>\n");
	printf("     Set the GO negotiation intent value to X (1-15)\n");
	printf("  --config <label|display|keypad|pbc>\n");
	printf("     Set the WPS config methods\n");
	printf("  --provision <label|display|keypad|pbc>\n");
	printf("     Set the provision discovery request config method\n");
#ifndef SOFTAP_ONLY
	printf("  --auto\n");
	printf("     Automatically enable/re-enable P2P discovery and allow\n");
	printf("     running this app in the background with no keyboard input.\n");
	printf("  --start_go \n");
	printf("     Automatically create/re-create P2P autonomous and allow\n");
	printf("     running this app in the background with no keyboard input.\n");
	printf("  --start_pbc \n");
	printf("     Automatically start WPS PBC when receive PBC provision request and allow\n");
	printf("     running this app in the background with no keyboard input.\n");
#endif /* SOFTAP_ONLY */
	printf("  --softap\n");
	printf("     Automatically start a soft AP and allow runnig this app in\n");
	printf("     the background with no keyboard input.\n");
	printf("  --pif <phys ifname>\n");
	printf("     Set the physical network interface. eg. --pif eth1\n");
	printf("  --nowps\n");
	printf("     Disable WPS.\n");
	printf("  --passphrase <8 to 64 characters>\n");
	printf("     Set passphrase for AP\n");
	printf("     eg. --passphrase helloworld\n");
	printf("  --pin <wps pin>\n");
	printf("     Set default WPS pin\n");
	printf("     eg. --pin 12345670\n");
	printf("  --wfd <source|psink|2sink|source-psink> <rtsp port> [hdcp]\n");
	printf("     WFD configuration.  [hdcp] is optionnal\n");
	printf("  --sec <type>\n");
	printf("     Set connection security to use when we are in the AP role:\n");
	printf("     wpa2, open, wpa, or wep.  eg. --sec wpa\n");
	printf("     (wpa2 is WPA2-PSK/AES, wpa is WPA-PSK/TKIP, wep is Open/WEP128\n");
	printf("  --add_services <num services>\n");
	printf("     Register specified number of arbitrary services for testing\n");
	printf("Default parameters:\n");
#ifdef SOFTAP_ONLY
	printf("    -n %s --pif eth1 --sec wpa2\n",
		p2papp_friendly_name);
#else
	printf("    -t %d -n %s --pif eth1 --sec wpa2\n",
		p2papp_discovery_iteration_secs, p2papp_friendly_name);
#endif /* SOFTAP_ONLY */
	printf("Example:\n");
	printf("    bcmp2papp -d -n my_device\n");
	printf("    bcmp2papp -di -n my_device --pin 11111115\n");
	return 0;
}

void
p2papp_shutdown(void)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	char *errmsg = NULL;

	P2PLOG1("p2papp_shutdown: hdl=%p\n", p2papp_dev_hdl);
	if (NULL != p2papp_dev_hdl && !p2papp_stay_connected) {

#ifndef SOFTAP_ONLY
		/* Turn off P2P discovery if it is on */
		if (BCMP2PIsDiscovering(p2papp_dev_hdl)) {
			status = BCMP2PCancelDiscover(p2papp_dev_hdl);
			errmsg = "BCMP2PCancelDiscover";
		}

		/* Teardown the P2P connection if it is connected */
		if (p2papp_is_created_grp_owner) {
			status = BCMP2PCancelCreateGroup(p2papp_dev_hdl);
			errmsg = "BCMP2PCancelCreateGroup";
		}
		else
#endif /* SOFTAP_ONLY */
		if (p2papp_is_created_softap) {
			status = BCMP2PCancelCreateSoftAP(p2papp_dev_hdl);
			errmsg = "BCMP2PCancelCreateSoftAP";
		}
#ifndef SOFTAP_ONLY
		status = BCMP2PCancelCreateLink(p2papp_dev_hdl);
		errmsg = "BCMP2PCancelCreateLink";
#endif /* SOFTAP_ONLY */

		if (status != BCMP2P_SUCCESS) {
			printf("p2papp_shutdown: %s failed!\n", errmsg);
		}

		/* Call a shell script to bring down the OS network interface */
		p2papp_run_disc_script();


#ifndef SOFTAP_ONLY
		/* De-initialize service discovery. */
		p2papp_deinit_service_discovery();
#endif /* not SOFTAP_ONLY */

		/* Deinitialize the P2P Library */
		BCMP2PClose(p2papp_dev_hdl);
		if (BCMP2PUnRegisterNotification() != BCMP2P_SUCCESS) {
			printf("p2papp_shutdown: BCMP2PUnregisterNotification failed!\n");
		}
		p2papp_eventq_delete();
		BCMP2PUninitialize();
	}
}

#ifndef SOFTAP_ONLY
static uint32
p2papp_get_provision_config_methods(uint32 provision_config_methods,
	uint32 peer_config_methods)
{
	uint32 config_methods = 0;

	/* config method selected based on provision enabled and peers config methods */
	/* order of precedence: display, keypad, label, pushbutton */
	if (provision_config_methods & peer_config_methods & BCMP2P_WPS_DISPLAY)
		config_methods = BCMP2P_WPS_DISPLAY;
	else if (provision_config_methods & peer_config_methods & BCMP2P_WPS_KEYPAD)
		config_methods = BCMP2P_WPS_KEYPAD;
	else if (provision_config_methods & peer_config_methods & BCMP2P_WPS_LABEL)
		config_methods = BCMP2P_WPS_LABEL;
	else if (provision_config_methods & peer_config_methods & BCMP2P_WPS_PUSHBUTTON)
		config_methods = BCMP2P_WPS_PUSHBUTTON;

	return config_methods;
}

static void
p2papp_print_discovered_services(BCMP2P_SVC_LIST *entry_list)
{
	if (entry_list != 0) {
		BCMP2P_SVC_ENTRY *entry_beg = (BCMP2P_SVC_ENTRY *)entry_list->svcEntries;
		int i;

		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"service data length = %d\n", entry_list->dataSize);
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"number of services = %d\n", entry_list->svcNum);

		for (i = 0; i < entry_list->svcNum; i++)
		{
			switch (entry_beg->svcProtol)
			{
			case BCMP2P_SVC_PROTYPE_UPNP:
				P2PLOG1("BCMP2P_SVC_PROTYPE_UPNP dataSize = %d\n", entry_beg->dataSize);
#if P2P_UPNP_DISCOVERY
				{
					BCMP2P_UINT8 prot_str[200];
					prot_str[0] = 0;
					p2papp_sd_upnp_print_information(prot_str, sizeof(prot_str),
						entry_beg->svcData, entry_beg->dataSize);
					if (strlen((char *)prot_str))
						P2PLOG1("SVC: %s\n", prot_str);
				}
#endif
				break;
			case BCMP2P_SVC_PROTYPE_BONJOUR:
				P2PLOG1("BCMP2P_SVC_PROTYPE_BONJOUR dataSize = %d\n", entry_beg->dataSize);
				break;
			default:
				break;
			}
			entry_beg = (BCMP2P_SVC_ENTRY *)((uint8 *)entry_beg +
				sizeof(BCMP2P_SVC_ENTRY) + entry_beg->dataSize - 1);
		}
	}
}

void
p2papp_print_peers_list(const char *line_prefix, BCMP2P_BOOL dbg)
{
	int j;
	BCMP2P_DISCOVER_ENTRY *peer;
	char wfd_info_str[256] = { 0 };
	char display_info_str[1024] = { 0 };

	if (p2papp_peer_count == 0) {
		if (dbg)
			p2papi_log(BCMP2P_LOG_VERB, TRUE, "%sNone\n", line_prefix);
		else
			printf("%sNone\n", line_prefix);
	} else {
		char *go_str;
		char *pg_str = "";
		char *wps_str;
		for (j = 0; j < p2papp_peer_count; j++) {
			BCMP2P_PERSISTENT persist;
			BCMP2P_BOOL is_persist = FALSE;
			uint32 cfg_methods;
			BCMP2P_CHANNEL_STRING channel_str;
			peer = &p2papp_peers_list[j];

			/* peer channel */
			BCMP2PChannelToString(&peer->channel, channel_str);

			/* check if peer has persistent data */
			if (p2papp_enable_persistent &&
				p2papp_persist_find_addr(
					(BCMP2P_ETHER_ADDR *)peer->mac_address, &persist) != 0) {
				if (peer->is_p2p_group) {
					/* peer is active GO -
					 * persistent data must be client with matching ssid
					 */
					if (!persist.is_go &&
						strncmp((char *)persist.ssid, (char *)peer->ssid,
						sizeof((char *)persist.ssid)) == 0) {
						is_persist = TRUE;
					}
				}
				else {
					is_persist = TRUE;
				}
			}
			go_str = (peer->is_p2p_group) ? "GO" : "  ";
			pg_str = is_persist ? "PG" : "  ";
			cfg_methods = p2papp_get_provision_config_methods(
				p2papp_provision_config_methods, peer->wps_cfg_methods);
			if (cfg_methods == BCMP2P_WPS_DISPLAY)
				wps_str = "display";
			else if (cfg_methods == BCMP2P_WPS_KEYPAD)
				wps_str = "keypad";
			else if (cfg_methods == BCMP2P_WPS_LABEL)
				wps_str = "label";
			else if (cfg_methods == BCMP2P_WPS_PUSHBUTTON)
				wps_str = "pbc";
			else
				wps_str = "none";
			{
				BCMP2P_SVC_LIST *entry_list;
#if P2P_UPNP_DISCOVERY
				entry_list = (BCMP2P_SVC_LIST *)(peer->svc_resp);
#else
				BCMP2PGetDiscoverService(p2papp_dev_hdl,
					(BCMP2P_ETHER_ADDR *)&peer->mac_address,
					&entry_list);
#endif /* P2P_UPNP_DISCOVERY */
				p2papp_print_discovered_services(entry_list);
			}

			/* Get peer WFDisp device information */
			p2papi_log(BCMP2P_LOG_MED, TRUE, "PEER SSID: %s\n", peer->ssid);
			p2papi_log_hexdata(BCMP2P_LOG_INFO, "Discovered peer mac: ", peer->mac_address, 6);

			sprintf(display_info_str, 
					"%s%2d)  %-25.25s  %02x:%02x:%02x:%02x:%02x:%02x %s  %s  Ch.%4s  %s ",
					line_prefix,
					j+1, peer->ssid,
					peer->mac_address[0], peer->mac_address[1],
					peer->mac_address[2], peer->mac_address[3],
					peer->mac_address[4], peer->mac_address[5],
					go_str, pg_str, channel_str, wps_str);

			if (p2papp_enable_wfdisp) {
				p2papp_wfd_form_peer_dev_info(peer->ie_data, peer->ie_data_len,
					wfd_info_str, sizeof(wfd_info_str));
				
				/* Attach WFDisp information if WFDisp is enabled */
				strcat(display_info_str, wfd_info_str);
			}

			if (dbg)
				p2papi_log(BCMP2P_LOG_MED, TRUE, "%s\n", display_info_str);
			else
				printf("%s\n", display_info_str);

			if (peer->is_p2p_group) {
				BCMP2PGetPeerGOClientInfo(p2papp_dev_hdl, peer,
					p2papp_client_list,
					sizeof(p2papp_client_list),
					&p2papp_client_count);
				if (p2papp_client_count) {
					int k;
					for (k = 0; k < p2papp_client_count; k++) {
						sprintf(display_info_str, 
								"%s    %2d) %02x:%02x:%02x:%02x:%02x:%02x %s ",
								line_prefix,
								k+1,
								p2papp_client_list[k].dev_addr.octet[0],
								p2papp_client_list[k].dev_addr.octet[1],
								p2papp_client_list[k].dev_addr.octet[2],
								p2papp_client_list[k].dev_addr.octet[3],
								p2papp_client_list[k].dev_addr.octet[4],
								p2papp_client_list[k].dev_addr.octet[5],
								p2papp_client_list[k].discoverable? "discoverable client" : "");

						/* Attach WFDisp info if it is enabled */
						if (p2papp_enable_wfdisp) {
							/* Print WFDisp information for the GC associated to the peer GO */
							p2papp_wfd_form_gc_dev_info(p2papp_client_list[k].int_addr.octet, 
								j, peer->ie_data, peer->ie_data_len, 
								wfd_info_str, sizeof(wfd_info_str));

							strcat(display_info_str, wfd_info_str);
						}

						if (dbg)
							p2papi_log(BCMP2P_LOG_MED, TRUE, "%s\n", display_info_str);
						else
							printf("%s\n", display_info_str);
					}
				}
			}
		}
	}
}

/* Print a list of STAs associated to the soft AP. */
void
p2papp_print_assoc_list(const char *prefix)
{
	BCMP2P_STATUS status;
	uint32 i, num_peers = 0;
	BCMP2P_PEER_INFO info[8];
	char display_info_str[512];

	memset(info, 0, sizeof(info));
	status = BCMP2PGetPeerInfo(p2papp_dev_hdl, &info[0], sizeof(info), &num_peers);
	if (status != BCMP2P_SUCCESS)
		return;

	printf("%s%d devices\n", prefix, num_peers);
	for (i = 0; i < num_peers; i++) {
		BCMP2P_PEER_INFO *peer = &info[i];

		sprintf(display_info_str,
				"|      %02x:%02x:%02x:%02x:%02x:%02x ",
				peer->mac_address[0], 
				peer->mac_address[1], 
				peer->mac_address[2], 
				peer->mac_address[3], 
				peer->mac_address[4], 
				peer->mac_address[5]);
		
		/* Attached WFDisp info if it is enabled */
		if (p2papp_enable_wfdisp) {
			char wfd_info_str[256] = { 0 };

			p2papp_wfd_form_peer_dev_info(peer->ie_data, peer->ie_data_len,
				wfd_info_str, sizeof(wfd_info_str));
			strcat(display_info_str, wfd_info_str);
		}

		printf("%s\n", display_info_str);
	}
}
#endif /* SOFTAP_ONLY */

/* Print a list of connected peers.
 * For exercising the BCMP2PGetPeerInfo() API.
 */
void
p2papp_print_peer_names(const char *prefix, BCMP2P_BOOL dbg)
{
#ifndef SOFTAP_ONLY
	BCMP2P_STATUS status;
	uint32 num_peers = 0;
	BCMP2P_PEER_INFO info[8];
	BCMP2P_PEER_INFO *peer;
	BCMP2P_BOOL i_am_ap = BCMP2PIsAP(p2papp_dev_hdl);
	uint32 i;
	char display_info_str[512] = { 0 };

#ifndef SOFTAP_ONLY
	if (p2papp_is_created_grp_owner) {
		p2papp_print_assoc_list(prefix);
		return;
	}
#endif /* SOFTAP_ONLY */

	memset(info, 0, sizeof(info));
	status = BCMP2PGetPeerInfo(p2papp_dev_hdl, &info[0], sizeof(info),
		&num_peers);
	if (status != BCMP2P_SUCCESS)
		return;

	if (dbg) {
		p2papi_log(BCMP2P_LOG_MED, TRUE, "%s%s", prefix,
			(num_peers == 0) ? " <none>" : "");
	} else {
		printf("%s%s", prefix,
			(num_peers == 0) ? " <none>" : "");
	}

	if (num_peers > 0)
		sprintf(display_info_str, " %d Devices\n", num_peers);

	for (i = 0; i < num_peers; i++) {
		char wfd_info_str[256];
		char mac_str[32] = { 0 };

		peer = &info[i];

		if (!dbg && i > 0 && !p2papp_enable_wfdisp) {
			printf(", ");
		}

		/* Add ssid string if it is available */
		if (peer->ssidLength > 0 && peer->ssid[0] != '\0') {
			strcpy(display_info_str, (char*)peer->ssid);
		}
		else {
			sprintf(mac_str, 
					"|        %02x:%02x:%02x:%02x:%02x:%02x%s",
					peer->mac_address[0], peer->mac_address[1],
					peer->mac_address[2], peer->mac_address[3],
					peer->mac_address[4], peer->mac_address[5],
					(i_am_ap && !peer->is_p2p) ? "(non-p2p)" : "");
		}

		strcat(display_info_str, mac_str);

		/* Attach WFDisp info if it is enabled */
		if (p2papp_enable_wfdisp && peer->is_p2p) {
			p2papp_wfd_form_peer_dev_info(peer->ie_data, 
				peer->ie_data_len, wfd_info_str, sizeof(wfd_info_str));

			strcat(display_info_str, wfd_info_str);
			strcat(display_info_str, "\n");
		}

		if (dbg)
			p2papi_log(BCMP2P_LOG_MED, FALSE, "%s", display_info_str);
		else
			printf("%s", display_info_str);
	}

	if (dbg)
		p2papi_log(BCMP2P_LOG_MED, FALSE, "\n");
	else
		printf("\n");
#else
	(void) prefix;
	(void) dbg;
#endif /* SOFTAP_ONLY */
}

BCMP2P_BOOL
p2papp_find_first_assoc_sta(BCMP2P_ETHER_ADDR *out_mac)
{
#ifndef SOFTAP_ONLY
	BCMP2P_STATUS status;
	uint32 num_peers = 0;
	BCMP2P_PEER_INFO info[8];
	BCMP2P_PEER_INFO *peer;

	memset(info, 0, sizeof(info));
	status = BCMP2PGetPeerInfo(p2papp_dev_hdl, &info[0], sizeof(info),
		&num_peers);
	if (status != BCMP2P_SUCCESS)
		return FALSE;
	if (num_peers == 0)
		return FALSE;

	peer = &info[0];
	memcpy(out_mac->octet, peer->mac_address, sizeof(out_mac->octet));
	return TRUE;
#else
	return FALSE;
#endif /* SOFTAP_ONLY */
}

BCMP2P_BOOL
p2papp_find_assoc_stas(uint32 mac_list_max, BCMP2P_ETHER_ADDR *out_mac_list,
	uint32 *out_mac_count)
{
#ifndef SOFTAP_ONLY
	BCMP2P_STATUS status;
	uint32 num_peers = 0;
	BCMP2P_PEER_INFO info[8];
	BCMP2P_PEER_INFO *peer;
	uint32 i;

	memset(info, 0, sizeof(info));
	status = BCMP2PGetPeerInfo(p2papp_dev_hdl, &info[0], sizeof(info),
		&num_peers);
	if (status != BCMP2P_SUCCESS)
		return FALSE;
	if (num_peers == 0)
		return FALSE;

	*out_mac_count = num_peers;
	if (*out_mac_count > mac_list_max)
		*out_mac_count = mac_list_max;
	for (i = 0; i < *out_mac_count; i++) {
		peer = &info[i];
		memcpy(out_mac_list[i].octet, peer->mac_address,
			sizeof(out_mac_list[i].octet));
	}

	return TRUE;
#else
	return FALSE;
#endif /* SOFTAP_ONLY */
}

#ifndef SOFTAP_ONLY

#endif /* SOFTAP_ONLY */

/* Redraw screen */
static void
p2papp_redraw(char *str1, char *str2, char *str3)
{
	p2papp_redraw_ex(str1, str2, str3, TRUE);
}

void
p2papp_display_status(void)
{
	p2papp_redraw_ex(NULL, NULL, NULL, FALSE);
}

static void
p2papp_redraw_ex(char *str1, char *str2, char *str3, BCMP2P_BOOL display_cmds)
{
#ifdef SOFTAP_ONLY
	BCMP2P_BOOL is_ap = FALSE;
	BCMP2P_BOOL is_sta = FALSE;
	BCMP2P_BOOL is_connecting = FALSE;
#else
	BCMP2P_BOOL is_ap = BCMP2PIsAP(p2papp_dev_hdl);
	BCMP2P_BOOL is_sta = BCMP2PIsSTA(p2papp_dev_hdl);
	BCMP2P_BOOL is_connecting = BCMP2PIsConnecting(p2papp_dev_hdl);
	char *discov_str = "Off";
	BCMP2P_ETHER_ADDR my_p2p_dev_addr;
	BCMP2P_ETHER_ADDR my_p2p_int_addr;
#endif /* SOFTAP_ONLY */
	BCMP2P_BOOL is_softap_on = BCMP2PIsSoftAPOn(p2papp_dev_hdl);
	char *connected_str = "";
	char conn_str[90];
	char *channel_str = "";
	char chan_str[16];
	BCMP2P_CHANNEL channel;

	/* Generate a debug log to provide a timestamp for this screen redraw */
	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_redraw: %s\n", str1);


	if (p2papp_is_created_grp_owner || is_ap) {
#ifndef SOFTAP_ONLY
		connected_str = conn_str;
		sprintf(conn_str, "is GO '%s'", p2papp_ssid);
#endif /* SOFTAP_ONLY */
	} else if (p2papp_is_created_softap) {
		connected_str = conn_str;
		strcpy(conn_str, "is SoftAP,");
		if (is_softap_on) {
			strcat(conn_str, " ready, ssid=");
			strcat(conn_str, p2papp_ssid);
		} else {
			strcat(conn_str, " not ready");
		}
	} else if (is_sta) {
		connected_str = "is STA";
	} else if (is_connecting) {
		connected_str = "connecting...";
	} else {
		connected_str = "No";
	}

	if (p2papp_is_created_grp_owner || p2papp_is_created_softap || is_ap || is_sta) {
		BCMP2P_CHANNEL_STRING str;
		BCMP2PGetChannel(p2papp_dev_hdl, &channel);
		BCMP2PChannelToString(&channel, str);
		sprintf(chan_str, " Ch=%s", str);
		channel_str = chan_str;
	}

	if (str1)
		p2papp_status_str = str1;
	if (str2)
		p2papp_status_str2 = str2;
	if (str3)
		p2papp_status_str3 = str3;

	/* Duplicate the redraw's status lines to the log file to make it easier
	 * to correlate timestamps in the log file with the screen output.
	 */
	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"+-------------------------------------------------------------\n");
	p2papi_log(BCMP2P_LOG_MED, TRUE, "| Status: %s\n", p2papp_status_str);
	p2papi_log(BCMP2P_LOG_MED, TRUE, "|         %s\n", p2papp_status_str2);
	if (p2papp_status_str3 != NULL && *p2papp_status_str3 != '\0')
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"|         %s\n", p2papp_status_str3);

#ifndef SOFTAP_ONLY
	if (BCMP2PIsDiscovering(p2papp_dev_hdl))
		discov_str = p2papp_is_listen_only ? "Listen" : "On";
	else
		discov_str = "Off";
	p2papi_log(BCMP2P_LOG_MED, TRUE, "| P2P Discovery: %-35s\n", discov_str);
#endif /* not SOFTAP_ONLY */

	p2papi_log(BCMP2P_LOG_MED, TRUE, "| Connected    : %s, %s%s%s\n",
		connected_str,
		"PIN=",
		BCMP2PGetWPSPin(p2papp_dev_hdl),
		channel_str);
#ifndef SOFTAP_ONLY
	p2papi_log(BCMP2P_LOG_MED, TRUE, "| Persistent   : %s\n",
		p2papp_enable_persistent ? "On" : "Off");
	if (BCMP2PIsDiscovering(p2papp_dev_hdl)) {
		p2papi_log(BCMP2P_LOG_MED, TRUE, "| %sDiscovered peers:\n",
			p2papp_is_listen_only ? "Previous " : "");
		p2papp_print_peers_list("|  ", TRUE);
	}
#endif /* SOFTAP_ONLY */
	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"+-------------------------------------------------------------\n");

	/* Redraw the status lines */
	printf("\n");
	printf("+-------------------------------------------------------------"
			 "----------------+\n");
	printf("| Status: %s\n", p2papp_status_str);
	if (p2papp_status_str2 && *p2papp_status_str2 != '\0')
		printf("|         %s\n", p2papp_status_str2);
	if (p2papp_status_str3 != NULL && *p2papp_status_str3 != '\0')
		printf("|         %s\n", p2papp_status_str3);
#ifndef SOFTAP_ONLY
	printf("|                                                   ");
	(void) BCMP2PGetIntAddr(p2papp_dev_hdl, &my_p2p_int_addr);
	printf("IntAddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		my_p2p_int_addr.octet[0], my_p2p_int_addr.octet[1],
		my_p2p_int_addr.octet[2], my_p2p_int_addr.octet[3],
		my_p2p_int_addr.octet[4], my_p2p_int_addr.octet[5]);
	printf("| P2P Discovery: %-35s",
		BCMP2PIsDiscovering(p2papp_dev_hdl) ? "On" : "Off");
	(void) BCMP2PGetDevAddr(p2papp_dev_hdl, &my_p2p_dev_addr);
	printf("DevAddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		my_p2p_dev_addr.octet[0], my_p2p_dev_addr.octet[1],
		my_p2p_dev_addr.octet[2], my_p2p_dev_addr.octet[3],
		my_p2p_dev_addr.octet[4], my_p2p_dev_addr.octet[5]);
#endif /* SOFTAP_ONLY */
	printf("| Connected    : %-35s", connected_str);
	printf("PIN=%s", BCMP2PGetWPSPin(p2papp_dev_hdl));
	printf("%s", channel_str);
	printf("\n");
	if (is_sta || is_ap) {
		p2papp_print_peer_names("| Connected to : ", FALSE);
	}
#ifndef SOFTAP_ONLY
	printf("| Persistent   : %s\n", p2papp_enable_persistent ? "On" : "Off");
	if (BCMP2PIsDiscovering(p2papp_dev_hdl)) {
		printf("| %sDiscovered peers:\n",
			p2papp_is_listen_only ? "Previous " : "");
		p2papp_print_peers_list("|  ", FALSE);
	}

#endif /* not SOFTAP_ONLY */

	/* Redraw the menu lines */
	if (display_cmds) {
#ifndef SOFTAP_ONLY
		/* Display commands. */
		printf("| _____________________ P2P Commands _______________\n");
		printf("| e) Enable discovery         l) Enter Listen state\n");
		printf("| d) Disable discovery\n");
		printf("| p) Enter WPS PIN          pbc) Activate pushbutton\n");
		printf("| g) Create P2P Group Owner\n");
		printf("| <num>) Initiate connection to discovered peer <num>\n");
		printf("| P <num>) Send provision discovery request to peer <num>\n");

		if (is_sta && p2papp_is_connected) {
			printf("| b) Send presence request\n");
		} else if (is_ap && !p2papp_is_created_softap) {
			printf("| b) Enable opportunistic power save and NoA schedule\n");
		}
		printf("| B) Enable extended listen timing\n");
		printf("| S <num>) Send service discovery to peer <num>\n");
		printf("| D <num> <client#>) Send dev discoverability to GO <num>\n");
		printf("| v) Enable persistent groups\n");
		printf("| w) Disable persistent groups\n");
		printf("| y) Delete all persistent credentials\n");

#endif /* SOFTAP_ONLY */
		printf("| ___________________ SoftAP Commands _____________\n");
		printf("| s) Soft AP Create           t) Soft AP Teardown\n");

		printf("| ___________________ Common Commands _____________\n");
		printf("| r) Redraw screen            q) Quit\n");
		if (is_sta || is_ap || is_connecting) {
			printf("| x) Disconnect or Cancel connection\n");
		}
	}

	printf("+-------------------------------------------------------------"
		"----------------+\n");
}

#ifndef SOFTAP_ONLY
static void
p2papp_get_discovery_results(void)
{
	BCMP2PGetDiscoverResult(p2papp_dev_hdl, FALSE, p2papp_peers_list,
		sizeof(p2papp_peers_list), &p2papp_peer_count);

	P2PLOG2("p2papp_get_discovery_results: count=%d timedout=%d\n",
		p2papp_peer_count, p2papp_discovery_timed_out);
}
#endif /* SOFTAP_ONLY */

#ifndef SOFTAP_ONLY
static BCMP2P_BOOL
p2papp_proc_rx_invite_req(void *pNotificationData)
{
	BCMP2P_BOOL status = BCMP2P_FALSE;
	BCMP2P_INVITE_PARAM invite_req;
	BCMP2P_INVITE_RESPONSE response = BCMP2P_INVITE_REJECT;
	BCMP2P_PERSISTENT persist;
	BCMP2P_BOOL isReinvoke = BCMP2P_FALSE;
	BCMP2P_BOOL isGo = BCMP2P_FALSE;
	BCMP2P_CHANNEL channel;

	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_proc_rx_invite_req\n");
	memcpy(&invite_req, pNotificationData,
		sizeof(invite_req));

	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"p2papp_proc_rx_invite_req: ssid=%s,len=%d ch=%d:%d flags=%d\n",
		invite_req.groupSsid, invite_req.groupSsidLength,
		invite_req.operatingChannel.channel_class,
		invite_req.operatingChannel.channel,
		invite_req.inviteFlags);
	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"    bssid=%02x:%02x:%02x:%02x:%02x:%02x"
		" devAddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		invite_req.groupBssid.octet[0],
		invite_req.groupBssid.octet[1],
		invite_req.groupBssid.octet[2],
		invite_req.groupBssid.octet[3],
		invite_req.groupBssid.octet[4],
		invite_req.groupBssid.octet[5],
		invite_req.groupDevAddr.octet[0],
		invite_req.groupDevAddr.octet[1],
		invite_req.groupDevAddr.octet[2],
		invite_req.groupDevAddr.octet[3],
		invite_req.groupDevAddr.octet[4],
		invite_req.groupDevAddr.octet[5]);

	if (BCMP2PIsSTA(p2papp_dev_hdl)) {
		p2papi_log(BCMP2P_LOG_MED, TRUE, "reject invite - already a STA\n");
		response = BCMP2P_INVITE_REJECT;
	}
	else if (BCMP2PIsGroupOwner(p2papp_dev_hdl)) {
		p2papi_log(BCMP2P_LOG_MED, TRUE, "reject invite - already a GO\n");
		response = BCMP2P_INVITE_REJECT;
	}
	else if (invite_req.inviteFlags & 0x1) {
		if (p2papp_enable_persistent &&
			p2papp_persist_find_ssid((char *)invite_req.groupSsid,
			&persist) != 0) {
			isReinvoke = TRUE;
			if (persist.is_go) {
				BCMP2PGetOperatingChannel(p2papp_dev_hdl,
					&channel.channel_class, &channel.channel);
				if ( BCMP2PGetReinvokeChannel(p2papp_dev_hdl, &channel) != BCMP2P_SUCCESS)
				{
					p2papi_log(BCMP2P_LOG_MED, TRUE,
						"reject invite - No Channel accept\n");
					response = BCMP2P_INVITE_REJECT_NO_COMMON_CHANNEL;

				}
				else
				{
					BCMP2PSetOperatingChannel(p2papp_dev_hdl,
						channel.channel_class, channel.channel);
					p2papi_log(BCMP2P_LOG_MED, TRUE,
						"accept invite - reinvoke GO\n");
					response = BCMP2P_INVITE_ACCEPT;
					isGo = TRUE;
				}
			}
			else {
				p2papi_log(BCMP2P_LOG_MED, TRUE,
					"accept invite - reinvoke STA\n");
				response = BCMP2P_INVITE_ACCEPT;
				isGo = FALSE;
			}
		}
		else {
			p2papi_log(BCMP2P_LOG_MED, TRUE,
				"reject invite - unknown group\n");
			response = BCMP2P_INVITE_REJECT_UNKNOWN_GROUP;
		}
	}
	else {
		if (memcmp(&invite_req.groupBssid,
			&P2PAPP_NULL_BSSID,	sizeof(P2PAPP_NULL_BSSID)) == 0) {
			p2papi_log(BCMP2P_LOG_MED, TRUE,
				"reject invite - no group BSSID\n");
			response = BCMP2P_INVITE_REJECT_UNKNOWN_GROUP;
		}
		else {
			p2papi_log(BCMP2P_LOG_MED, TRUE,
				"accept invite - join existing group\n");
			response = BCMP2P_INVITE_ACCEPT;
		}
	}

	/* send invitation response before processing invite */
	BCMP2PSendInviteResponse(p2papp_dev_hdl,
		&invite_req, response, isGo);

	sprintf(p2papp_msg_buf,
		"........ %s Invitation Request from %02x:%02x:%02x:%02x:%02x:%02x",
		response == BCMP2P_INVITE_ACCEPT ? "Accepted" : "Rejected",
		invite_req.srcDevAddr.octet[0],
		invite_req.srcDevAddr.octet[1],
		invite_req.srcDevAddr.octet[2],
		invite_req.srcDevAddr.octet[3],
		invite_req.srcDevAddr.octet[4],
		invite_req.srcDevAddr.octet[5]);
	p2papp_redraw(p2papp_msg_buf, "", "");

	if (response == BCMP2P_INVITE_ACCEPT) {
		/* delay to allow tx of invite response before processing invite */
		p2papp_delay(500);

		if (isReinvoke) {
			if (isGo) {
				p2papp_redraw("....... Reinvoking persistent GO .......",
					p2papp_msg_buf2, "");
				BCMP2PUpdateWPAKey(p2papp_dev_hdl,
					(char *)persist.pmk,
					(char *)persist.passphrase);
				BCMP2PCreateGroup(p2papp_dev_hdl,
					invite_req.groupSsid, TRUE);
			}
			else {
				p2papi_log(BCMP2P_LOG_MED, TRUE,
					"wait for GO's config timeout %u ms\n",
					invite_req.goConfigTimeoutMs);
				p2papp_delay(invite_req.goConfigTimeoutMs);
				p2papp_redraw("....... Reinvoking persistent client .......",
					p2papp_msg_buf2, "");
				BCMP2PJoinGroupWithCredentials(p2papp_dev_hdl,
					&invite_req.groupDevAddr,
					&invite_req.operatingChannel,
					invite_req.groupSsid,
					invite_req.groupSsidLength,
					&invite_req.groupBssid,
					persist.pmk,
					P2PAPP_CONNECT_TMO_SECS);
			}
		}
		else {
			/* receiving invite to join an existing group requires
			 * invited peer to send provision discovery which requires
			 * user input so join with WPS should not be invoked until
			 * after user input
			 * however, sigma requires and checks for provision so this
			 * code is only to satisify sigma
			 * proper app implmentation should invoke provision discovery,
			 * wait for user input, then initiate connect back to peer
			 */
			p2papi_log(BCMP2P_LOG_MED, TRUE,
				"wait for GO's config timeout %u ms\n",
				invite_req.goConfigTimeoutMs);
			p2papp_delay(invite_req.goConfigTimeoutMs);
			p2papp_redraw("....... Sending provision discovery request .......",
				p2papp_msg_buf2, "");

			
			BCMP2PSendProvisionDiscoveryRequest(p2papp_dev_hdl,
				p2papp_get_provision_config_methods(
				p2papp_provision_config_methods,
				p2papp_provision_config_methods),
				TRUE, invite_req.groupSsid,
				invite_req.groupSsidLength,
				&invite_req.operatingChannel,
				&invite_req.groupDevAddr);
			p2papp_redraw("........ Joining existing group........",
				p2papp_msg_buf2, "");

			BCMP2PCreateLinkToDevAddr(p2papp_dev_hdl,
				&invite_req.groupDevAddr, &invite_req.operatingChannel,
				TRUE, &invite_req.groupBssid,
				BCMP2P_CONNECT_TMO_SECS);
		}
		status = BCMP2P_TRUE;
	}
	return status;
}

static BCMP2P_BOOL
p2papp_proc_rx_invite_rsp(void *pNotificationData)
{
	BCMP2P_BOOL status = BCMP2P_FALSE;
	BCMP2P_INVITE_PARAM invite_rsp;
	char *status_str;
	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_proc_rx_invite_rsp\n");
	memcpy(&invite_rsp, pNotificationData,
		sizeof(invite_rsp));

	if (invite_rsp.status == P2P_STATSE_PASSED_UP)
		status_str = "passed up";
	else if (invite_rsp.status == P2P_STATSE_SUCCESS)
		status_str = "accepted";
	else
		status_str = "rejected";

	sprintf(p2papp_msg_buf,
		"........ Received Invite Rsp (%s) ........", status_str);
	sprintf(p2papp_msg_buf2,
		"........ from %02x:%02x:%02x:%02x:%02x:%02x",
		invite_rsp.srcDevAddr.octet[0],
		invite_rsp.srcDevAddr.octet[1],
		invite_rsp.srcDevAddr.octet[2],
		invite_rsp.srcDevAddr.octet[3],
		invite_rsp.srcDevAddr.octet[4],
		invite_rsp.srcDevAddr.octet[5]);
	p2papp_redraw(p2papp_msg_buf, p2papp_msg_buf2, "");

	if (invite_rsp.status == P2P_STATSE_SUCCESS) {
		if (memcmp(&invite_rsp.groupBssid,
			&P2PAPP_NULL_BSSID,	sizeof(P2PAPP_NULL_BSSID)) != 0) {
			BCMP2P_PERSISTENT persist;
			if (p2papp_enable_persistent &&
				p2papp_persist_find_addr(&invite_rsp.srcDevAddr,
				&persist) != 0) {
				p2papi_log(BCMP2P_LOG_MED, TRUE,
					"wait for GO's config timeout %u ms\n",
					invite_rsp.goConfigTimeoutMs);
					p2papp_delay(invite_rsp.goConfigTimeoutMs);
				p2papp_redraw("....... Reinvoking persistent client .......",
					p2papp_msg_buf2, "");
				BCMP2PJoinGroupWithCredentials(p2papp_dev_hdl,
					&invite_rsp.srcDevAddr,
					&invite_rsp.operatingChannel,
					persist.ssid,
					strlen((const char *)persist.ssid),
					&invite_rsp.groupBssid,
					persist.pmk,
					P2PAPP_CONNECT_TMO_SECS);
			}
		}
		status = BCMP2P_TRUE;
	}
	else if (invite_rsp.status == P2P_STATSE_FAIL_INFO_CURR_UNAVAIL) {
		/* do nothing if no info available */
		status = BCMP2P_TRUE;
	}

	return status;
}
#endif /* SOFTAP_ONLY */


/*
 * Callback to receive P2P Library event notifications.
 * Note: This callback is called from a different thread than the one
 *       calling BCMP2PDiscover() and BCMP2PCreateLink()
 * Note: This callback is call from the HSL's event handler thread so HSL
 *       receive event processing is blocked until this function returns.
 *       Therefore this function must never call any HSL APIs that wait for
 *       a received event before returning.  eg. BCMP2PJoinGroupWithWps().
 */
static void
p2papp_notif_cb(BCMP2P_NOTIFICATION_CODE code, void *pContext,
	void *pNotificationData, int notificationDataLength)
{
	p2papp_event_t event;

	assert(notificationDataLength <= MAX_NOTIFICATION_SIZE);
	if (notificationDataLength > MAX_NOTIFICATION_SIZE)
		goto fail;

	/* queue up event for processing */
	memset(&event, 0, sizeof(event));
	event.context = pContext;
	event.code = code;
	memcpy(event.notificationData, pNotificationData, notificationDataLength);
	event.notificationDataLength = notificationDataLength;

	if (p2papp_eventq_send((char *)&event) == 0)
		return;

fail:
	p2papi_log(BCMP2P_LOG_ERR, TRUE,
		"p2p_app: failed to queue event: code=%04x length=%d\n",
		code, notificationDataLength);
}

static void
p2papp_process_event(BCMP2P_NOTIFICATION_CODE code, void *pContext,
	void *pNotificationData, int notficationDataLength)
{
#ifndef SOFTAP_ONLY
	static BCMP2P_BOOL is_gon_go = FALSE;
	char *wps_str;
	uint8 status_code;
	BCMP2P_CHANNEL channel;
	BCMP2P_CHANNEL_STRING channel_str;
#endif /* not SOFTAP_ONLY */

	(void) pContext;
/*	P2PLOG2("p2papp_notif_cb: code=0x%02x ctxt=%p\n", code, pContext); */

	switch (code) {
#ifndef SOFTAP_ONLY
	case BCMP2P_NOTIF_DISCOVER_START_80211_SCAN:
		P2PLOG("BCMP2P_NOTIF_DISCOVER_START_80211_SCAN\n");
		p2papp_is_discover_disabled = BCMP2P_FALSE;
		p2papp_redraw("........Scanning for groups........", "", "");
		break;
	case BCMP2P_NOTIF_DISCOVER_START_SEARCH_LISTEN:
		P2PLOG("p2papp: BCMP2P_NOTIF_DISCOVER_START_SEARCH_LISTEN\n");
		p2papp_redraw("........Scanning for peers........", "", "");
		break;
	case BCMP2P_NOTIF_DISCOVER_SEARCH_LISTEN_ITERATION:
		P2PVERB("p2papp: BCMP2P_NOTIF_DISCOVER_SEARCH_LISTEN_ITERATION\n");
		break;
	case BCMP2P_NOTIF_DISCOVER_FOUND_P2P_GROUPS:
		P2PLOG("p2papp: BCMP2P_NOTIF_DISCOVER_FOUND_P2P_GROUPS\n");
		p2papp_get_discovery_results();
		p2papp_redraw(NULL, NULL, NULL);
		break;
	case BCMP2P_NOTIF_DISCOVER_FOUND_PEERS:
		P2PLOG("p2papp: BCMP2P_NOTIF_DISCOVER_FOUND_PEERS\n");
		p2papp_get_discovery_results();
		p2papp_redraw(NULL, NULL, NULL);
		break;
	case BCMP2P_NOTIF_DISCOVER_CANCEL:
		P2PLOG("p2papp: BCMP2P_NOTIF_DISCOVER_CANCEL\n");
		p2papp_is_discover_disabled = BCMP2P_TRUE;
		p2papp_redraw("........ Discovery cancelled ........", "", "");
		break;
	case BCMP2P_NOTIF_DISCOVER_FAIL:
		P2PLOG("p2papp: BCMP2P_NOTIF_DISCOVER_FAIL\n");
		p2papp_is_discover_disabled = BCMP2P_TRUE;
		p2papp_discovery_failed = TRUE;
		p2papp_redraw("........ Discovery failed ........", "", "");
		break;
	case BCMP2P_NOTIF_DISCOVER_COMPLETE:
		P2PLOG("p2papp: BCMP2P_NOTIF_DISCOVER_COMPLETE\n");
		p2papp_is_discover_disabled = BCMP2P_TRUE;
		p2papp_discovery_timed_out = BCMP2P_TRUE;
		p2papp_iterate_discovery();
		p2papp_redraw("Discovery timed out", "", "");
		break;
	case BCMP2P_NOTIF_DISCOVER_SUSPENDED:
		P2PLOG("p2papp: BCMP2P_NOTIF_DISCOVER_SUSPENDED\n");
		p2papp_redraw("........Discovery suspended........", NULL, NULL);
		break;
	case BCMP2P_NOTIF_DISCOVER_RESUMED:
		P2PLOG("p2papp: BCMP2P_NOTIF_DISCOVER_RESUMED\n");
		p2papp_redraw("........Scanning for peers........", NULL, NULL);
		break;
	case BCMP2P_NOTIF_DISCOVER_START_LISTEN_ONLY:
		P2PLOG("p2papp: BCMP2P_NOTIF_DISCOVER_START_LISTEN_ONLY\n");
		p2papp_redraw("........Entered Listen State........", "", "");
		break;

	/* provision discovery */
	case BCMP2P_NOTIF_PROVISION_DISCOVERY_REQUEST:
	{
		BCMP2P_DISCOVER_ENTRY notification_data;
		P2PLOG("p2papp: BCMP2P_NOTIF_PROVISION_DISCOVERY_REQUEST\n");
		memcpy(&notification_data, pNotificationData,
			sizeof(notification_data));
		printf("\n");
		sprintf(p2papp_msg_buf,
			"........ Provision discovery request from %s "
			"(%02x:%02x:%02x:%02x:%02x:%02x)",
			notification_data.ssid,
			notification_data.mac_address[0],
			notification_data.mac_address[1],
			notification_data.mac_address[2],
			notification_data.mac_address[3],
			notification_data.mac_address[4],
			notification_data.mac_address[5]);
		wps_str =
			(notification_data.wps_cfg_methods == BCMP2P_WPS_DISPLAY)
			? "Display"
			: (notification_data.wps_cfg_methods == BCMP2P_WPS_KEYPAD)
			? "Keypad"
			: (notification_data.wps_cfg_methods == BCMP2P_WPS_LABEL)
			? "Label"
			: (notification_data.wps_cfg_methods == BCMP2P_WPS_PUSHBUTTON)
			? "Pushbutton"
			: "unknown";

		/* send response before configuring PIN else peer may
		 * timeout waiting for response
		 */
	
		BCMP2PSendProvisionDiscoveryResponse(p2papp_dev_hdl,
			notification_data.wps_cfg_methods &
			BCMP2PGetSupportedWpsConfigMethods(p2papp_dev_hdl));

		p2papp_msg_buf3[0] = '\0';
		if (notification_data.wps_cfg_methods == BCMP2P_WPS_DISPLAY) {
			char *pin;
			pin = BCMP2PGetWPSPin(p2papp_dev_hdl);
			BCMP2PSetWPSPin(p2papp_dev_hdl, pin);
			sprintf(p2papp_msg_buf3, "Enter WPS PIN=%s on peer device.", pin);
		} else if (notification_data.wps_cfg_methods == BCMP2P_WPS_KEYPAD) {
			sprintf(p2papp_msg_buf3, "Enter WPS PIN displayed on peer device.");
		} else if (notification_data.wps_cfg_methods == BCMP2P_WPS_LABEL) {
			char *pin = BCMP2PGetWPSPin(p2papp_dev_hdl);
			BCMP2PSetWPSPin(p2papp_dev_hdl, pin);
			sprintf(p2papp_msg_buf3, "Enter WPS PIN=%s on peer device.", pin);
		} else if (notification_data.wps_cfg_methods == BCMP2P_WPS_PUSHBUTTON) {
			if (p2papp_auto_pbc_mode == TRUE)
			{
				BCMP2PPushButton(p2papp_dev_hdl);
				sprintf(p2papp_msg_buf3, "Start pushbutton automatically.");
			}
			else
				sprintf(p2papp_msg_buf3, "Activate pushbutton.");

		} else {
			sprintf(p2papp_msg_buf3, "Provision discovery failed.");
		}
		p2papp_redraw(p2papp_msg_buf, wps_str, p2papp_msg_buf3);
		break;
	}

	case BCMP2P_NOTIF_PROVISION_DISCOVERY_RESPONSE:
	{
		BCMP2P_DISCOVER_ENTRY notification_data;
		P2PLOG("p2papp: BCMP2P_NOTIF_PROVISION_DISCOVERY_RESPONSE\n");
		memcpy(&notification_data, pNotificationData,
			sizeof(notification_data));
		printf("\n");
		sprintf(p2papp_msg_buf,
			"........ Provision discovery response from %02x:%02x:%02x:%02x:%02x:%02x",
			notification_data.mac_address[0],
			notification_data.mac_address[1],
			notification_data.mac_address[2],
			notification_data.mac_address[3],
			notification_data.mac_address[4],
			notification_data.mac_address[5]);
		wps_str =
			(notification_data.wps_cfg_methods == BCMP2P_WPS_DISPLAY)
			? "Display"
			: (notification_data.wps_cfg_methods == BCMP2P_WPS_KEYPAD)
			? "Keypad"
			: (notification_data.wps_cfg_methods == BCMP2P_WPS_LABEL)
			? "Label"
			: (notification_data.wps_cfg_methods == BCMP2P_WPS_PUSHBUTTON)
			? "Pushbutton"
			: "unknown";

		p2papp_msg_buf3[0] = '\0';
		if (notification_data.wps_cfg_methods == BCMP2P_WPS_KEYPAD) {
			char *pin;
			pin = BCMP2PGetWPSPin(p2papp_dev_hdl);
			BCMP2PSetWPSPin(p2papp_dev_hdl, pin);
			sprintf(p2papp_msg_buf3, "Enter WPS PIN=%s on peer device.", pin);
		} else if (notification_data.wps_cfg_methods == BCMP2P_WPS_DISPLAY) {
			sprintf(p2papp_msg_buf3, "Enter WPS PIN displayed on peer device.");
		} else if (notification_data.wps_cfg_methods == BCMP2P_WPS_LABEL) {
			sprintf(p2papp_msg_buf3, "Enter WPS PIN from label on peer device.");
		} else if (notification_data.wps_cfg_methods == BCMP2P_WPS_PUSHBUTTON) {
			sprintf(p2papp_msg_buf3, "Activate pushbutton.");
		} else {
			sprintf(p2papp_msg_buf3, "Provision discovery failed.");
		}
		p2papp_redraw(p2papp_msg_buf, wps_str, p2papp_msg_buf3);
		break;
	}

	case BCMP2P_NOTIF_PROVISION_DISCOVERY_TIMEOUT:
		P2PLOG("p2papp: BCMP2P_NOTIF_PROVISION_DISCOVERY_TIMEOUT\n");
		p2papp_redraw("Provision discovery timed out, no response", "", "");
		break;

	case BCMP2P_NOTIF_P2P_PRESENCE_REQ:
	{
		BCMP2P_PRESENCE_PARAM *param = pNotificationData;
		char *status_str = param->status == P2P_STATSE_SUCCESS ?
			"Success": "Failed";
		p2papp_redraw("Received presence request", status_str, "");
		P2PLOG("p2papp: BCMP2P_NOTIF_P2P_PRESENCE_REQ\n");
		break;
	}

	case BCMP2P_NOTIF_P2P_PRESENCE_RSP:
	{
		BCMP2P_PRESENCE_PARAM *param = pNotificationData;
		char *status_str = param->status == P2P_STATSE_SUCCESS ?
			"Success": "Failed";
		p2papp_redraw("Received presence response", status_str, "");
		P2PLOG("p2papp: BCMP2P_NOTIF_P2P_PRESENCE_RSP\n");
		break;
	}

	/* Group Owner Negotiation */
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_START:
		P2PLOG("p2papp: BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_START\n");
		p2papp_initiated_conn = TRUE;
		p2papp_is_gon_waiting = FALSE;
		break;
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_AP_ACK:
		P2PLOG("p2papp: BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_AP_ACK\n");
		is_gon_go = TRUE;
		break;
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_STA_ACK:
		P2PLOG("p2papp: BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_STA_ACK\n");
		is_gon_go = FALSE;
		break;
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_REQUEST_RECEIVED:
	{
		BCMP2P_DISCOVER_ENTRY notification_data;
		P2PLOG("p2papp: BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_REQUEST_RECEIVED\n");
			
		p2papp_initiated_conn = FALSE;
		memcpy(&notification_data, pNotificationData, sizeof(notification_data));
		sprintf(p2papp_msg_buf,
			"........ Received GON request from"
			" %02x:%02x:%02x:%02x:%02x:%02x",
			notification_data.mac_address[0],
			notification_data.mac_address[1],
			notification_data.mac_address[2],
			notification_data.mac_address[3],
			notification_data.mac_address[4],
			notification_data.mac_address[5]);
		p2papp_redraw(p2papp_msg_buf, "", "");
		break;
	}
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_COMPLETE:
		P2PLOG("p2papp: BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_COMPLETE\n");
		if (!p2papp_initiated_conn) {
			/* If an incoming connection needs us to provide a main thread context
			 * to automatically accept it.
			 */
			P2PLOG("p2p_app: processing incoming connect\n");
			BCMP2PProcessIncomingConnection(p2papp_dev_hdl,
			P2PAPP_CONNECT_TMO_SECS);
		}
		BCMP2PGetOperatingChannel(p2papp_dev_hdl,
			&channel.channel_class, &channel.channel);
		BCMP2PChannelToString(&channel, channel_str);
		sprintf(p2papp_msg_buf,
			"........ GON result - %s using operating channel %s",
			is_gon_go ? "GO" : "STA", channel_str);
		p2papp_redraw(p2papp_msg_buf, "", "");
		p2papp_msg_buf[0] = 0;
		p2papp_is_gon_waiting = FALSE;
		break;
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL:
		P2PLOG("p2papp: BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL\n");
		p2papp_redraw("........ GON failed ........", "", "");
		p2papp_update_conn_complete(code);
		p2papp_is_gon_waiting = FALSE;
		break;
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_NO_PROV_INFO:
	{
		P2PLOG("p2papp: BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_NO_PROV_INFO\n");
		memcpy(&p2papp_gon_info, pNotificationData,
			sizeof(p2papp_gon_info));
		sprintf(p2papp_msg_buf,
			"... Rejected GONreq from %02x:%02x:%02x:%02x:%02x:%02x ch %d ...",
			p2papp_gon_info.mac_address[0],
			p2papp_gon_info.mac_address[1],
			p2papp_gon_info.mac_address[2],
			p2papp_gon_info.mac_address[3],
			p2papp_gon_info.mac_address[4],
			p2papp_gon_info.mac_address[5],
			p2papp_gon_info.channel.channel);
		p2papp_redraw(p2papp_msg_buf,
			"... Because we have no provisioning info ..........",
			"### Enter 'pbc' to push button and restart GON ###");
			p2papp_is_gon_waiting = TRUE;
		p2papp_update_conn_complete(code);
		break;
	}
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL:
		P2PLOG("p2papp: BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL\n");
		p2papp_redraw("........ Peer has no provisioning info ........", "", "");
		p2papp_update_conn_complete(code);
		p2papp_is_gon_waiting = FALSE;
		break;

	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL_INTENT:
		P2PLOG("p2papp: BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL_INTENT\n");
		p2papp_redraw("........ GON intent value fail ........", "", "");
		p2papp_update_conn_complete(code);
		p2papp_is_gon_waiting = FALSE;
		break;


	case BCMP2P_NOTIF_PRIMARY_IF_DISCONNECTED:
		P2PLOG("p2papp: BCMP2P_NOTIF_PRIMARY_IF_DISCONNECTED\n");
		printf("\nPrimary interface has been disconnected by "
			"infrastructure AP with minor reason code %d.\n",
			*(uint8 *)pNotificationData);
		break;
	case BCMP2P_NOTIF_P2P_INVITE_REQ:
		P2PLOG("p2papp: BCMP2P_NOTIF_P2P_INVITE_REQ\n");
		if (!p2papp_proc_rx_invite_req(pNotificationData))
			p2papp_update_conn_complete(code);
		break;

	case BCMP2P_NOTIF_P2P_INVITE_RSP:
		P2PLOG("p2papp: BCMP2P_NOTIF_P2P_INVITE_RSP\n");
		if (!p2papp_proc_rx_invite_rsp(pNotificationData))
			p2papp_update_conn_complete(code);
		break;

	case BCMP2P_NOTIF_DEV_DISCOVERABILITY_REQ :
		P2PLOG("p2papp: BCMP2P_NOTIF_DEV_DISCOVERABILITY_REQ \n");
		printf("Received Device Discoverability Request.\n");
		break;
	case BCMP2P_NOTIF_GO_DISCOVERABILITY_REQ:
		P2PLOG("p2papp: BCMP2P_NOTIF_GO_DISCOVERABILITY_REQ\n");
		printf("Received GO Discoverability Request.\n");
		/* Enter Listen state */
		p2papp_enable_discovery(TRUE, 0);
		p2papp_received_go_discoverability_req = TRUE;
		break;
	case BCMP2P_NOTIF_DEV_DISCOVERABILITY_RSP:
		P2PLOG("p2papp: BCMP2P_NOTIF_DEV_DISCOVERABILITY_RSP\n");
		printf("Received Device Discoverability Response.\n");
		status_code = *(uint8 *)pNotificationData;
		printf("-- Status code = %d\n", status_code);
		if (status_code == 0) {
			if (p2papp_invoke_client_discovery_connection) {
				p2papi_log(BCMP2P_LOG_MED, TRUE,
					"p2p_app: Connect to discovered client using its DevAddr: "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					p2papp_target_client_addr.octet[0],
					p2papp_target_client_addr.octet[1],
					p2papp_target_client_addr.octet[2],
					p2papp_target_client_addr.octet[3],
					p2papp_target_client_addr.octet[4],
					p2papp_target_client_addr.octet[5]);
				BCMP2PCreateLinkToDevAddr(p2papp_dev_hdl,
					&p2papp_target_client_addr, &p2papp_target_client_channel,
					FALSE, 0, BCMP2P_CONNECT_TMO_SECS);
			}
		}
		break;


	/* Link Creation */
	case BCMP2P_NOTIF_CREATE_LINK_START:
		P2PLOG("p2papp: BCMP2P_NOTIF_CREATE_LINK_START\n");
		break;
	case BCMP2P_NOTIF_CREATE_LINK_CANCEL:
		P2PLOG("p2papp: BCMP2P_NOTIF_CREATE_LINK_CANCEL\n");
		p2papp_is_connected = FALSE;
		p2papp_redraw("........ Connection cancelled ........", "", "");
		p2papp_update_conn_complete(code);
		break;
	case BCMP2P_NOTIF_CREATE_LINK_TIMEOUT:
		P2PLOG("p2papp: BCMP2P_NOTIF_CREATE_LINK_TIMEOUT\n");
		p2papp_is_connected = FALSE;
		p2papp_redraw("........ Connection timeout ........", "", "");
		p2papp_update_conn_complete(code);
		break;
	case BCMP2P_NOTIF_CREATE_LINK_AUTH_FAIL:
		P2PLOG("p2papp: BCMP2P_NOTIF_CREATE_LINK_AUTH_FAIL\n");
		p2papp_is_connected = FALSE;
		p2papp_redraw("........ Connection auth failed ........", "", "");
		p2papp_update_conn_complete(code);
		break;
	case BCMP2P_NOTIF_CREATE_LINK_FAIL:	/* for unknown reasons */
		P2PLOG("p2papp: BCMP2P_NOTIF_CREATE_LINK_FAIL\n");
		p2papp_is_connected = FALSE;
		p2papp_msg_buf2[0] = '\0';
		p2papp_redraw("......... Connection failed .........", "", "");
		p2papp_update_conn_complete(code);
		break;
#endif /* not SOFTAP_ONLY */
	case BCMP2P_NOTIF_SOFTAP_START:
		P2PLOG("p2papp: BCMP2P_NOTIF_SOFTAP_START\n");
		p2papp_is_ap = TRUE;
		break;
	case BCMP2P_NOTIF_SOFTAP_READY:
	{
		P2PLOG("p2papp: BCMP2P_NOTIF_SOFTAP_READY\n");
		strncpy(p2papp_ssid, BCMP2PGetGOName(p2papp_dev_hdl),
			sizeof(p2papp_ssid));
		p2papp_is_softap_ready = TRUE;
		if (p2papp_is_created_grp_owner) {
			p2papp_run_conn_script();
			p2papp_redraw("........... Group Created ...........", "", "");
		}
		else if (p2papp_is_created_softap) {
			p2papp_redraw("........... SoftAP Created ...........", "", "");
		}
		break;
	}
	case BCMP2P_NOTIF_SOFTAP_STOP:
		P2PLOG("p2papp: BCMP2P_NOTIF_SOFTAP_STOP\n");
		p2papp_ssid[0] = '\0';
		p2papp_is_softap_ready = FALSE;
		p2papp_is_created_grp_owner = FALSE;
		p2papp_is_created_softap = FALSE;
		p2papp_redraw("........ SoftAP stopped ........", "", "");
		p2papp_update_conn_complete(code);
		break;
	case BCMP2P_NOTIF_SOFTAP_FAIL:
		P2PLOG("p2papp: BCMP2P_NOTIF_SOFTAP_FAIL\n");
		p2papp_ssid[0] = '\0';
		p2papp_is_softap_ready = FALSE;
		p2papp_is_created_grp_owner = FALSE;
		p2papp_is_created_softap = FALSE;
		p2papp_redraw("........ SoftAP create failed ........", "", "");
		p2papp_update_conn_complete(code);
		break;
	case BCMP2P_NOTIF_DHCP_START:
		P2PLOG("p2papp: BCMP2P_NOTIF_DHCP_START\n");
		break;
	case BCMP2P_NOTIF_DHCP_STOP:
		P2PLOG("p2papp: BCMP2P_NOTIF_DHCP_STOP\n");
		break;
	case BCMP2P_NOTIF_CREATE_LINK_COMPLETE:
	{
#ifndef SOFTAP_ONLY
		BCMP2P_PERSISTENT *persist = pNotificationData;
#endif
		P2PLOG("p2papp: BCMP2P_NOTIF_CREATE_LINK_COMPLETE\n");
		p2papp_is_connected = TRUE;
#ifndef SOFTAP_ONLY
		BCMP2PCancelDiscover(p2papp_dev_hdl);
		if (p2papp_enable_persistent) {
			p2papp_persist_save(persist);
			p2papp_redraw("........ Persistent credentials saved ........", "", "");
		}
		if (BCMP2PIsAP(p2papp_dev_hdl)) {
			p2papp_redraw("........ Connected as an AP ........", "", "");
		}
		else if (BCMP2PIsSTA(p2papp_dev_hdl)) {
			p2papp_redraw("........ Connected as a STA ........", "", "");
		}
#endif /* SOFTAP_ONLY */


		/* Run a data transfer test */
		p2papp_redraw("........ Running Connection Script ........", "", "");
		p2papp_run_conn_script();
		p2papp_redraw("........ Completed Connection Script ........", "", "");
		p2papp_update_conn_complete(code);
		break;
	}
	case BCMP2P_NOTIF_SOFTAP_STA_ASSOC:
		P2PLOG("p2papp: BCMP2P_NOTIF_SOFTAP_STA_ASSOC\n");

		printf("\nA STA has joined the soft AP.\n");
		p2papp_print_peer_names("Associated STAs: ", FALSE);
		if (p2papp_log_filename[0] != '\0') {
			p2papp_print_peer_names("Associated STAs: ", TRUE);
		}
		break;
	case BCMP2P_NOTIF_SOFTAP_STA_DISASSOC:
		P2PLOG("p2papp: BCMP2P_NOTIF_SOFTAP_STA_DISASSOC\n");
		
		printf("\nA STA has left the soft AP.\n");
		p2papp_print_peer_names("Associated STAs: ", FALSE);
		if (p2papp_log_filename[0] != '\0') {
			p2papp_print_peer_names("Associated STAs: ", TRUE);
		}
		p2papp_redraw("", "", "");
		break;

	case BCMP2P_NOTIF_LINK_LOSS:
	{
		P2PLOG("p2papp: BCMP2P_NOTIF_LINK_LOSS\n");
		p2papp_is_connected = FALSE;
		p2papp_redraw("........ Disconnected ........", "", "");
		p2papp_disconnect();
		break;
	}

#ifndef SOFTAP_ONLY
	case BCMP2P_NOTIF_SVC_REQ_RECEIVED:
	{
		BCMP2P_SERVICE_DISCOVERY_PARAM *params = pNotificationData;
		P2PLOG("BCMP2P_NOTIF_SVC_REQ_RECEIVED\n");
		sprintf(p2papp_msg_buf2,
			".....from %02x:%02x:%02x%02x:%02x:%02x",
			params->peerAddress.octet[0], params->peerAddress.octet[1],
			params->peerAddress.octet[2], params->peerAddress.octet[3],
			params->peerAddress.octet[4], params->peerAddress.octet[5]);
		sprintf(p2papp_msg_buf3,
			".....token=%d, cback=%d, length=%d, more=%d, fragment=%d",
			params->dialogToken, params->comebackDelay, params->length,
			(params->fragmentId >> 7) & 0x01, params->fragmentId & ~0x80);
		p2papp_redraw(".....Received service discovery request....",
			p2papp_msg_buf2, p2papp_msg_buf3);
		p2papp_status_str = "";
		p2papp_status_str2 = "";
		p2papp_status_str3 = "";
		break;
	}

	case BCMP2P_NOTIF_SVC_RESP_RECEIVED:
	{
		BCMP2P_SERVICE_DISCOVERY_PARAM *params = pNotificationData;
		P2PLOG("BCMP2P_NOTIF_SVC_RESP_RECEIVED\n");
		sprintf(p2papp_msg_buf2,
			".....from %02x:%02x:%02x%02x:%02x:%02x",
			params->peerAddress.octet[0], params->peerAddress.octet[1],
			params->peerAddress.octet[2], params->peerAddress.octet[3],
			params->peerAddress.octet[4], params->peerAddress.octet[5]);
		sprintf(p2papp_msg_buf3,
			".....token=%d, cback=%d, length=%d, more=%d, fragment=%d",
			params->dialogToken, params->comebackDelay, params->length,
			(params->fragmentId >> 7) & 0x01, params->fragmentId & ~0x80);
		p2papp_redraw(".....Received service discovery response....",
			p2papp_msg_buf2, p2papp_msg_buf3);
		p2papp_status_str = "";
		p2papp_status_str2 = "";
		p2papp_status_str3 = "";
		break;
	}

	case BCMP2P_NOTIF_SVC_COMEBACK_REQ_RECEIVED:
	{
		BCMP2P_SERVICE_DISCOVERY_PARAM *params = pNotificationData;
		P2PLOG("BCMP2P_NOTIF_SVC_COMEBACK_REQ_RECEIVED\n");
		sprintf(p2papp_msg_buf2,
			".....from %02x:%02x:%02x%02x:%02x:%02x",
			params->peerAddress.octet[0], params->peerAddress.octet[1],
			params->peerAddress.octet[2], params->peerAddress.octet[3],
			params->peerAddress.octet[4], params->peerAddress.octet[5]);
		sprintf(p2papp_msg_buf3,
			".....token=%d, cback=%d, length=%d, more=%d, fragment=%d",
			params->dialogToken, params->comebackDelay, params->length,
			(params->fragmentId >> 7) & 0x01, params->fragmentId & ~0x80);
		p2papp_redraw(".....Received service discovery comeback request....",
			p2papp_msg_buf2, p2papp_msg_buf3);
		p2papp_status_str = "";
		p2papp_status_str2 = "";
		p2papp_status_str3 = "";
		break;
	}

	case BCMP2P_NOTIF_SVC_COMEBACK_RESP_RECEIVED:
	{
		BCMP2P_SERVICE_DISCOVERY_PARAM *params = pNotificationData;
		P2PLOG("BCMP2P_NOTIF_SVC_COMEBACK_RESP_RECEIVED\n");
		sprintf(p2papp_msg_buf2,
			".....from %02x:%02x:%02x%02x:%02x:%02x",
			params->peerAddress.octet[0], params->peerAddress.octet[1],
			params->peerAddress.octet[2], params->peerAddress.octet[3],
			params->peerAddress.octet[4], params->peerAddress.octet[5]);
		sprintf(p2papp_msg_buf3,
			".....token=%d, cback=%d, length=%d, more=%d, fragment=%d",
			params->dialogToken, params->comebackDelay, params->length,
			(params->fragmentId >> 7) & 0x01, params->fragmentId & ~0x80);
		p2papp_redraw(".....Received service discovery comeback response....",
			p2papp_msg_buf2, p2papp_msg_buf3);
		p2papp_status_str = "";
		p2papp_status_str2 = "";
		p2papp_status_str3 = "";
		break;
	}

	case BCMP2P_NOTIF_SVC_REQ_COMPLETED:
	{
		BCMP2P_SERVICE_DISCOVERY_PARAM *params = pNotificationData;
		BCMP2P_SVC_LIST *entry_list;

		P2PLOG("BCMP2P_NOTIF_SVC_REQ_COMPLETED\n");

		if (BCMP2PGetDiscoverService(p2papp_dev_hdl, &params->peerAddress,
			&entry_list) == BCMP2P_SUCCESS) {
			p2papp_print_discovered_services(entry_list);
		}
	}
#endif /* not SOFTAP_ONLY */

	/* WPS status */
	case BCMP2P_NOTIF_WPS_START:
	case BCMP2P_NOTIF_WPS_STATUS_SCANNING:
	case BCMP2P_NOTIF_WPS_STATUS_SCANNING_OVER:
	case BCMP2P_NOTIF_WPS_STATUS_ASSOCIATING:
	case BCMP2P_NOTIF_WPS_STATUS_ASSOCIATED:
	case BCMP2P_NOTIF_WPS_STATUS_WPS_MSG_EXCHANGE:
	case BCMP2P_NOTIF_WPS_STATUS_DISCONNECTING:
	case BCMP2P_NOTIF_WPS_PROTOCOL_FAIL:
	case BCMP2P_NOTIF_WPS_FAIL: /* generic errors */
		P2PLOG1("p2papp: NOTIF_WPS status %d\n", code);
		break;
	case BCMP2P_NOTIF_WPS_WRONG_PIN:
		P2PLOG("p2papp: BCMP2P_NOTIF_WPS_WRONG_PIN\n");
		p2papp_is_connected = FALSE;
		p2papp_redraw("........ Wrong WPS PIN ........", "", "");
		p2papp_update_conn_complete(code);
		break;
	case BCMP2P_NOTIF_WPS_TIMEOUT:
		P2PLOG("p2papp: BCMP2P_NOTIF_WPS_TIMEOUT\n");
		p2papp_is_connected = FALSE;
		p2papp_redraw("........ WPS timeout ........", "", "");
		p2papp_update_conn_complete(code);
		break;
	case BCMP2P_NOTIF_WPS_SESSION_OVERLAP:
		P2PLOG("p2papp: BCMP2P_NOTIF_WPS_SESSION_OVERLAP\n");
		p2papp_is_connected = FALSE;
		p2papp_redraw("........ WPS session overlap ........", "", "");
		p2papp_update_conn_complete(code);
		break;
	case BCMP2P_NOTIF_WPS_COMPLETE:
		P2PLOG1("p2papp: NOTIF_WPS_COMPLETE\n", code);
		p2papp_redraw("........... WPS complete .........", "", "");
		break;
	default:
		P2PLOG1("p2papp_notif_cb: unknown code 0x%x\n", code);
		break;
	}
	p2papi_log(BCMP2P_LOG_INFO, TRUE, "p2papp_notif_cb: end\n");
}


void
p2papp_destroy_softap(void)
{
	BCMP2P_STATUS status;

	status = BCMP2PCancelCreateSoftAP(p2papp_dev_hdl);
	P2PLOG1("p2papp_destroy_softap: BCMP2PCancelCreateSoftAP ret %d\n", status);
	if (status != BCMP2P_SUCCESS) {
		p2papp_redraw("........ SoftAP Cancel failed! ........", "", "");
	}
	p2papp_is_created_softap = FALSE;
}

BCMP2P_STATUS
p2papp_disconnect(void)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	char *status_str = NULL;

	(void) status_str;
	P2PLOG1("p2papp_disconnect: is_connected=%d\n", p2papp_is_connected);

#ifndef SOFTAP_ONLY
	/* Turn off P2P discovery if it is on */
	if (BCMP2PIsDiscovering(p2papp_dev_hdl)) {
		status = BCMP2PCancelDiscover(p2papp_dev_hdl);
		P2PLOG1("p2papp_disconnect: BCMP2PIsDiscovering ret %d\n", status);
		if (status != BCMP2P_SUCCESS) {
			p2papp_redraw("........ Discovery Cancel failed! ........", "", "");
		}
	}
#endif /* not SOFTAP_ONLY */


	/*
	 * Tear down the connection
	 */
	if (p2papp_is_created_grp_owner) {
#ifndef SOFTAP_ONLY
		status = BCMP2PCancelCreateGroup(p2papp_dev_hdl);
		P2PLOG1("p2papp_disconnect: BCMP2PCancelCreateGroup ret %d\n", status);
		if (status != BCMP2P_SUCCESS) {
			p2papp_redraw("........ Group Cancel failed! ........", "", "");
		}
		p2papp_is_created_grp_owner = FALSE;
#endif /* SOFTAP_ONLY */
	} else if (p2papp_is_created_softap) {
		status = BCMP2PCancelCreateSoftAP(p2papp_dev_hdl);
		P2PLOG1("p2papp_disconnect: BCMP2PCancelCreateSoftAP ret %d\n", status);
		if (status != BCMP2P_SUCCESS) {
			p2papp_redraw("........ SoftAP Cancel failed! ........", "", "");
		}
		p2papp_is_created_softap = FALSE;
	}
#ifndef SOFTAP_ONLY
	status_str = p2papp_is_connected
		? "......... Tearing down connection ........."
		: "......... Cancelling link create .........";
	p2papp_redraw(status_str, "", "");
	status = BCMP2PCancelCreateLink(p2papp_dev_hdl);
	P2PLOG1("p2papp_disconnect: BCMP2PCancelCreateLink ret %d\n", status);
	if (status != BCMP2P_SUCCESS) {
		printf("p2papp: BCMP2PCancelCreateLink failed!\n");
	}
#endif /* SOFTAP_ONLY */

	/* Call a shell script to bring down the OS network interface */
	p2papp_run_disc_script();

	/* Reset connection state variables */
	p2papp_is_connected = FALSE;
	p2papp_is_ap = FALSE;
	p2papp_is_created_grp_owner = FALSE;
	p2papp_is_created_softap = FALSE;
	p2papp_is_connect_complete = FALSE;

	/* Reset discovery state variables */
	p2papp_discovery_timed_out = BCMP2P_FALSE;
#ifndef SOFTAP_ONLY
	p2papp_discovery_failed = FALSE;
#endif /* SOFTAP_ONLY */

	p2papp_redraw("", "", "");

	if (p2papp_auto_responder_mode) {
		printf("Automatically re-enabling P2P discovery.\n");
		(void) p2papp_process_cmd('e');
	}
	else if (p2papp_auto_go_mode) {
		printf("Automatically created as autonomous GO.\n");
		(void) p2papp_process_cmd('g');
	}
	P2PLOG("p2papp_disconnect: end\n");
	return status;
}

void
p2papp_deauth(void)
{
	BCMP2P_ETHER_ADDR sta_mac;
	BCMP2P_BOOL ret;

	/* Deauthenticate the first connected STA in the connected STA list */
	if (p2papp_find_first_assoc_sta(&sta_mac)) {
		ret = BCMP2PDeauth(p2papp_dev_hdl, &sta_mac);
		printf("Deauthenticate %02x:%02x:%02x:%02x:%02x:%02x %s.\n",
			sta_mac.octet[0], sta_mac.octet[1], sta_mac.octet[2],
			sta_mac.octet[3], sta_mac.octet[4], sta_mac.octet[5],
			(ret == BCMP2P_SUCCESS) ? "succeeded" : "failed");
	} else {
		printf("Cannot deauthenticate - no associated STAs.\n");
	}
}

/* Cycle the MAC addr filter to allow/deny the currently associated STAs.
 * Filter test procedure:
 * 1. Associate the STAs to be filtered.
 * 2. Call this fn to cycle the filter mode from OFF to DENY.
 *    This will also set the filter's MAC list to the MACs of the currently
 *    associated STAs.
 * 3. Diassociate the STAs.
 * 4. Try to associate from the STAs on the list - should be denied.
 *    Try to associate from other STA(s) not on the list - should be allowed.
 * 5. Call this fn to cycle the filter mode from DENY to ALLOW.
 *    This will also set the filter's MAC list to the MACs of the currently
 *    associated STAs.
 * 6. Try to associate from the STAs on the list - should be allowed.
 *    Try to associate from other STAs not on the list - should be denied.
 * 7. Call this fn to cycle the filter mode from ALLOW to OFF.
 *    This will also set the filter's MAC list to nothing.
 * 8. Try to associate from all STAs - should be allowed.
 */
void
p2papp_cycle_mac_filter(void)
{
	unsigned int i;
	BCMP2P_STATUS status;
	#define P2PAPP_MAC_LIST_MAX 2
	BCMP2P_ETHER_ADDR mac_list[P2PAPP_MAC_LIST_MAX];
	unsigned int mac_count = 0;
	BCMP2P_MAC_FILTER_MODE mode = BCMP2P_MAC_FILTER_OFF;
	char *mode_names[3] = { "off", "deny", "allow" };
	char *modestr;

	/* Get the current MAC filter mode */
	status = BCMP2PGetMACList(p2papp_dev_hdl, P2PAPP_MAC_LIST_MAX, mac_list,
		&mac_count, &mode);
	if (status != BCMP2P_SUCCESS) {
		printf("p2papp_cycle_mac_filter: BCMP2PGetMACList error %d\n", status);
		return;
	}

	/* Show the current MAC filter mode and MAC list */
	if (mode < 3)
		modestr = mode_names[mode];
	else
		modestr = "undefined";
	printf("Current MAC filter: mode=%s count=%u\n", modestr, mac_count);
	if (mac_count > 0)
		printf("    mac list:");
	for (i = 0; i < mac_count; i++) {
		printf(" %02x:%02x:%02x:%02x:%02x:%02x",
			mac_list[i].octet[0], mac_list[i].octet[1], mac_list[i].octet[2],
			mac_list[i].octet[3], mac_list[i].octet[4], mac_list[i].octet[5]);
	}
	printf("\n");

	/* Get our new MAC filter list from the currently associated STAs list */
	if (!p2papp_find_assoc_stas(P2PAPP_MAC_LIST_MAX, mac_list, &mac_count)) {
		printf("MAC filter test: no associated STAs, using empty MAC list.\n");
		mode = BCMP2P_MAC_FILTER_ALLOW;
	}

	/* Cycle the new MAC filter mode and set it */
	++mode;
	if (mode >= BCMP2P_MAC_FILTER_MAX)
		mode = BCMP2P_MAC_FILTER_OFF;
	status = BCMP2PSetMACListMode(p2papp_dev_hdl, mode);
	if (status != BCMP2P_SUCCESS) {
		printf("p2papp_cycle_mac_filter: BCMP2PSetMACListMode error %d\n",
			status);
		return;
	}
	modestr = mode_names[mode];

	printf("New MAC filter: mode=%s count=%u\n", modestr, mac_count);
	printf("    mac list:");
	for (i = 0; i < mac_count; i++) {
		printf(" %02x:%02x:%02x:%02x:%02x:%02x",
			mac_list[i].octet[0], mac_list[i].octet[1], mac_list[i].octet[2],
			mac_list[i].octet[3], mac_list[i].octet[4], mac_list[i].octet[5]);
	}
	printf("\n");

	/* Set the new MAC filter list */
	status = BCMP2PSetMACList(p2papp_dev_hdl, mac_list, mac_count);
	if (status != BCMP2P_SUCCESS) {
		printf("p2papp_cycle_mac_filter: BCMP2PSetMACList error %d\n",
			status);
		return;
	}
}

/* update config with product info */
int p2papp_update_product_info(BCMP2P_CONFIG *config)
{
	struct ether_addr our_mac;

	if (!config)
	{
		return -1;
	}

	/* manufacturer name passed in command line args to p2p_app_main */
	if (strlen(p2papp_manufacturer) > 0)
	{
		memcpy(config->prodInfo.manufacturer, p2papp_manufacturer,
		       sizeof(config->prodInfo.manufacturer));
	}

	/* model name passed in command line args to p2p_app_main */
	if (strlen(p2papp_modelName) > 0)
	{
		memcpy(config->prodInfo.modelName, p2papp_modelName,
		       sizeof(config->prodInfo.modelName));
	}

	/* model number passed in command line args to p2p_app_main */
	if (strlen(p2papp_modelNumber) > 0)
	{
		memcpy(config->prodInfo.modelNumber, p2papp_modelNumber,
		       sizeof(config->prodInfo.modelNumber));
	}

	/* serial number is our device mac addr, as text, can be over-ridden by cmd line arg */
	if (strlen(p2papp_serialNumber) > 0)
	{
		memcpy(config->prodInfo.serialNumber, p2papp_serialNumber,
		       sizeof(config->prodInfo.serialNumber));
	}
	else
	{
		if (p2papi_get_mac_addr(p2papp_dev_hdl, &our_mac) == 0)
		{
			sprintf(config->prodInfo.serialNumber, "%02x%02x%02x%02x%02x%02x",
				our_mac.octet[0], our_mac.octet[1], our_mac.octet[2],
				our_mac.octet[3], our_mac.octet[4], our_mac.octet[5]);
		}
	}

	/* OS version */
	if (p2papp_osVersion != 0)
	{
		config->prodInfo.osVersion = p2papp_osVersion;
	}

	return 0;
}

BCMP2P_CONFIG*
p2papp_get_link_config(void)
{
	BCMP2P_CONFIG* link_config = NULL;

	if (strcmp(p2papp_security_type, "open") == 0)
		link_config = &p2papp_open_link_config;
	else if (strcmp(p2papp_security_type, "wpa2") == 0)
		link_config = &p2papp_wpa2_aes_link_config;
	else if (strcmp(p2papp_security_type, "wpa2tkip") == 0)
		link_config = &p2papp_wpa2_tkip_link_config;
	else if (strcmp(p2papp_security_type, "wpawpa2") == 0)
		link_config = &p2papp_wpa_wpa2_link_config;
	else if (strcmp(p2papp_security_type, "wpa") == 0)
		link_config = &p2papp_wpa_tkip_link_config;
	else if (strcmp(p2papp_security_type, "wpaaes") == 0)
		link_config = &p2papp_wpa_aes_link_config;
	else if (strcmp(p2papp_security_type, "wep") == 0)
		link_config = &p2papp_wep_link_config;
	else if (strcmp(p2papp_security_type, "wep.10") == 0)
		link_config = &p2papp_wep10_link_config;
	else if (strcmp(p2papp_security_type, "wep.11") == 0)
		link_config = &p2papp_wep11_link_config;
	else if (strcmp(p2papp_security_type, "wep.13") == 0)
		link_config = &p2papp_wep13_link_config;
	else if (strcmp(p2papp_security_type, "wep.20") == 0)
		link_config = &p2papp_wep20_link_config;
	else if (strcmp(p2papp_security_type, "wep.21") == 0)
		link_config = &p2papp_wep21_link_config;
	else if (strcmp(p2papp_security_type, "wep.22") == 0)
		link_config = &p2papp_wep22_link_config;
	else if (strcmp(p2papp_security_type, "wep.40") == 0)
		link_config = &p2papp_wep40_link_config;
	else if (strcmp(p2papp_security_type, "wep.41") == 0)
		link_config = &p2papp_wep41_link_config;
	else if (strcmp(p2papp_security_type, "wep.42") == 0)
		link_config = &p2papp_wep42_link_config;
	else if (strcmp(p2papp_security_type, "wep.43") == 0)
		link_config = &p2papp_wep43_link_config;
	else if (strcmp(p2papp_security_type, "hideopen") == 0)
		link_config = &p2papp_hidden_open_link_config;
	else if (strcmp(p2papp_security_type, "hidewpa2") == 0)
		link_config = &p2papp_hidden_wpa2_aes_link_config;
	else {
		printf("Invalid security type: %s\n", p2papp_security_type);
		return NULL;
	}

	if (link_config) {
		BCMP2P_INIT_BCMP2P_CONFIG(&p2papp_bss_config);
		p2papp_bss_config.operatingChannel = link_config->operatingChannel;
		p2papp_bss_config.encryption = link_config->encryption;
		p2papp_bss_config.authentication = link_config->authentication;
		memcpy(p2papp_bss_config.keyWPA, link_config->keyWPA,
			sizeof(p2papp_bss_config.keyWPA));
		memcpy(p2papp_bss_config.WEPKey, link_config->WEPKey,
			sizeof(p2papp_bss_config.WEPKey));
		p2papp_bss_config.WEPKeyIndex = link_config->WEPKeyIndex;
		memcpy(&p2papp_bss_config.DHCPConfig, &link_config->DHCPConfig,
			sizeof(p2papp_bss_config.DHCPConfig));
		memcpy(&p2papp_bss_config.WPSConfig, &link_config->WPSConfig,
			sizeof(p2papp_bss_config.WPSConfig));
		p2papp_bss_config.ip_addr = link_config->ip_addr;
		p2papp_bss_config.netmask = link_config->netmask;
		p2papp_bss_config.allow11b = link_config->allow11b;
		p2papp_bss_config.enableWMM = link_config->enableWMM;
		p2papp_bss_config.enableWMM_PS = link_config->enableWMM_PS;
		p2papp_bss_config.maxClients = link_config->maxClients;
		p2papp_bss_config.hideSSID = link_config->hideSSID;
	}

	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"p2papp_get_link_config: p2papp_go_intent=%u override=%u\n",
		p2papp_go_intent, p2papp_override_go_intent);
	if (p2papp_override_go_intent) {
		p2papp_bss_config.grp_owner_intent = p2papp_go_intent;
	}

	memcpy(&p2papp_bss_config.operatingChannel, &p2papp_operating_channel,
		sizeof(p2papp_bss_config.operatingChannel));
#ifdef BCM_P2P_OPTEXT
    p2papp_bss_config.opch_force = p2papp_opch_force;
    p2papp_bss_config.opch_high = p2papp_opch_high;
#endif
#ifndef SOFTAP_ONLY
	p2papp_bss_config.sameIntDevAddrs = p2papp_same_int_dev_addr;
	p2papp_bss_config.wantPersistentGroup = p2papp_enable_persistent;
	p2papp_bss_config.enableManagedDevice = p2papp_enable_managed;
#endif /* not SOFTAP_ONLY */

	p2papp_bss_config.primaryDevType = p2papp_pri_devtype;
	p2papp_bss_config.primaryDevSubCat = p2papp_pri_subcat;

	/* generate random passphrase if not user specified */
	if (!p2papp_override_passphrase) {
		BCMP2PRandomPassphrase(p2papp_dev_hdl,
			BCMP2P_PASSPHRASE_MIN_LENGTH, &p2papp_passphrase);
	}
	strncpy((char *)p2papp_bss_config.keyWPA, p2papp_passphrase,
		sizeof(p2papp_bss_config.keyWPA));
	printf("--> Passphrase        : %s\n", p2papp_passphrase);

	if (p2papp_override_wps_config_methods) {
		p2papp_bss_config.WPSConfig.wpsConfigMethods =
			p2papp_wps_config_methods;
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"p2papp_get_link_config: wpsConfigMethods=0x%x\n",
			p2papp_bss_config.WPSConfig.wpsConfigMethods);
	}

	/* generate random WPS pin if not user specified */
	if (!p2papp_override_wps_pin) {
		BCMP2PRandomWPSPin(p2papp_dev_hdl, &p2papp_wps_pin);
	}
	strncpy(p2papp_bss_config.WPSConfig.wpsPin,
		p2papp_wps_pin, sizeof(p2papp_bss_config.WPSConfig.wpsPin));
	p2papp_bss_config.WPSConfig.wpsPinMode = TRUE;
	printf("--> PIN               : %s\n", p2papp_wps_pin);

	if (p2papp_disable_wps) {
		P2PLOG("p2papp_get_link_config: disabling WPS\n");
		p2papp_bss_config.WPSConfig.wpsEnable = FALSE;
	}

	/* update config with product info */
	p2papp_update_product_info(&p2papp_bss_config);

	return &p2papp_bss_config;
}

void
p2papp_run_script(char *script_name, char *apsta, char *ifname, BCMP2P_BOOL enable_ping, int rtsp_port)
{
	char cmd[80];

	/* Pass in WFDisp rtsp source port number $4 and local device type $5 to the script */
	snprintf(cmd, sizeof(cmd), "%s %s %s %d %d %d\n",
		script_name, apsta, ifname, enable_ping,
		rtsp_port, wfd_dev_config.dev_type);

	p2papi_log(BCMP2P_LOG_MED, TRUE, "Running: %s\n", cmd);
	printf("\n====== Calling app script: %s\n\n", cmd);
	p2papp_system(cmd);
	printf("====== Returned from app script: %s\n", cmd);
	p2papi_log(BCMP2P_LOG_MED, TRUE, "Returned from: %s\n", cmd);
}

void
p2papp_run_conn_script(void)
{
	char *apsta;
	char *ifname;
	int rtsp_port = 0;
	
#ifdef P2P_USE_UCLIBC
	char *script = "./p2papp_connected_uclibc.sh";
#else
	char *script = "./p2papp_connected.sh";
#endif   /* P2P_USE_UCLIBC */

	/* Call an application shell script to set the OS network interface's IP
	 * address and run data transfer tests.
	 */
	ifname = BCMP2PGetNetifName(p2papp_dev_hdl);
#ifdef SOFTAP_ONLY
	p2papp_is_ap = FALSE;
#else
	p2papp_is_ap = BCMP2PIsAP(p2papp_dev_hdl);
#endif /* SOFTAP_ONLY */
	if (p2papp_is_created_grp_owner) {
		apsta = "standalone_go";
	} else if (p2papp_auto_responder_mode || p2papp_auto_softap_mode || p2papp_auto_go_mode) {
		apsta = p2papp_is_ap ? "auto_ap" : "auto_sta";
	} else {
		apsta = p2papp_is_ap ? "ap" : "sta";
	}
	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"p2papp_run_conn_script: apsta=%s ifname=%s\n", apsta, ifname);

	/* Get peer rtsp port and pass it to shell script as $4 */
	if (p2papp_enable_wfdisp)
		rtsp_port = p2papp_wfd_get_rtsp_port();

	p2papp_run_script(script, apsta, ifname, p2papp_enable_ping, rtsp_port);	
}

void
p2papp_run_disc_script(void)
{
	char *apsta;
	char *ifname;
#ifdef P2P_USE_UCLIBC
	char *script = "./p2papp_disconnected_uclibc.sh";
#else
	char *script = "./p2papp_disconnected.sh";
#endif   /* P2P_USE_UCLIBC */

	/* Call an application shell script to set the OS network interface's IP
	 * address and run data transfer tests.
	 */
	ifname = BCMP2PGetNetifName(p2papp_dev_hdl);
#ifdef SOFTAP_ONLY
	p2papp_is_ap = FALSE;
#else
	p2papp_is_ap = BCMP2PIsAP(p2papp_dev_hdl);
#endif /* SOFTAP_ONLY */
	apsta = p2papp_is_ap ? "ap" : "sta";
	P2PLOG2("p2papp_run_disc_script: ifname=%s apsta=%s\n", ifname, apsta);

	p2papp_run_script(script, apsta, ifname, 0, 0);
}


/* Process the result of a connection attempt */
BCMP2P_STATUS
p2papp_process_conn_result(BCMP2P_STATUS status)
{
	char *status_str = NULL;

	if (p2papp_is_created_softap) {
		p2papp_redraw("........... SoftAP Created ...........", p2papp_ssid,
			"");
		P2PLOG("p2papp_process_conn_result: is created SoftAP\n");
		return BCMP2P_SUCCESS;
	}

	P2PLOG1("p2papp_process_conn_result: begin, status=%d\n", status);

#ifndef SOFTAP_ONLY
	/* If connected and we are not a GO, turn off P2P discovery */
	if (status == BCMP2P_SUCCESS && !p2papp_is_created_grp_owner) {
		P2PLOG("p2papp: turning off discovery\n");
		if (BCMP2PCancelDiscover(p2papp_dev_hdl) != BCMP2P_SUCCESS) {
			printf("Discovery cancel failed!\n");
		}
	}
#endif /* SOFTAP_ONLY */

	if (status == BCMP2P_GO_NEGOTIATE_TIMEOUT) {
		status_str = "........ Link Create timed out! ........";
	} else if (status == BCMP2P_CONNECT_REJECTED) {
		status_str = "........ Link Create rejected ........";
	} else if (status == BCMP2P_BAD_WPS_PIN) {
		status_str = "........ Wrong WPS PIN ........";
	} else if (status == BCMP2P_GON_FAILED_INFO_UNAVAIL) {
		status_str = "........ Peer has no Provisioning Info ........";
	} else if (status != BCMP2P_SUCCESS && !p2papp_discovery_timed_out) {
		status_str = "........ Link Create failed! ........";
	} else if (status == BCMP2P_SUCCESS) {
#ifndef SOFTAP_ONLY
		if (BCMP2PIsAP(p2papp_dev_hdl)) {
			status_str = "........ Connected as an AP ........";
			p2papi_wl_assoclist(p2papp_dev_hdl);
		}
		else if (BCMP2PIsSTA(p2papp_dev_hdl)) {
			status_str = "........ Connected as a STA ........";
			p2papi_wl_status(p2papp_dev_hdl, BCMP2P_LOG_MED);
		} else
#endif /* SOFTAP_ONLY */
		{
			status_str = ".........Not Connected........";
			p2papi_wl_status(p2papp_dev_hdl, BCMP2P_LOG_MED);
			p2papi_wl_assoclist(p2papp_dev_hdl);
		}
	} else {
		status_str = "........ Not Connected ........";
		p2papi_wl_status(p2papp_dev_hdl, BCMP2P_LOG_MED);
		p2papi_wl_assoclist(p2papp_dev_hdl);
	}
	p2papp_redraw(status_str, "", "");

	P2PLOG("p2papp_process_conn_result: end\n");
	return status;
}

static BCMP2P_STATUS p2papp_update_conn_complete(BCMP2P_NOTIFICATION_CODE notification)
{
	BCMP2P_STATUS status = BCMP2P_ERROR;

	switch (notification) {
	case BCMP2P_NOTIF_CREATE_LINK_COMPLETE:
		status = BCMP2P_SUCCESS;
			break;
			case BCMP2P_NOTIF_CREATE_LINK_CANCEL:
				status = BCMP2P_CONNECT_CANCELLED;
				break;
			case BCMP2P_NOTIF_CREATE_LINK_TIMEOUT:
				/* Use BCMP2P_GO_NEGOTIATE_TIMEOUT to mean a generic
				 * connection timeout
				 */
				status = BCMP2P_GO_NEGOTIATE_TIMEOUT;
				break;
			case BCMP2P_NOTIF_WPS_WRONG_PIN:
				status = BCMP2P_BAD_WPS_PIN;
				break;
			case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL_INTENT:
				status = BCMP2P_BOTH_GROUP_OWNER_INTENT;
				break;
			case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL:
				status = BCMP2P_GON_FAILED_INFO_UNAVAIL;
				break;
			default:
				status = BCMP2P_ERROR;
				break;
			}

	/* latch first status */
	if (!p2papp_is_connect_complete) {
		p2papp_connect_status = status;
		p2papp_is_connect_complete = TRUE;
		P2PLOG2("p2papp_update_conn_complete: notification=0x%x status=%d\n",
			notification, p2papp_connect_status);
	}

	P2PLOG("p2papp_update_conn_complete: end\n");
	return status;
}

#ifndef SOFTAP_ONLY

/* Wait for a notification callback indicating discovery
 * has been disabled
 */
BCMP2P_STATUS
p2papp_wait_for_discover_disable(int timeout_msec)
{
	BCMP2P_STATUS status = BCMP2P_ERROR;
	int msec;

	for (msec = 0; msec < timeout_msec; msec += 100) {

		/* Process events. */
		bcmp2p_event_process(BCMP2P_TRUE);

		if (p2papp_is_discover_disabled) {
			status = BCMP2P_SUCCESS;
			break;
		}

		/* Sleep 100 msec */
		OSL_DELAY(100 * 1000);
	}

	return (status);
}

/* Wait for a notification callback indicating the P2P connection has
 * completed or failed.
 */
BCMP2P_STATUS
p2papp_wait_for_connect_complete(int timeout_msec)
{
	BCMP2P_STATUS status = BCMP2P_ERROR;
	int msec;

	for (msec = 0; msec < timeout_msec; msec += 100) {

		/* Process events. */
		bcmp2p_event_process(BCMP2P_TRUE);

		if (p2papp_is_connect_complete) {
			status = p2papp_connect_status;
			break;
		}

		/* Sleep 100 msec */
		OSL_DELAY(100 * 1000);
	}

	return (status);
}

/* Wait for a notification callback indicating the P2P group create has
 * completed or failed.
 */
BCMP2P_STATUS
p2papp_wait_for_group_create_complete(int timeout_msec)
{
	BCMP2P_STATUS status = BCMP2P_ERROR;
	int	msec;

	for (msec = 0; msec < timeout_msec; msec += 100) {

		/* Process events. */
		bcmp2p_event_process(BCMP2P_TRUE);

		if (p2papp_is_softap_ready) {
			status = BCMP2P_SUCCESS;
			break;
		}

		/* Sleep 100 msec */
		OSL_DELAY(100 * 1000);
	}

	return (status);
}

#endif /* SOFTAP_ONLY */

#ifndef SOFTAP_ONLY

#define MAC_ADDR_STR_LEN	17	/* "aa:bb:cc:dd:ee:ff" */

/*
 * Convert ascii text version of a MAC address, e.g. "11:22:33:44:55:66", to
 * to a numerical array of 6 bytes.
 */
static BCMP2P_STATUS
p2papp_hex_char_to_num(char hex, unsigned int *num)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	if ((hex >= '0') && (hex <= '9')) {
		*num = (hex - '0');
	}
	else if ((hex >= 'a') && (hex <= 'f')) {
		*num = (hex - 'a' + 10);
	}
	else if ((hex >= 'A') && (hex <= 'F')) {
		*num = (hex - 'A' + 10);
	}
	else {
	     status = BCMP2P_INVALID_PARAMS;
	}

	return (status);
}

BCMP2P_STATUS
p2papp_macaddr_aton(const char *mac_addr_str, BCMP2P_UINT8 *mac_addr)
{
	unsigned int	i;
	unsigned int 	num1, num2;

	if (strlen(mac_addr_str) != MAC_ADDR_STR_LEN) {
		return (BCMP2P_INVALID_PARAMS);
	}

	for (i = 0; i < 6; i++) {
		if (p2papp_hex_char_to_num(*mac_addr_str++, &num1) != BCMP2P_SUCCESS) {
			return (BCMP2P_INVALID_PARAMS);
		}

		if (p2papp_hex_char_to_num(*mac_addr_str++, &num2) != BCMP2P_SUCCESS) {
			return (BCMP2P_INVALID_PARAMS);
		}

		*mac_addr++ = (num1 * 16) + num2;

		if ((i < 5) && (*mac_addr_str++ != ':')) {
			return (BCMP2P_INVALID_PARAMS);
		}
	}

	return (BCMP2P_SUCCESS);
}


/*
 * Send a service discovery request message to the specified peer.
 */
BCMP2P_STATUS
p2papp_send_service_discovery_from_name(const char *name)
{
	unsigned int	peer_idx;

	if (BCMP2P_SUCCESS == p2papp_get_peer_idx_from_name(name, &peer_idx)) {
		printf("Send Service Discovery to peer client %d\n", peer_idx);
		return (p2papp_send_service_discovery(peer_idx));
	}

	return (BCMP2P_INVALID_PARAMS);
}

static BCMP2P_STATUS p2papp_send_service_discovery(unsigned int peer_index)
{
	BCMP2P_STATUS		status = BCMP2P_SUCCESS;
	unsigned int 		sd_params_len;
	BCMP2P_SVC_LIST 	*svc_list;
	BCMP2P_SVC_ENTRY 	*svc_entry;


#define SD_WILDCARD_QUERY	1
#if SD_WILDCARD_QUERY
	/* Create service discovery parameters to send to peer. */
	sd_params_len = sizeof(BCMP2P_SVC_LIST) - 1 + sizeof(BCMP2P_SVC_ENTRY) - 1;
	svc_list = (BCMP2P_SVC_LIST *) P2PAPI_MALLOC(sd_params_len);

	svc_list->status = BCMP2P_SD_STATUS_SUCCESS;
	svc_list->svcNum = 1;
	svc_list->dataSize = sizeof(BCMP2P_SVC_ENTRY) - 1;

	svc_entry = (BCMP2P_SVC_ENTRY *) svc_list->svcEntries;
	svc_entry->svcProtol = BCMP2P_SVC_PROTYPE_ALL;
	svc_entry->tsc_id = 0;
	svc_entry->status = BCMP2P_SD_STATUS_SUCCESS;
	svc_entry->dataSize = 0;
#endif   /* SD_WILDCARD_QUERY */


#if SD_BONJOUR_QUERY
	const BCMP2P_UINT8 bonjour_query[] = {
		0x0b, 0x5f, 0x61, 0x66, 0x70, 0x6f, 0x76, 0x65,
		0x72, 0x74, 0x63, 0x70, 0xc0, 0x0c, 0x00, 0x0c,
		0x01};
	BCMP2P_UINT32 bonjour_query_size = sizeof(bonjour_query);

	/* Create service discovery parameters to send to peer. */
	sd_params_len = sizeof(BCMP2P_SVC_LIST) - 1 + sizeof(BCMP2P_SVC_ENTRY)
	                - 1 + bonjour_query_size;
	svc_list = (BCMP2P_SVC_LIST *) P2PAPI_MALLOC(sd_params_len);

	svc_list->status = BCMP2P_SD_STATUS_SUCCESS;
	svc_list->svcNum = 1;
	svc_list->dataSize = sizeof(BCMP2P_SVC_ENTRY) - 1 + bonjour_query_size;

	svc_entry = (BCMP2P_SVC_ENTRY *) svc_list->svcEntries;
	svc_entry->svcProtol = BCMP2P_SVC_PROTYPE_BONJOUR;
	svc_entry->tsc_id = 0;
	svc_entry->status = BCMP2P_SD_STATUS_SUCCESS;
	svc_entry->dataSize = bonjour_query_size;
	memcpy(svc_entry->svcData, bonjour_query, bonjour_query_size);
#endif   /* SD_BONJOUR_QUERY */
#if SD_UPNP_QUERY
		const BCMP2P_UINT8* upnp_query = (BCMP2P_UINT8*)"0x10 ssdp:all";
		BCMP2P_UINT32 upnp_query_size = strlen((char*)upnp_query);

		/* Create service discovery parameters to send to peer. */
		sd_params_len = sizeof(BCMP2P_SVC_LIST) - 1 + sizeof(BCMP2P_SVC_ENTRY)
						- 1 + upnp_query_size;
		svc_list = (BCMP2P_SVC_LIST *) P2PAPI_MALLOC(sd_params_len);
		svc_list->status = BCMP2P_SD_STATUS_SUCCESS;
		svc_list->svcNum = 1;
		svc_list->dataSize = sizeof(BCMP2P_SVC_ENTRY) - 1 + upnp_query_size;

		svc_entry = (BCMP2P_SVC_ENTRY *) svc_list->svcEntries;
		svc_entry->svcProtol = BCMP2P_SVC_PROTYPE_UPNP;
		svc_entry->tsc_id = 0;
		svc_entry->status = BCMP2P_SD_STATUS_SUCCESS;
		svc_entry->dataSize = upnp_query_size;
		memcpy(svc_entry->svcData, upnp_query, upnp_query_size);
		p2papi_log(BCMP2P_LOG_MED, TRUE, "%s: query=%x %x query len=%d\n",
		__FUNCTION__, *(unsigned int*)upnp_query,
		*((unsigned int*)upnp_query+1), upnp_query_size);

#endif   /* SD_UPNP_QUERY */

	p2papi_log(BCMP2P_LOG_MED, TRUE, "%s: peer_index=%d p2papp_peer_count=%d\n",
		__FUNCTION__, peer_index, p2papp_peer_count);

	/* If no peer was found, exit now */
	if (p2papp_peer_count == 0) {
		p2papp_redraw("........ No peers found ........", "", "");
		status = BCMP2P_PEER_NOT_FOUND;
		goto exit;
	}

	/* If no peer was selected, exit now */
	if (peer_index < 0) {
		p2papp_redraw("........ No peer selected ........", "", "");
		status = BCMP2P_PEER_NOT_FOUND;
		goto exit;
	}
	/* If an invalid peer was selected, exit now */
	if (peer_index > p2papp_peer_count) {
		p2papp_redraw("........ Invalid peer selected ........", "", "");
		status = BCMP2P_PEER_NOT_FOUND;
		goto exit;
	}

	/* Print the selected peer */
	p2papi_log(BCMP2P_LOG_MED, TRUE, "%s: Selected peer %u of %u\n",
		__FUNCTION__, peer_index + 1, p2papp_peer_count);


	/* Send service discovery request. */
	status = BCMP2PDiscoverService(p2papp_dev_hdl,
		&p2papp_peers_list[peer_index], svc_list);

exit:
	P2PAPI_FREE(svc_list);
	return (BCMP2P_SUCCESS);
}

/*
 * Create a P2P link with a named peer. The name can be either a MAC address,
 * e.g. "11:22:33:44:55:66", or the device name.
 */
BCMP2P_STATUS
p2papp_get_peer_idx_from_name(const char *name, unsigned int *idx)
{
	BCMP2P_BOOL		found = FALSE;
	unsigned int		peer_idx;
	BCMP2P_DISCOVER_ENTRY	*peer;
	BCMP2P_UINT8		mac_addr[6];
	BCMP2P_BOOL		is_valid_mac_addr = FALSE;


	if (p2papp_macaddr_aton(name, mac_addr) == BCMP2P_SUCCESS) {
		is_valid_mac_addr = TRUE;
	}


	for (peer_idx = 0; peer_idx < p2papp_peer_count; peer_idx++) {
		peer = &p2papp_peers_list[peer_idx];

		if (!is_valid_mac_addr) {
			if (strcmp(name, (char *)peer->ssid) == 0) {
				found = TRUE;
				break;
			}
		}

		if ((is_valid_mac_addr) &&
		    (memcmp(mac_addr, peer->mac_address, sizeof(mac_addr)) == 0)) {
			found = TRUE;
			break;
		}
	}

	if (found) {
		*idx = peer_idx;
		return (BCMP2P_SUCCESS);
	}


	return (BCMP2P_ERROR);
}

BCMP2P_STATUS
p2papp_send_provision_discovery(const char *name, BCMP2P_WPS_CONFIG_METHODS config_method)
{
	unsigned int	peer_idx;

	if (BCMP2P_SUCCESS == p2papp_get_peer_idx_from_name(name, &peer_idx)) {
		printf("Send Provision Discovery to peer client %d config=%x\n",
			peer_idx, config_method);

	
		return (BCMP2PSendProvisionDiscoveryRequest(p2papp_dev_hdl, config_method,
			p2papp_peers_list[peer_idx].is_p2p_group,
			p2papp_peers_list[peer_idx].grp_ssid,
			p2papp_peers_list[peer_idx].grp_ssidLength,
			&p2papp_peers_list[peer_idx].channel,
			(BCMP2P_ETHER_ADDR *)p2papp_peers_list[peer_idx].mac_address));
	}

	return (BCMP2P_INVALID_PARAMS);
}


BCMP2P_STATUS
p2papp_connect(const char *device_id)
{
	BCMP2P_UINT8		mac_addr[6];
	BCMP2P_STATUS		status;
	BCMP2P_PERSISTENT	persist;

	if (p2papp_macaddr_aton(device_id, mac_addr) != BCMP2P_SUCCESS) {
		return (BCMP2P_ERROR);
	}

	p2papp_is_connect_complete = FALSE;

	
	status = BCMP2PConnect(p2papp_dev_hdl, (BCMP2P_ETHER_ADDR *)mac_addr,
		p2papp_enable_persistent ?
		p2papp_persist_find_addr((BCMP2P_ETHER_ADDR *)mac_addr, &persist) :
		0);

	return (status);
}
#endif /* not SOFTAP_ONLY */

char *p2papp_get_pin(void)
{
	return p2papp_wps_pin;
}

#ifndef SOFTAP_ONLY
BCMP2P_STATUS
p2papp_create_group(char *ssid)
{
	BCMP2P_STATUS status;
	const char *persist_go_ssid;

	p2papp_is_gon_waiting = FALSE;
	if (ssid == NULL) {
		ssid = p2papp_friendly_name;
	}

	/* if we have a saved Group SSID, use that! */
	persist_go_ssid = ssid;
	if (p2papp_enable_persistent)
	{
		persist_go_ssid = p2papp_persist_get_go_ssid();
	}
	if(persist_go_ssid == NULL)
		persist_go_ssid = ssid;


	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_create_group: ssid=%s\n", ssid);
	status = BCMP2PSetFname(p2papp_dev_hdl, ssid);

	/* create the "DIRECT-" version if this is our first time :) */
	if (strncmp(persist_go_ssid, "DIRECT-", 7) != 0)
	{
		/* we've already set the friendly name, prepend "DIRECT-xy" */
		BCMP2PGenerateGoSsid(p2papp_dev_hdl);
	}

	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_create_group:Create Group: %s\n", persist_go_ssid);
	status = BCMP2PCreateGroup(p2papp_dev_hdl, (unsigned char*)persist_go_ssid, TRUE);	
	
	if (status == BCMP2P_SUCCESS)
	{
		p2papp_is_created_grp_owner = TRUE;
		/* if persist is on, save Group ID SSID name */
		if (p2papp_enable_persistent)
		{
			if (strncmp(p2papi_get_go_name(p2papp_dev_hdl), "DIRECT-", 7) == 0)
			{
				p2papp_persist_save_go_ssid(p2papi_get_go_name(p2papp_dev_hdl));
			}
		}
	}		
	else
	{
	
		p2papp_redraw("........ Group Create failed ........", "", "");
	}
	return status;
}
#endif /* SOFTAP_ONLY */

BCMP2P_STATUS
p2papp_create_softap(void)
{
	BCMP2P_STATUS status;

	p2papp_set_link_config(TRUE);

	status = BCMP2PCreateSoftAP(p2papp_dev_hdl,
		(unsigned char*)p2papp_friendly_name);
	if (status == BCMP2P_SUCCESS)
		p2papp_is_created_softap = TRUE;
	else
		p2papp_redraw("........ SoftAP Create failed ........", "", "");

	return status;
}

void
p2papp_set_link_config(BCMP2P_BOOL softap_only)
{
	BCMP2P_CONFIG *link_config;
	char *ssid;

	link_config = p2papp_get_link_config();
	if (link_config == NULL) {
		P2PLOG("p2papp_set_link_config: unable to get link config!\n");
		return;
	}
	link_config->disableP2P = softap_only;

	if (p2papp_ssid[0] == '\0')
		ssid = p2papp_friendly_name;
	else
		ssid = p2papp_ssid;

	BCMP2PSetLinkConfig(p2papp_dev_hdl, link_config, ssid);
}


#ifndef SOFTAP_ONLY
BCMP2P_STATUS
p2papp_enable_discovery(BCMP2P_BOOL is_listen_only, int timeout_secs)
{
	BCMP2P_STATUS status;

	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"p2papp_enable_discovery: listen_only=%d tmo=%d\n",
		is_listen_only, timeout_secs);

	/* Reset discovery state variables */
	if (!is_listen_only)
		p2papp_peer_count = 0;
	p2papp_discovery_timed_out = BCMP2P_FALSE;
	p2papp_discovery_failed = FALSE;

	/* Start discovery */
	memset(&p2papp_discovery_params, 0, sizeof(p2papp_discovery_params));
	p2papp_discovery_params.social_timeout =
		(timeout_secs == 0) ? P2PAPP_DISCOVER_TMO_SECS : timeout_secs;
	p2papp_discovery_params.scan_interval = 0;
	memcpy(p2papp_discovery_params.ssid, p2papp_friendly_name,
		sizeof(p2papp_discovery_params.ssid));
	p2papp_discovery_params.ssidLength = strlen(p2papp_friendly_name);
	p2papp_discovery_params.socialChannel = p2papp_listen_channel;
	p2papp_discovery_params.reqDevType = p2papp_discov_filt_devtype;
	p2papp_discovery_params.reqDevSubCat = p2papp_discov_filt_subcat;
	p2papp_discovery_params.isListenOnly = is_listen_only;
	p2papp_discovery_params.keepPrevPeersList = BCMP2P_FALSE;
	p2papp_discovery_iteration = 0;
	p2papp_is_listen_only = is_listen_only;

#if P2P_UPNP_DISCOVERY
	status = p2papp_sd_upnp_CreateListOfQueries(&p2papp_discovery_params.svcQueryEntries,
		&p2papp_discovery_params.svcQueryListSize);
	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_enable_discovery: "
		"p2papp_discovery_params.svcQueryEntries 0x%x "
		"p2papp_discovery_params.svcQueryListSize %d!\n",
		p2papp_discovery_params.svcQueryEntries, p2papp_discovery_params.svcQueryListSize);
#endif   /* P2P_UPNP_DISCOVERY */

	/* If we are already a Group Owner, skip the initial 802.11 scan to speed
	 * up discovery.  A GO cannot send an invite to GO so there is no point
	 * to doing this 802.11 scan to find existing GOs.
	 */
	p2papp_discovery_params.skipGroupScan = (p2papp_is_created_grp_owner ||
		p2papp_is_ap);


	status = BCMP2PDiscover(p2papp_dev_hdl, &p2papp_discovery_params);
	if (status != BCMP2P_SUCCESS) {
		p2papp_redraw("........Discovery start failed!", "", "");
	}

	return status;
}

BCMP2P_STATUS
p2papp_iterate_discovery(void)
{
	BCMP2P_STATUS status;

	++p2papp_discovery_iteration;
	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"p2papp_iterate_discovery: iteration %d\n", p2papp_discovery_iteration);

	/* Restart Discovery, keeping the previous discovery results */
	p2papp_discovery_params.keepPrevPeersList = BCMP2P_TRUE;
	status = BCMP2PDiscover(p2papp_dev_hdl, &p2papp_discovery_params);
	if (status != BCMP2P_SUCCESS) {
		p2papp_redraw("........Discovery iteration failed!", "", "");
	}

	/* Retrieve and redraw the previous discovery results */
	p2papp_get_discovery_results();

	return status;
}

BCMP2P_STATUS
p2papp_disable_discovery(void)
{
	BCMP2P_STATUS status;

	/* Disable discovery */
	status = BCMP2PCancelDiscover(p2papp_dev_hdl);
	if (status != BCMP2P_SUCCESS) {
		p2papp_redraw("........Discovery cancel failed!", "", "");
	}
	/* Reset discovery state variables */
	p2papp_discovery_timed_out = FALSE;
	p2papp_discovery_failed = FALSE;

	return status;
}

BCMP2P_STATUS
p2papp_suspend_discovery(void)
{
	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_suspend_discovery\n");
	return BCMP2PSuspendDiscovery(p2papp_dev_hdl);
}

BCMP2P_STATUS
p2papp_resume_discovery(void)
{
	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_resume_discovery\n");
	return BCMP2PResumeDiscovery(p2papp_dev_hdl);
}

#endif /* SOFTAP_ONLY */


#ifndef SOFTAP_ONLY

BCMP2P_STATUS
p2papp_get_group_id(BCMP2P_ETHER_ADDR *dst_dev_addr, char *dst_ssid)
{
	BCMP2P_STATUS		status;
	BCMP2P_UINT8		ssid[BCMP2P_MAX_SSID_LEN];
	BCMP2P_UINT8		key[sizeof(p2papp_bss_config.keyWPA)];
	BCMP2P_BOOL		is_go = BCMP2PIsGroupOwner(p2papp_dev_hdl);
	struct ether_addr	*dev_addr;
	BCMP2P_UINT8		passphrase[sizeof(p2papp_bss_config.keyWPA)];

	status = BCMP2PGetGOCredentials(p2papp_dev_hdl, ssid, key, passphrase);
	if (BCMP2P_SUCCESS != status) {
		return status;
	}

	if (is_go)
		dev_addr = p2papi_get_p2p_dev_addr(p2papp_dev_hdl);
	else
		dev_addr = p2papi_get_peer_dev_addr(p2papp_dev_hdl);

	memcpy(dst_dev_addr->octet, dev_addr->octet, sizeof(*dst_dev_addr));
	memcpy(dst_ssid, ssid, BCMP2P_MAX_SSID_LEN);
	dst_ssid[BCMP2P_MAX_SSID_LEN - 1] = '\0';

	return (BCMP2P_SUCCESS);
}

/* maintain service handle for cleanup */
#define SVC_BONJOUR_MAX	3
static BCMSVCHandle svc_bonjour[SVC_BONJOUR_MAX];
#define SVC_UPNP_MAX	4
static BCMSVCHandle svc_upnp[SVC_UPNP_MAX];
static BCMSVCHandle *svc_added;

static BCMP2P_STATUS p2papp_init_service_discovery(void)
{
	/* use example data from P2P spec Annex E */
	const BCMP2P_UINT8 bonjour_query1[] = {
		0x0b, 0x5f, 0x61, 0x66, 0x70, 0x6f, 0x76, 0x65,
		0x72, 0x74, 0x63, 0x70, 0xc0, 0x0c, 0x00, 0x0c,
		0x01};
	BCMP2P_UINT32 bonjour_query_size1 = sizeof(bonjour_query1);
	const BCMP2P_UINT8 bonjour_resp1[] = {
		0x0b, 0x5f, 0x61, 0x66, 0x70, 0x6f, 0x76, 0x65,
		0x72, 0x74, 0x63, 0x70, 0xc0, 0x0c, 0x00, 0x0c,
		0x01, 0x07, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c,
		0x65, 0xc0, 0x27};
	BCMP2P_UINT32 bonjour_resp_size1 = sizeof(bonjour_resp1);

	const BCMP2P_UINT8 bonjour_query2[] = {
		0x04, 0x5f, 0x69, 0x70, 0x70, 0xc0, 0x0c, 0x00,
		0x0c, 0x01};
	BCMP2P_UINT32 bonjour_query_size2 = sizeof(bonjour_query2);
	const BCMP2P_UINT8 bonjour_resp2[] = {
		0x04, 0x5f, 0x69, 0x70, 0x70, 0xc0, 0x0c, 0x00,
		0x0c, 0x01, 0x09, 0x4d, 0x79, 0x50, 0x72, 0x69,
		0x6e, 0x74, 0x65, 0x72, 0xc0, 0x27};
	BCMP2P_UINT32 bonjour_resp_size2 = sizeof(bonjour_resp2);

	const BCMP2P_UINT8 bonjour_query3[] = {
		0x09, 0x6d, 0x79, 0x70, 0x72, 0x69, 0x6e, 0x74,
		0x65, 0x72, 0x04, 0x5f, 0x69, 0x70, 0x70, 0xc0,
		0x0c, 0x00, 0x10, 0x01};
	BCMP2P_UINT32 bonjour_query_size3 = sizeof(bonjour_query3);
	const BCMP2P_UINT8 bonjour_resp3[] = {
		0x09, 0x6d, 0x79, 0x70, 0x72, 0x69, 0x6e, 0x74,
		0x65, 0x72, 0x04, 0x5f, 0x69, 0x70, 0x70, 0xc0,
		0x0c, 0x00, 0x10, 0x01, 0x09, 0x74, 0x78, 0x74,
		0x76, 0x65, 0x72, 0x73, 0x3d, 0x31, 0x1a, 0x70,
		0x64, 0x6c, 0x3d, 0x61, 0x70, 0x70, 0x6c, 0x69,
		0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x70,
		0x6f, 0x73, 0x74, 0x73, 0x63, 0x72, 0x69, 0x70,
		0x74};
	BCMP2P_UINT32 bonjour_resp_size3 = sizeof(bonjour_resp3);
#ifndef P2P_UPNP_DISCOVERY
	const BCMP2P_UINT8 upnp_query1[] =
		"\x10urn:schemas-upnporg:device:InternetGatewayDevice:1";
	BCMP2P_UINT32 upnp_query_size1 = sizeof(upnp_query1) - 1;
	const BCMP2P_UINT8 upnp_resp1[] =
		"\x10uuid:6859dede-8574-59ab-9332-123456789012::"
		"urn:schemas-upnporg:device:InternetGatewayDevice:1";
	BCMP2P_UINT32 upnp_resp_size1 = sizeof(upnp_resp1) - 1;

	const BCMP2P_UINT8 upnp_query2[] =
		"\x10upnp:rootdevice";
	BCMP2P_UINT32 upnp_query_size2 = sizeof(upnp_query2) - 1;
	const BCMP2P_UINT8 upnp_resp2[] =
		"\x10uuid:6859dede-8574-59ab-9332-123456789012::"
		"upnp:rootdevice,uuid:5566d33e-9774-09ab-4822-333456785632::"
		"upnp:rootdevice";
	BCMP2P_UINT32 upnp_resp_size2 = sizeof(upnp_resp2) - 1;

	const BCMP2P_UINT8 upnp_query3[] =
		"\x10uuid:6859dede-8574-59ab-9332-123456789012";
	BCMP2P_UINT32 upnp_query_size3 = sizeof(upnp_query3) - 1;
	const BCMP2P_UINT8 upnp_resp3[] =
		"\x10uuid:6859dede-8574-59ab-9332-123456789012";
	BCMP2P_UINT32 upnp_resp_size3 = sizeof(upnp_resp3) - 1;

	const BCMP2P_UINT8 upnp_query4[] =
		"\x10urn:schemas-upnporg:service:ContentDirectory:2";
	BCMP2P_UINT32 upnp_query_size4 = sizeof(upnp_query4) - 1;
	const BCMP2P_UINT8 upnp_resp4[] =
		"\x10uuid:1122de4e-8574-59ab-9322-333456789044::"
		"urn:schemas-upnporg:service:ContentDirectory:2,"
		"uuid:5566d33e-9774-09ab-4822-333456785632::"
		"urn:schemas-upnporg:service:ContentDirectory:2";
	BCMP2P_UINT32 upnp_resp_size4 = sizeof(upnp_resp4) - 1;
#endif /* P2P_UPNP_DISCOVERY */
	svc_bonjour[0] = BCMP2PRegService(p2papp_dev_hdl,
		0, BCMP2P_SVC_PROTYPE_BONJOUR,
		bonjour_query1, bonjour_query_size1,
		bonjour_resp1, bonjour_resp_size1);

	svc_bonjour[1] = BCMP2PRegService(p2papp_dev_hdl,
		0, BCMP2P_SVC_PROTYPE_BONJOUR,
		bonjour_query2, bonjour_query_size2,
		bonjour_resp2, bonjour_resp_size2);

	svc_bonjour[2] = BCMP2PRegService(p2papp_dev_hdl,
		0, BCMP2P_SVC_PROTYPE_BONJOUR,
		bonjour_query3, bonjour_query_size3,
		bonjour_resp3, bonjour_resp_size3);
#ifndef P2P_UPNP_DISCOVERY
	svc_upnp[0] = BCMP2PRegService(p2papp_dev_hdl,
		0, BCMP2P_SVC_PROTYPE_UPNP,
		upnp_query1, upnp_query_size1,
		upnp_resp1, upnp_resp_size1);

	svc_upnp[1] = BCMP2PRegService(p2papp_dev_hdl,
		0, BCMP2P_SVC_PROTYPE_UPNP,
		upnp_query2, upnp_query_size2,
		upnp_resp2, upnp_resp_size2);

	svc_upnp[2] = BCMP2PRegService(p2papp_dev_hdl,
		0, BCMP2P_SVC_PROTYPE_UPNP,
		upnp_query3, upnp_query_size3,
		upnp_resp3, upnp_resp_size3);

	svc_upnp[3] = BCMP2PRegService(p2papp_dev_hdl,
		0, BCMP2P_SVC_PROTYPE_UPNP,
		upnp_query4, upnp_query_size4,
		upnp_resp4, upnp_resp_size4);
#else
	/*
	* For UPNP, we want to register queries by using p2papp_upnp.c
	* Function p2papp_sd_register_upnp_allsvcs() in p2papp_upnp.c -
	* will take care of registering all UPNP related queries
	*/
	p2papp_sd_register_upnp_allsvcs();
#endif /* P2P_UPNP_DISCOVERY */
	/* add services for testing device discovery comeback */
	if (p2papp_num_add_services > 0) {
		int i;

		svc_added = malloc(p2papp_num_add_services * sizeof(BCMSVCHandle));

		for (i = 0; i < p2papp_num_add_services; i++) {
			uint8 query[SD_TEST_DATA_SIZE];
			uint8 response[SD_TEST_DATA_SIZE];

			/* initialize query and response data */
			memset(query, i, SD_TEST_DATA_SIZE);
			memset(response, ~i, SD_TEST_DATA_SIZE);

			/* register service */
			svc_added[i] = BCMP2PRegService(p2papp_dev_hdl,
				0, BCMP2P_SVC_PROTYPE_UPNP,
				query, SD_TEST_DATA_SIZE,
				response, SD_TEST_DATA_SIZE);
		}
	}

	return (BCMP2P_SUCCESS);
}

static BCMP2P_STATUS p2papp_deinit_service_discovery(void)
{
	int i;

	for (i = 0; i < SVC_BONJOUR_MAX; i++)
		BCMP2PDeregService(p2papp_dev_hdl, svc_bonjour[i]);
#ifndef P2P_UPNP_DISCOVERY
	for (i = 0; i < SVC_UPNP_MAX; i++)
		BCMP2PDeregService(p2papp_dev_hdl, svc_upnp[i]);
#else
	p2papp_sd_unregister_upnp_allsvcs();
#endif
	for (i = 0; i < p2papp_num_add_services; i++)
		BCMP2PDeregService(p2papp_dev_hdl, svc_added[i]);
	if (p2papp_num_add_services > 0)
		free(svc_added);
	return (BCMP2P_SUCCESS);
}

/* Tx a P2P Device Discoverability Req to an active GO on the discovered peers
 * list.
 */
BCMP2P_STATUS
p2papp_tx_dev_discb_req_to_go(int go_peer_index, int client_number)
{
	BCMP2P_DISCOVER_ENTRY *dest_go;
	BCMP2P_STATUS status = BCMP2P_ERROR;

	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"p2papp_tx_dd_req_to_go: go_index=%d, GO client #%d\n",
		go_peer_index, client_number);

	/* Get the destination GO from the discovered peers list */
	if (go_peer_index >= p2papp_peer_count) {
		printf("Index %d is not in discovered peers list\n", go_peer_index);
		return status;
	}
	dest_go = &p2papp_peers_list[go_peer_index];

	/* Get the targeted GO client.  For now always use the GO's 1st client. */
	status = BCMP2PGetDiscoveredGOClientInfo(p2papp_dev_hdl, dest_go,
		client_number, &p2papp_target_client_addr);
	if (status != BCMP2P_SUCCESS) {
		printf("GO client #%d not found\n", client_number);
		return status;
	}

	/* Save operating channel as listen channel */
	memcpy(&p2papp_target_client_channel, &dest_go->channel,
		sizeof(p2papp_target_client_channel));

	/* Send P2P Device Discoverability Req to GO */
	status = BCMP2PSendDevDiscoverabilityReq(p2papp_dev_hdl,
		dest_go, &p2papp_target_client_addr);

	return status;
}
#endif /* not SOFTAP_ONLY */


static void
p2papp_print_version(BCMP2P_BOOL use_printf)
{
	if (use_printf) {
		printf("****************************************************\n");
		printf("Broadcom Wi-Fi Direct Host Support Library Test App\n");
		printf("Version: %s\n", P2PAPP_VERSION_STR);
		printf("****************************************************\n");
	} else {
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"****************************************************\n");
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"Broadcom Wi-Fi Direct Host Support Library Test App\n");
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"Version: %s\n", P2PAPP_VERSION_STR);
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"****************************************************\n");
	}
}

BCMP2P_BOOL
p2papp_init_lib(void)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	BCMP2P_BOOL ret = TRUE;

	p2papp_eventq_create(sizeof(p2papp_event_t));

	/* Initialize the P2P Library */
	status = BCMP2PInitialize(1, NULL);
	if (status != BCMP2P_SUCCESS) {
		printf("p2papp: BCMP2PInitialize() failed with %d\n", status);
		ret = FALSE;
	}

	if (ret) {
		/* Register our P2P library callbacks */
		if (BCMP2P_SUCCESS != BCMP2PRegisterNotification(
			BCMP2P_NOTIFY_ALL,
			p2papp_notif_cb, (void*) 0xabcd, NULL)) {
			printf("p2papp: BCMP2PRegisterNotification failed!\n");
			ret = FALSE;
		}
	}
	if (ret && p2papp_is_syslog) {
		p2papp_log_init();
		BCMP2PLogRegisterLogHandler(p2papp_log_print, "HSL", ":");
	}
	if (p2papp_changed_log_level) {
		BCMP2PLogEnable(p2papp_log_level);
	}

	p2papp_print_version(FALSE);

	if (ret) {
		/* Open our P2P device */
		p2papp_dev_hdl = BCMP2POpen(p2papp_phys_if_name, p2papp_phys_if_name);
		if (p2papp_dev_hdl == NULL) {
			printf("p2papp: BCMP2POpen failed!\n");
			return FALSE;
		}

		/* initialize connection parameters */
		p2papp_set_link_config(FALSE);

#ifndef SOFTAP_ONLY
		/* Set action frame tx parameters if changed from defaults */
		if (p2papp_af_retry_count != -1) {
			p2papi_set_af_tx_params(p2papp_dev_hdl, p2papp_af_retry_count,
				p2papp_af_retry_ms);
		}

		/* Enable/Disable persistent group capability */
		BCMP2PEnablePersistent(p2papp_dev_hdl, p2papp_enable_persistent);

		/* enable capabilities */
		BCMP2PEnableIntraBss(p2papp_dev_hdl, TRUE);
		BCMP2PEnableConcurrent(p2papp_dev_hdl, TRUE);
		BCMP2PEnableInvitation(p2papp_dev_hdl, TRUE);
		BCMP2PEnableServiceDiscovery(p2papp_dev_hdl, TRUE);
		BCMP2PEnableClientDiscovery(p2papp_dev_hdl, TRUE);

		/* Initialize service discovery. */
		p2papp_init_service_discovery();

		/* Initialize WFDisp */
		if (p2papp_enable_wfdisp)
			p2papp_wfd_init();
#endif /* not SOFTAP_ONLY */
	}

	/* For debug only: disable PBC overlap detection if requested */
	if (ret && p2papp_disable_pbc_overlap) {
		printf("p2papp: disabling PBC overlap detection.\n");
		(void) p2papi_enable_pbc_overlap(p2papp_dev_hdl, FALSE);
	}

	return ret;
}

void
p2papp_show_status(void)
{
	BCMP2P_CHANNEL channel;
	BCMP2P_STATUS status;

	status = BCMP2PGetChannel(p2papp_dev_hdl, &channel);
	if (status != BCMP2P_SUCCESS) {
		p2papi_log(BCMP2P_LOG_ERR, TRUE,
			"p2p_app: BCMP2PGetChannel error %d\n", status);
	}

	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"p2p_app: logLevel=%d HwChannel=%d:%d\n", p2papp_log_level,
		channel.channel_class, channel.channel);
}


/* Process a command.
 * Returns FALSE if command was an exit command, else returns TRUE.
 */
BCMP2P_BOOL
p2papp_process_cmd(uint8 key)
{
	char*	argv[1];
	char	buf[2];

	argv[0] = buf;
	buf[0] = key;
	buf[1] = '\0';

	return (p2papp_process_cmd_ex(1, argv));
}

const char* p2papp_log_level_name[BCMP2P_LOG_LEVEL_MAX] = {
	"BCMP2P_LOG_ALWAYS",	/* BCMP2P_LOG_ALWAYS */
	"BCMP2P_LOG_OFF",	/* BCMP2P_LOG_OFF */
	"BCMP2P_LOG_ERR",	/* BCMP2P_LOG_ERR */
	"BCMP2P_LOG_WARN",	/* BCMP2P_LOG_WARN */
	"BCMP2P_LOG_MED",	/* BCMP2P_LOG_MED */
	"BCMP2P_LOG_INFO",	/* BCMP2P_LOG_INFO */
	"BCMP2P_LOG_VERB",	/* BCMP2P_LOG_VERB */
	"BCMP2P_LOG_VERB_EVENT" /* BCMP2P_LOG_VERB_EVENT */
};

BCMP2P_BOOL
p2papp_process_cmd_ex(int argc, char* argv[])
{
	static BCMP2P_BOOL is_pin_input_mode = FALSE;
	BCMP2P_BOOL ret = TRUE;
	int i;
	int16 peer_index = -1;
	BCMP2P_BOOL is_num;

	/* If debug logs are being redirected to a log file
	 *   Output the command string to the log file.
	 */
	if (argc > 0 && p2papp_log_filename[0] != '\0') {
		p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_process_cmd_ex: %s %s %s %s\n",
			argv[0],
			argc > 1 ? argv[1] : "",
			argc > 2 ? argv[2] : "",
			argc > 3 ? argv[3] : "");
	}

	/* Check if the key selects the number of a peer on the discovered peers
	 * list.
	 */
	if (argc > 0) {
		is_num = TRUE;
		for (i = 0; i < strlen(argv[0]); i++) {
			if (!isdigit(argv[0][i])) {
				is_num = FALSE;
				break;
			}
		}

		if (is_num) {
			peer_index = (atoi(argv[0]) - 1);
		}
	}


	if (argc == 0) {
		/* P2PLOG("p2p_app: no key pressed\n"); */
	} else if (!strcmp(",", argv[0])) {
		/* Sleep 1 second */
		OSL_DELAY(1000 * 1000);
	} else if (!strcmp("i", argv[0])) {
		/* Initialize the P2P Library */
		if (!p2papp_do_startup_init) {
			ret = p2papp_init_lib();
		}
	} else if (!strcmp("config", argv[0])) {
		set_wps_config_method(argv[1]);
		p2papp_set_link_config(FALSE);
#ifndef SOFTAP_ONLY
	} else if ((!strcmp("e", argv[0])) || (!strcmp("l", argv[0]))) {
		if (BCMP2PIsDiscovering(p2papp_dev_hdl)) {
			p2papp_redraw("........Discovery already on......", "", "");
		} else {
			(void) p2papp_enable_discovery(strcmp("e", argv[0]),
				p2papp_discovery_iteration_secs);
		}
	} else if (!strcmp("d", argv[0])) {
		p2papp_is_gon_waiting = FALSE;
		(void) p2papp_disable_discovery();
	} else if (!strcmp("g", argv[0])) {
		/* Create P2P Group Owner */
		p2papp_create_group(NULL);

	} else if (!strcmp("b", argv[0])) {
		if (BCMP2PIsSTA(p2papp_dev_hdl) && p2papp_is_connected) {
			/* as per test case 6.1.9 */
			printf("Sending presence request with "
				"prefer=51200/102400, acceptable=none\n");
			BCMP2PSendPresenceRequest(p2papp_dev_hdl,
				TRUE, 51200, 102400, FALSE, 0, 0);
		} else if (BCMP2PIsAP(p2papp_dev_hdl) && !p2papp_is_created_softap) {
			BCMP2P_NOA_DESC desc = {0, 102400, 80000, 255};
			printf("Enabling CTWindow=10, NoA=80000/102400\n");
			BCMP2PEnableOppPwrSave(p2papp_dev_hdl, TRUE, 10);
			BCMP2PSetNoaSchedule(p2papp_dev_hdl,
				BCMP2P_NOA_TYPE_ABS, BCMP2P_NOA_ACTION_DOZE,
				BCMP2P_NOA_OPTION_NORMAL, 1, &desc);
		}
	} else if (!strcmp("B", argv[0])) {
		printf("Enabling extended listen timing 25/100 msec\n");
		BCMP2PExtendedListenTiming(p2papp_dev_hdl, TRUE, 25, 100);
	} else if (!strcmp("P", argv[0])) {
		if (argc == 2) {
			int num = atoi(argv[1]);
			printf("Send Provision Discovery to peer client %d\n",
				num);
			
			BCMP2PSendProvisionDiscoveryRequest(p2papp_dev_hdl,
				p2papp_get_provision_config_methods(
				p2papp_provision_config_methods,
				p2papp_peers_list[num-1].wps_cfg_methods),
				p2papp_peers_list[num-1].is_p2p_group,
				p2papp_peers_list[num-1].grp_ssid,
				p2papp_peers_list[num-1].grp_ssidLength,
				&p2papp_peers_list[num-1].channel,
				(BCMP2P_ETHER_ADDR *)p2papp_peers_list[num-1].mac_address);
		}
		else {
			printf("Usage: P <peer-index>\n");
		}
	} else if (!strcmp("S", argv[0])) {
		if (argc == 2) {
			int num = atoi(argv[1]);
			printf("Send Service Discovery request to peer client %d\n", num);
			p2papp_send_service_discovery(num-1);
		}
		else {
			printf("Usage: S <peer-index>\n");
		}
	} else if (!strcmp("v", argv[0])) {
		p2papp_enable_persistent = TRUE;
		BCMP2PEnablePersistent(p2papp_dev_hdl, p2papp_enable_persistent);
		p2papp_redraw("", "", "");
	} else if (!strcmp("w", argv[0])) {
		p2papp_enable_persistent = FALSE;
		BCMP2PEnablePersistent(p2papp_dev_hdl, p2papp_enable_persistent);
		p2papp_redraw("", "", "");
	} else if (!strcmp("y", argv[0])) {
		p2papp_persist_delete_all();
		p2papp_redraw("........ Persistent credentials deleted ........", "", "");
#endif /* SOFTAP_ONLY */
	} else if (!strcmp("p", argv[0]) || is_pin_input_mode) {
		/* Set WPS PIN */
		is_pin_input_mode = TRUE;
		if (strcmp("c", argv[0]) == 0) {
			BCMP2PSetWPSPin(p2papp_dev_hdl, p2papp_wps_pin);
			is_pin_input_mode = FALSE;
			}
		else if (strcmp("p", argv[0]) != 0) {
			int num;
			/* check for 8 digits numeric */
			if (strlen(argv[0]) == 8)
				if (sscanf(argv[0], "%d", &num) == 1)
					if (num <= 99999999) {
						BCMP2PSetWPSPin(p2papp_dev_hdl, argv[0]);
						is_pin_input_mode = FALSE;
					}
		}
		if (is_pin_input_mode) {
			if (strlen(p2papp_wps_pin))
				printf("Enter WPS pin (8 digits) or 'c' to use default PIN=%s: \n",
					p2papp_wps_pin);
			else
				printf("Enter WPS pin (8 digits): \n");
		}
#ifndef SOFTAP_ONLY
	} else if (!strcmp("pbc", argv[0])) {
		BCMP2PSelectWpsConfigMethod(p2papp_dev_hdl,BCMP2P_WPS_PUSHBUTTON);
		BCMP2PPushButton(p2papp_dev_hdl);
#endif /* not SOFTAP_ONLY */
	} else if (!strcmp("s", argv[0])) {
		/* Create a soft AP */
		 p2papp_create_softap();
	} else if (!strcmp("t", argv[0])) {
		/* Tear down a soft AP */
		p2papp_destroy_softap();
		p2papp_redraw("", "", "");
#ifndef SOFTAP_ONLY
	} else if (peer_index != -1) {
		/* '1'...'0','!'...'_': Initiate connection to a discovered P2P peer */
		P2PLOG1("p2p_app: selected peer_index %d\n", peer_index);
		{
			BCMP2P_UINT8 *deviceAddr;
			BCMP2P_PERSISTENT persist;

			deviceAddr = p2papp_peers_list[peer_index].mac_address;

			if (BCMP2PConnect(p2papp_dev_hdl, (BCMP2P_ETHER_ADDR *)deviceAddr,
				p2papp_enable_persistent ? p2papp_persist_find_addr(
				(BCMP2P_ETHER_ADDR *)deviceAddr, &persist) : 0)
				!= BCMP2P_SUCCESS) {
				p2papp_redraw("Invalid connection", "", "");
			}
		}
#endif /* SOFTAP_ONLY */
	} else if (!strcmp("x", argv[0])) {
		/* Disconnect in-progress or connected P2P connection, or end a
		 * P2P group/soft AP.
		 */
		p2papp_disconnect();
		p2papp_redraw(NULL, NULL, NULL);
	} else if (!strcmp("q", argv[0])) {
		/* Quit this app with disconnect and P2P Library shutdown */
		p2papp_stay_connected = FALSE;
		ret = FALSE;
#ifndef SOFTAP_ONLY
	} else if (!strcmp("D", argv[0])) {
		if (argc == 3) {
			int go_num = atoi(argv[1]);
			int client_num = atoi(argv[2]);
			printf("Send Device Discoverability request to peer GO %d\n",
				go_num);
			p2papp_tx_dev_discb_req_to_go(go_num - 1, client_num - 1);
			p2papp_invoke_client_discovery_connection = FALSE;
		}
		else {
			printf("Usage: D <peer-GO-index> <GO-client-number>\n");
			printf("   eg: D 5 1\n");
			printf("       Sends to a GO which is the 5th item in the\n");
			printf("       discovered peers list, specifying a target GO\n");
			printf("       client that is in the 1st client info descriptor\n");
			printf("       in the GO's P2P IE Group Info attribute.\n");
		}
#endif /* not SOFTAP_ONLY */
	} else if (!strcmp("zzz", argv[0])) {
			BCMP2PSetPowerSavingMode(p2papp_dev_hdl, BCMP2P_PS_ENHANCED);
	} else if (!strcmp("ooo", argv[0])) {
			BCMP2PSetPowerSavingMode(p2papp_dev_hdl, BCMP2P_PS_WAKEUP);
	} else if (!strcmp("z", argv[0])) {
		/* Quit this app without disconnect or lib cleanup (stay connected) */
		p2papp_stay_connected = TRUE;
		ret = FALSE;
	} else if (!strcmp("r", argv[0])) {
		/* Redraw the menu/status screen */
		p2papp_redraw(NULL, NULL, NULL);
	} else if (!strcmp("+", argv[0])) {
		/* Increase debug log verbosity */
		if (p2papp_log_level < BCMP2P_LOG_LEVEL_MAX-1)
			p2papp_log_level++;
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"p2p_app: increasing log verbosity to %d (%s)\n",
			p2papp_log_level, p2papp_log_level_name[p2papp_log_level]);
		BCMP2PLogEnable(p2papp_log_level);
	} else if (!strcmp("-", argv[0])) {
		/* Decrease debug log verbosity */
		if (p2papp_log_level > BCMP2P_LOG_OFF)
			p2papp_log_level--;
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"p2p_app: decreasing log verbosity to %d (%s)\n",
			p2papp_log_level, p2papp_log_level_name[p2papp_log_level]);
		BCMP2PLogEnable(p2papp_log_level);
	} else if (!strcmp("?", argv[0])) {
		p2papp_show_status();
		p2papp_test_ioctl(p2papp_dev_hdl);
		p2papp_test_iovar(p2papp_dev_hdl);
	} else if (!strcmp("a", argv[0])) {
		p2papp_deauth();
	} else if (!strcmp("f", argv[0])) {
		p2papp_cycle_mac_filter();
	} else {
		fprintf(stderr, "p2p_app: Invalid cmd '%s'\n", argv[0]);
	}

	return ret;
}

BCMP2P_STATUS
set_provision_config_method(char *val)
{
	if (strcmp(val, "label") == 0) {
		p2papp_provision_config_methods = BCMP2P_WPS_LABEL;
	}
	else if (strcmp(val, "display") == 0) {
		p2papp_provision_config_methods = BCMP2P_WPS_DISPLAY;
	}
	else if (strcmp(val, "keypad") == 0) {
		p2papp_provision_config_methods = BCMP2P_WPS_KEYPAD;
	}
	else if (strcmp(val, "pbc") == 0) {
		p2papp_provision_config_methods = BCMP2P_WPS_PUSHBUTTON;
	}
	else
	{
		return (BCMP2P_ERROR);
	}

	return (BCMP2P_SUCCESS);
}

BCMP2P_STATUS
set_wps_config_method(char *val)
{
	P2PLOG1("p2papp set_wps_config_method: %s\n", val);

	/* OR supported/selected config method bits */
	if (strcmp(val, "label") == 0) {
		p2papp_override_wps_config_methods = TRUE;
		p2papp_wps_config_methods |= BCMP2P_WPS_LABEL;
	}
	else if (strcmp(val, "display") == 0) {
		p2papp_override_wps_config_methods = TRUE;
		p2papp_wps_config_methods |= BCMP2P_WPS_DISPLAY;
	}
	else if (strcmp(val, "keypad") == 0) {
		p2papp_override_wps_config_methods = TRUE;
		p2papp_wps_config_methods |= BCMP2P_WPS_KEYPAD;
	}
	else if (strcmp(val, "pbc") == 0) {
		p2papp_override_wps_config_methods = TRUE;
		p2papp_wps_config_methods |= BCMP2P_WPS_PUSHBUTTON;
	}
	else {
		return (BCMP2P_ERROR);
	}

	return (BCMP2P_SUCCESS);
}

/*
 * Main event processing loop.
 * This polls for both keyboard input and changes in internal app
 * flags.
 */
#define MAX_NUM_ARGS	32
BCMP2P_STATUS
bcmp2p_event_process(BCMP2P_BOOL non_blocking)
{
	char *cmd_argv[MAX_NUM_ARGS];
	int cmd_argc;
	int status;
	p2papp_event_t event;

	/* process event queue until empty */
	while (1) {
		if (p2papp_eventq_receive((char *)&event) == -1)
			break;

		p2papp_process_event(event.code, event.context,
			event.notificationData, event.notificationDataLength);
	}

	/*
	 * Poll for and process keyboard input
	 */
#ifndef SOFTAP_ONLY
	/* Automatically resend GON if we send GON RESP failure with provisioning not ready */
	if (p2papp_is_gon_waiting && BCMP2PIsProvision(p2papp_dev_hdl)) {

		p2papp_is_gon_waiting = FALSE;

		P2PLOG("Issue GON request back while provisioning info is ready \n");
		if (BCMP2PConnect2(p2papp_dev_hdl, (BCMP2P_ETHER_ADDR *)p2papp_gon_info.mac_address,	
						   &p2papp_gon_info.channel, p2papp_gon_info.is_p2p_group,
						   (BCMP2P_ETHER_ADDR *)p2papp_gon_info.int_address, 
						   (char *)p2papp_gon_info.ssid, 0) != BCMP2P_SUCCESS) {
			p2papp_redraw("Invalid connection", "", "");
		}
	}
#endif /* SOFTAP_ONLY */
	status = p2papp_cli(cmd_argv, MAX_NUM_ARGS, &cmd_argc, non_blocking);
	if (status == BCMP2P_ERROR) {
		/* Error, exit main loop. */
		return (BCMP2P_ERROR);
	}

	if (!p2papp_process_cmd_ex(cmd_argc, cmd_argv))
		return (BCMP2P_ERROR);

	return (BCMP2P_SUCCESS);
}

/*
 * Delay while continuing to process events.
 * May be invoked recursively (i.e. while processing event)
 */
BCMP2P_STATUS
p2papp_delay(int msec)
{
	int sleep = 100;
	int elapsed;

	for (elapsed = 0; elapsed < msec; elapsed += sleep) {
		bcmp2p_event_process(BCMP2P_TRUE);
		OSL_DELAY(sleep * 1000);
	}

	return BCMP2P_SUCCESS;
}


/*
 * Name        : main
 * Description : Main entry point for the P2P Library Sample App
 * Arguments   : int argc, char *argv[] - command line parameters
 * Return type : int
 */
int
bcmp2p_main_str(char *str)
{
	char *argv[MAX_NUM_ARGS];
	int argc;
	char *token;
	char *saveptr;
	char *strp;


	memset(argv, 0, sizeof(argv));

	/* Parse args string into white-space separated tokens. */
	argc = 0;
	strp = str;
	while ((argc < (MAX_NUM_ARGS - 1)) &&
	       ((token = strtok_r(strp, " \t\n", &saveptr)) != NULL)) {
		argv[argc++] = token;
		strp = NULL;
	}
	argv[argc] = NULL;

	return (bcmp2p_main(argc, argv));
}

int
bcmp2p_main(int argc, char* argv[])
{
	int index;
	char *cmd, *val;
	char *batch_cmds = NULL;
	struct ether_addr our_mac;
	bool is_op_chan_specified = FALSE;
	int ret = -1;
	BCMP2P_CHANNEL_STRING channel_str;

	p2papp_print_version(TRUE);

	/*
	 * Parse the command line arguments, skipping the program name.
	 */
	argc--;
	index = 1;
	while (argc) {
		cmd = argv[index++]; argc--;
		if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
			print_usage();
			goto exit;
		}
#ifndef SOFTAP_ONLY
		else if (!strcmp(cmd, "--persist")) {
			printf("Enable persistent group capability.\n");
			p2papp_enable_persistent = TRUE;
		}
		else if (!strcmp(cmd, "--managed")) {
			printf("Enable managed device.\n");
			p2papp_enable_managed = TRUE;
		}
		else if (!strcmp(cmd, "--auto")) {
			p2papp_auto_responder_mode = TRUE;
			printf("Enabling background auto P2P responder mode.\n");
		}
		else if (!strcmp(cmd, "--start_go")) {
			p2papp_auto_go_mode = TRUE;
			printf("Enabling background autonomous GO mode.\n");
		}
		else if (!strcmp(cmd, "--start_pbc")) {
			p2papp_auto_pbc_mode = TRUE;
			printf("Enabling background automatically start WPS PBC mode.\n");
		}
		else if (!strcmp(cmd, "--auto_disassoc")) {
			p2papp_auto_disassoc_mode = TRUE;
			printf("Automatically tear down GO if no GC associates with it.\n");
		}

#endif /* not SOFTAP_ONLY */
		else if (!strcmp(cmd, "-b") || !strcmp(cmd, "--batch")) {
			if (argc <= 0 || argv[index][0] == '-') {
				printf("Must specify a string of key cmds after '%s'\n", cmd);
				printf("eg. %s %s i,s,,,,rz\n", argv[0], cmd);
				goto exit;
			}
			batch_cmds = argv[index++];
			argc--;
			printf("Running these commands in batch mode: %s\n", batch_cmds);
		}
#ifndef SOFTAP_ONLY
		else if (!strcmp(cmd, "-c") || !strcmp(cmd, "--channel")) {
			if (argc <= 0) {
				printf("Need to specify a listen channel # after '-c'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			p2papp_listen_channel.channel = atoi(val);
		}
#endif /* SOFTAP_ONLY */
		else if (!strcmp(cmd, "-o") || !strcmp(cmd, "--opch")) {
			BCMP2P_CHANNEL channel;
			if (argc <= 0) {
				printf("Need to specify an operating channel # after '-o'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			if (BCMP2PStringToChannel(val, &channel) == BCMP2P_SUCCESS) {
				memcpy(&p2papp_operating_channel, &channel,
					sizeof(p2papp_operating_channel));
				is_op_chan_specified = TRUE;
			}
		}
#ifdef BCM_P2P_OPTEXT
		else if (!strcmp(cmd, "-oforce"))
		{
			p2papp_opch_force = TRUE;
		}
		else if (!strcmp(cmd, "-ohigh"))
		{
			p2papp_opch_high = TRUE;
		}
#endif
		else if (!strcmp(cmd, "-d") || !strcmp(cmd, "--debug")) {
			p2papp_log_level = BCMP2P_LOG_MED;
			p2papp_changed_log_level = TRUE;
		}
		else if (!strcmp(cmd, "-de")) {
			p2papp_log_level = BCMP2P_LOG_ERR;
			p2papp_changed_log_level = TRUE;
		}
		else if (!strcmp(cmd, "-dw")) {
			p2papp_log_level = BCMP2P_LOG_WARN;
			p2papp_changed_log_level = TRUE;
		}
		else if (!strcmp(cmd, "-dm")) {
			p2papp_log_level = BCMP2P_LOG_MED;
			p2papp_changed_log_level = TRUE;
		}
		else if (!strcmp(cmd, "-di")) {
			p2papp_log_level = BCMP2P_LOG_INFO;
			p2papp_changed_log_level = TRUE;
		}
		else if (!strcmp(cmd, "-dv")) {
			p2papp_log_level = BCMP2P_LOG_VERB;
			p2papp_changed_log_level = TRUE;
		}
		else if (!strcmp(cmd, "-i")) {
			/* suppress app startup initialization */
			p2papp_do_startup_init = FALSE;
		} else if (!strcmp(cmd, "--nowps")) {
			printf("--nowps specified: disabling WPS.\n");
			p2papp_disable_wps = TRUE;
		} else if (!strcmp(cmd, "--intent")) {
			p2papp_override_go_intent = TRUE;
			val = argv[index++];
			argc--;
			p2papp_go_intent = atoi(val);
		} else if (!strcmp(cmd, "--provision")) {
			val = argv[index++];
			argc--;
			set_provision_config_method(val);
		} else if (!strcmp(cmd, "--config")) {
			val = argv[index++];
			argc--;
			set_wps_config_method(val);
		} else if (!strcmp(cmd, "-l") || !strcmp(cmd, "--log")) {
			if (argc <= 0) {
				printf("Need to specify a log file name after '-l'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			strncpy(p2papp_log_filename, val, sizeof(p2papp_log_filename));
			p2papi_set_log_file(p2papp_log_filename);
		} else if (!strcmp(cmd, "-lp")) {
			/* User specified log filename prefix. Timestamp will be
			 * appended to log filename.
			 */
			if (argc <= 0) {
				printf("Need to specify a log file name prefix after '-lp'\n");
				goto exit;
			}

			/* Filename prefix. */
			val = argv[index++];
			strncpy(p2papp_log_filename_prefix, val,
				sizeof(p2papp_log_filename_prefix));
			argc--;
			p2papp_get_timestamped_log_name(p2papp_log_filename,
			                                sizeof(p2papp_log_filename),
			                                val);
			p2papi_set_log_file(p2papp_log_filename);
		}
		else if (!strcmp(cmd, "-n") || !strcmp(cmd, "--name")) {
			if (argc <= 0) {
				printf("Need to specify a name after '-n'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			strncpy((char *)p2papp_friendly_name, val,
				sizeof(p2papp_friendly_name));
			p2papp_friendly_name[sizeof(p2papp_friendly_name) - 1] = '\0';
			printf("-n specified, friendly name=%s\n", p2papp_friendly_name);
		}
		else if (!strcmp(cmd, "--nooverlap")) {
			/* Disable PBC overlap detection */
			p2papp_disable_pbc_overlap = TRUE;
		}
		else if (!strcmp(cmd, "--overlap")) {
			/* Enable PBC overlap detection */
			p2papp_disable_pbc_overlap = FALSE;
		}
		else if (!strcmp(cmd, "--nosigint")) {
			/* Disable exiting the app on a SIGINT (ctrl-C) */
			p2papp_disable_sigint_exit = TRUE;
		}
		else if (!strcmp(cmd, "--passphrase")) {
			if (argc <= 0) {
				printf("Specify the passphrase (8 to 64 chars) "
					"after '--passphrase'\n");
				goto exit;
			}
			p2papp_override_passphrase = TRUE;
			p2papp_passphrase[0] = '\0';
			val = argv[index++];
			argc--;
			strncpy(p2papp_passphrase, val, sizeof(p2papp_passphrase));
		}
		else if (!strcmp(cmd, "--pin")) {
			if (argc <= 0) {
				printf("Specify the 8-digit PIN after '--pin'\n");
				goto exit;
			}
			p2papp_override_wps_pin = TRUE;
			p2papp_wps_pin[0] = '\0';
			val = argv[index++];
			argc--;
			strncpy(p2papp_wps_pin, val, sizeof(p2papp_wps_pin));
		}
		else if (!strcmp(cmd, "--pif")) {
			if (argc <= 0) {
				printf("Specify the physical interface name after '--pif'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			strncpy(p2papp_phys_if_name, val, sizeof(p2papp_phys_if_name));
		}
#ifndef SOFTAP_ONLY
		else if (!strcmp(cmd, "--pridevtype")) {
			if (argc <= 1) {
				printf("Specify Primary Device Type category/sub-category.\n");
				printf("eg. --pridevtype 7 1\n");
				printf("    means TYPE_CAT_DISPLAYS SUB_CAT_DISP_TV\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			p2papp_pri_devtype = atoi(val);
			val = argv[index++];
			argc--;
			p2papp_pri_subcat = atoi(val);
		}
		else if (!strcmp(cmd, "--reqdevtype")) {
			if (argc <= 1) {
				printf("Specify Requested Device Type/sub-cat for discovery.\n");
				printf("eg. --reqdevtype 10 1\n");
				printf("    means TYPE_CAT_TELEPHONE SUB_CAT_PHONE_WM\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			p2papp_discov_filt_devtype = atoi(val);
			val = argv[index++];
			argc--;
			p2papp_discov_filt_subcat = atoi(val);
		} else if (!strcmp(cmd, "--sameaddr")) {
			printf("Using same P2P Interface Address as P2P Device Address.\n");
			p2papp_same_int_dev_addr = TRUE;
		}
#endif /* not SOFTAP_ONLY */
		else if (!strcmp(cmd, "--sec")) {
			if (argc <= 0) {
				printf("Specify the security type: open wep wpa wpa2\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			strncpy(p2papp_security_type, val, sizeof(p2papp_security_type));
			printf("Applying security type %s\n", p2papp_security_type);
		}
		else if (!strcmp(cmd, "--softap")) {
			p2papp_auto_softap_mode = TRUE;
			printf("Enabling background Soft AP mode.\n");
		}
		else if (!strcmp(cmd, "--syslog")) {
			p2papp_is_syslog = TRUE;
		}
		else if (!strcmp(cmd, "-t") || !strcmp(cmd, "--timeout")) {
			if (argc <= 0) {
				printf("Need to specify the # of seconds after '-n'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			p2papp_discovery_iteration_secs = atoi(val);
		}
		else if (!strcmp(cmd, "--noevtloop")) {
			p2papp_no_evt_loop = TRUE;
		}
#ifndef SOFTAP_ONLY
		else if (!strcmp(cmd, "--add_services")) {
			if (argc <= 0) {
				printf("Need to specify the # of services after"
					" '--add_services'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			p2papp_num_add_services = atoi(val);
		}
		else if (!strcmp(cmd, "--af_retry")) {
			/* Debug: Specify action frame tx parameters */
			if (argc <= 1) {
				printf("Specify the # of retries and retry milliseconds\n");
				printf("eg. --afretry 7 100\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			p2papp_af_retry_count = atoi(val);
			val = argv[index++];
			argc--;
			p2papp_af_retry_ms = atoi(val);
		}
		else if (strcmp(cmd, "--wfd") == 0) {
			p2papp_enable_wfdisp = TRUE;

			/* WiFiDisplay related parameters */
			val = argv[index++];

			memset(&wfd_dev_config, 0, sizeof(wfd_dev_config));

			/* Set WFD device type */
			wfd_dev_config.sess_avl = WFDCAPD_TRUE;
			wfd_dev_config.max_tput = 0x96;
			if (strcmp(val, "source") == 0)
				wfd_dev_config.dev_type = WFDCAPD_DEVICE_TYPE_SRC;
			else if (strcmp(val, "psink") == 0)
				wfd_dev_config.dev_type = WFDCAPD_DEVICE_TYPE_PRIM_SINK;
			else if (strcmp(val, "2sink") == 0)
				wfd_dev_config.dev_type = WFDCAPD_DEVICE_TYPE_SEC_SINK;
			else if (strcmp(val, "source-psink") == 0)
				wfd_dev_config.dev_type = WFDCAPD_DEVICE_TYPE_SRC_PRIM_SINK;
			else {
				printf("Missing WFD device type informaiton\n");
				goto exit;
			}
			argc--;

			/* Set WFD RTSP tcp port number */
			val = argv[index++];
			wfd_dev_config.rtsp_tcp_port = atoi(val);
			argc--;

			/* Check if optional argument 'hdcp' is present */
			if (argc && (strcmp(argv[index], "hdcp") == 0)) {
				wfd_dev_config.content_protected = TRUE;
				index++;
				argc--;
			}
			else 
				wfd_dev_config.content_protected = FALSE;

			/* TDLS configuration */
			if (argc && strcmp(argv[index], "tdls") == 0) {
				BCMP2P_IP_ADDR local_ip;
				uint8 assoc_bssid[6];
				struct in_addr ip_addr;

				index++;

				if (argv[index] == NULL || argv[index + 1] == NULL) {
					printf("Invalid TDLS parameter : %s\n", cmd);
					print_usage();
					goto exit;
				}

				if (sscanf(argv[index++], "%02x:%02x:%02x:%02x:%02x:%02x", 
						(unsigned int *)&assoc_bssid[0], 
						(unsigned int *)&assoc_bssid[1], 
						(unsigned int *)&assoc_bssid[2], 
						(unsigned int *)&assoc_bssid[3], 
						(unsigned int *)&assoc_bssid[4], 
						(unsigned int *)&assoc_bssid[5]) != 6) {
					printf("Invalid parameter (TDLS: associated bssid): %s\n", cmd);
					print_usage();
					goto exit;
				}
					
				local_ip = inet_addr(argv[index++]);
				if (local_ip == -1) {
					printf("Invalid parameter (TDLS: local ip address): %s\n", cmd);
					print_usage();
					goto exit;
				}

				wfd_dev_config.tdls_available = WFDCAPD_TRUE;
				memcpy(&wfd_dev_config.tdls_cfg.assoc_bssid, assoc_bssid, 6);
				wfd_dev_config.tdls_cfg.local_ip = local_ip;

				argc -= 3;
				ip_addr.s_addr = wfd_dev_config.tdls_cfg.local_ip;
				printf("WFD cmd parameters. TDLS: assoc mac %02x:%02x:%02x:%02x:%02x:%02x,"
					" local IP addresss %s\n",
					assoc_bssid[0], 
					assoc_bssid[1], 
					assoc_bssid[2], 
					assoc_bssid[3], 
					assoc_bssid[4], 
					assoc_bssid[5],
					inet_ntoa(ip_addr));
			}

			printf("WFD cmd parameters. dev_type %d, port %d hdcp %d\n",
			       wfd_dev_config.dev_type, wfd_dev_config.rtsp_tcp_port,
			       wfd_dev_config.content_protected);
		}
#endif /* not SOFTAP_ONLY */
		else if (strcmp(cmd, "--manufacturer") == 0) {
			if (argc <= 0) {
				P2PLOG("Specify the  manufacturer name (up to 64 chars) "
					"after '--manufacturer'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			strncpy(p2papp_manufacturer, val, sizeof(p2papp_manufacturer));
		}
		else if (strcmp(cmd, "--modelName") == 0) {
			if (argc <= 0) {
				P2PLOG("Specify the  model name (up to 32 chars) "
					"after '--modelName'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			strncpy(p2papp_modelName, val, sizeof(p2papp_modelName));
		}
		else if (strcmp(cmd, "--modelNumber") == 0) {
			if (argc <= 0) {
				P2PLOG("Specify the  model number (up to 32 chars) "
					"after '--modelNumber'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			strncpy(p2papp_modelNumber, val, sizeof(p2papp_modelNumber));
		}
		else if (strcmp(cmd, "--serialNumber") == 0) {
			if (argc <= 0) {
				P2PLOG("Specify the  serial number (up to 32 chars) "
					"after '--serialNumber'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			strncpy(p2papp_serialNumber, val, sizeof(p2papp_serialNumber));
		}
		else if (strcmp(cmd, "--osVersion") == 0) {
			if (argc <= 0) {
				P2PLOG("Specify the  OS Version (32-bit value) "
					"after '--osVersion'\n");
				goto exit;
			}
			val = argv[index++];
			argc--;
			p2papp_osVersion = atoi(val);
		}

		else {
			printf("Invalid parameter : %s\n", cmd);
			print_usage();
			goto exit;
		}
	}

	/* If wireless interface name not specified, auto-detect it */
	if (!*p2papp_phys_if_name) {
		if (0 != p2papp_get_wlan_ifname(p2papp_phys_if_name,
			sizeof(p2papp_phys_if_name))) {
			printf("wl driver adapter not found.\n");
			goto exit;
		}
	}

	/* if op channel not specified then becomes same as listen */
	if (!is_op_chan_specified)
		p2papp_operating_channel.channel = p2papp_listen_channel.channel;

	printf("--> Wireless interface: '%s'\n", p2papp_phys_if_name);
	printf("--> Friendly name     : '%s'\n", p2papp_friendly_name);
	printf("--> Discovery timeout : %d seconds\n",
		p2papp_discovery_iteration_secs);
	BCMP2PChannelToString(&p2papp_listen_channel, channel_str);
	printf("--> Listen channel    : %s\n", channel_str);
	BCMP2PChannelToString(&p2papp_operating_channel, channel_str);
	printf("--> Operating channel : %s\n", channel_str);

	/*
	 * If we are in batch mode
	 */
	if (batch_cmds != NULL) {
		p2papp_redraw(NULL, NULL, NULL);
		while (*batch_cmds != '\0')
		{
			printf("Processing batch command: %c\n", *batch_cmds);
			if (!p2papp_process_cmd(*batch_cmds))
				break;
			batch_cmds++;
			OSL_DELAY(130000);
		}
		printf("Finished processing batch commands.\n");
		ret = 0;

		if (p2papp_auto_responder_mode) {
			printf("Auto-enable P2P discovery.\n");
			(void) p2papp_process_cmd('e');
		}else if (p2papp_auto_go_mode) {
			printf("Auto-create Group Owner.\n");
			(void) p2papp_process_cmd('g');
		}

	/*
	 * else we are in interactive mode
	 */
	} else {

		/* If app startup initialization is not suppressed
		 *     Initialize the P2P Library.
		 * Notes:
		 * - batch mode always suppresses startup intialization.
		 * - the 'i' command can be used to do startup initialization.
		 */
		if (p2papp_do_startup_init) {
			if (!p2papp_init_lib()) {
				goto exit;
			}
		}
		ret = 0;

		if (p2papi_get_mac_addr(p2papp_dev_hdl, &our_mac)!= 0) {
			printf("Get current etheraddr failed. Exit\n");
			goto exit;
		}
		printf("--> Our MAC address  : %02x:%02x:%02x:%02x:%02x:%02x\n",
			our_mac.octet[0], our_mac.octet[1],
			our_mac.octet[2], our_mac.octet[3],
			our_mac.octet[4], our_mac.octet[5]);

#ifndef SOFTAP_ONLY
		/* Initialize our list of discovered peers */
		p2papp_peer_count = 0;
#endif

		if (p2papp_auto_responder_mode) {
			/* Enable P2P discovery */
			printf("Auto-enable P2P discovery.\n");
			(void) p2papp_process_cmd('e');
		} else if (p2papp_auto_softap_mode) {
			/* Enable SoftAP */
			printf("Auto-enable SoftAP.\n");
			(void) p2papp_process_cmd('s');
		} else if (p2papp_auto_go_mode) {
			printf("Auto-create Group Owner.\n");
			(void) p2papp_process_cmd('g');
		}


		p2papp_redraw(NULL, NULL, NULL);

		/* Bail if we're not required to run the main polling loop. */
		if (p2papp_no_evt_loop) {
			return ret;
		}

		/*
		 * Main event polling loop.
		 * This polls for both keyboard input and changes in internal app
		 * flags.
		 */
		while (1)
		{
			if (bcmp2p_event_process(BCMP2P_FALSE) != BCMP2P_SUCCESS) {
				break;
			}
		}
			/* If it is GO but not autonomous GO, we will check if there no GC is associated, disconnect in 20 secs */
#ifndef SOFTAP_ONLY
		if (p2papp_auto_disassoc_mode)
		{
			if ( !p2papp_is_created_grp_owner && p2papp_is_ap)
			{
				int i =0;
				uint32 num_peers = 0;
				BCMP2P_PEER_INFO info[8];

				if (p2papp_is_connected)
				{
//					P2PLOG2(" completed? + %d, is connected %d\n", p2papp_is_connect_complete, p2papp_is_connected);
//					P2PLOG( "Connected!.....\n");
					memset(info, 0, sizeof(info));
					while ((num_peers == 0) && (i < 10))
					{
						if (BCMP2PGetPeerInfo(p2papp_dev_hdl, &info[0], sizeof(info),&num_peers) != BCMP2P_SUCCESS)
							break;
						if (num_peers) {
							break;
						}
						i ++;
						OSL_DELAY(1000 * 1000); //Sleep 1000 msec
						printf("Sleep 1 sec\n");
					}
					if (num_peers == 0) {
						/* Disconnect GO since no GC associated during 10 sec in GON case*/
						printf("Disabled since no peer assciated\n");
						p2papp_disconnect();
						if (p2papp_auto_responder_mode) {
							printf("Automatically re-enabling P2P discovery.\n");
							OSL_DELAY(4000 * 1000); //Give 2s delay to make sure interface is down.
							(void) p2papp_process_cmd('l');
						}

						p2papp_redraw(NULL, NULL, NULL);

					}
				}
				else
				{
					/* Wait for up to 2 minutes for WPS */
					P2PLOG( "Check GO accociation status ........\n");
					P2PLOG2(" completed? + %d, is connected %d\n", p2papp_is_connect_complete, p2papp_is_connected);
					if (p2papp_wait_for_connect_complete(120*1000) != BCMP2P_SUCCESS)  
					{
						/* Disconnect the GO if Link failed */
						p2papp_disconnect();
						P2PLOG("Disabled since link failed\n");
						if (p2papp_auto_responder_mode) {
							printf("Automatically re-enabling P2P discovery.\n");
							OSL_DELAY(4000 * 1000); //Give 2s delay to make sure interface is down.
							(void) p2papp_process_cmd('l');
						}
						p2papp_redraw(NULL, NULL, NULL);
					}
				}

			}
#endif

	}
	P2PLOG("p2p_app: exited main loop\n");
	}

exit:
	p2papp_osl_deinit();

	if (p2papp_stay_connected) {
		printf("\n================= Detaching p2papp ================\n");
	} else {
		printf("\n================= Shutting down p2papp ================\n");
		p2papp_shutdown();
		P2PLOG("=== P2P app shutdown complete ===\n");
	}
	return ret;
}


/* Reset all the P2P parameters to device defaults including but not
 * limited to removal of persistent group and stored credentials.
 */
BCMP2P_STATUS p2papp_device_reset(void)
{
	P2PLOG("p2papp_device_reset\n");

	/* Print the date to allow correlating the HSL logs with the UCC logs */
	p2papi_log(BCMP2P_LOG_MED, TRUE, "%s\n", p2papp_ctime());

	/*
	 * Disable discovery and tear down the connection.
	 */
#ifndef SOFTAP_ONLY
	p2papp_disable_discovery();
#endif
	p2papp_disconnect();
	/* Sleep 500 ms to wait for asynchronous complete */
	OSL_DELAY(500 * 1000);

	/* restore to default */
	BCMP2PSetSupportedWpsConfigMethods(p2papp_dev_hdl, P2PAPP_DEFAULT_CONFIG_METHODS);
	p2papp_wps_config_methods = P2PAPP_DEFAULT_CONFIG_METHODS;
	p2papp_provision_config_methods = P2PAPP_DEFAULT_CONFIG_METHODS;

#ifndef SOFTAP_ONLY
	/* Disable extended listen timing. */
	BCMP2PExtendedListenTiming(p2papp_dev_hdl, FALSE, 0, 0);

	/* enable intra-BSS */
	BCMP2PEnableIntraBss(p2papp_dev_hdl, TRUE);
#endif /* not SOFTAP_ONLY */

	/* Remove all credentials. */
	p2papp_persist_delete_all();

#ifndef SOFTAP_ONLY
	p2papp_enable_connect_ping(FALSE);
#endif /* not SOFTAP_ONLY */


	return (BCMP2P_SUCCESS);
}


/* Enable/disable post connection ping test. */
BCMP2P_STATUS p2papp_enable_connect_ping(BCMP2P_BOOL enable)
{
	p2papp_enable_ping = enable;

	return (BCMP2P_SUCCESS);
}

BCMP2PHandle p2papp_get_hdl(void)
{
	return p2papp_dev_hdl;
}


#ifndef SOFTAP_ONLY
/* Wait until specified peer is discovered. Return when found, or timeout. */
BCMP2P_STATUS p2papp_wait_to_discover_peer(const char *peer_dev_id, unsigned int timeout_sec,
	BCMP2P_BOOL *is_client, int *go_idx, int *client_idx)
{
	BCMP2P_DISCOVER_ENTRY	*peer;
	unsigned int		msec, timeout_msec, peer_idx;
	BCMP2P_UINT8		mac_addr[6];

	/* Convert ASCII MAC address to binary. */
	if (p2papp_macaddr_aton(peer_dev_id, mac_addr) != BCMP2P_SUCCESS) {
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"p2papp_wait_to_discover_peer: aton error, peer_dev_id=%s\n",
			peer_dev_id);
		return (BCMP2P_ERROR);
	}
	p2papi_log(BCMP2P_LOG_MED, TRUE,
		"p2papp_wait_to_discover_peer: mac_addr=%x:%x:%x:%x:%x:%x\n",
		mac_addr[0], mac_addr[1], mac_addr[2],
		mac_addr[3], mac_addr[4], mac_addr[5]);

	timeout_msec = 1000 * timeout_sec;
	for (msec = 0; msec < timeout_msec; msec += 100) {

		/* Process events. */
		bcmp2p_event_process(BCMP2P_TRUE);

		/* Look for specified peer. */
		for (peer_idx = 0; peer_idx < p2papp_peer_count; peer_idx++) {
			peer = &p2papp_peers_list[peer_idx];

			if (memcmp(mac_addr, peer->mac_address, sizeof(mac_addr)) == 0) {
				/* Found it, bail. */
				*is_client = FALSE;
				p2papi_log(BCMP2P_LOG_MED, TRUE,
					"p2papp_wait_to_discover_peer: peer %d found\n",
					peer_idx);
				return (BCMP2P_SUCCESS);
			}

			/* get clients if group owner */
			if (peer->is_p2p_group) {
				uint32 client_count = 0;
				BCMP2P_CLIENT_LIST client_list[BCMP2P_MAX_SOFTAP_CLIENTS];
				uint32 i;

				BCMP2PGetPeerGOClientInfo(p2papp_dev_hdl, peer,
					client_list, sizeof(client_list), &client_count);
				p2papi_log(BCMP2P_LOG_MED, TRUE,
					"    peer %d: %02x:%02x:%02x:%02x:%02x:%02x"
					" is GO with %d clients:\n",
					peer_idx,
					peer->mac_address[0], peer->mac_address[1],
					peer->mac_address[2], peer->mac_address[3],
					peer->mac_address[4], peer->mac_address[5],
					client_count);

				for (i = 0; i < client_count; i++) {

					p2papi_log(BCMP2P_LOG_MED, TRUE,
						"        GO client %02x:%02x:%02x:%02x:%02x:%02x\n",
						client_list[i].dev_addr.octet[0],
						client_list[i].dev_addr.octet[1],
						client_list[i].dev_addr.octet[2],
						client_list[i].dev_addr.octet[3],
						client_list[i].dev_addr.octet[4],
						client_list[i].dev_addr.octet[5]);
					if (memcmp(mac_addr, client_list[i].dev_addr.octet,
						sizeof(mac_addr)) == 0) {
						/* Found it, bail. */
						*is_client = TRUE;
						*go_idx = peer_idx;
						*client_idx = i;
						p2papi_log(BCMP2P_LOG_MED, TRUE,
							"p2papp_wait_to_discover_peer: "
							"peer %d client %d found\n", peer_idx, i);
						return (BCMP2P_SUCCESS);
					}
				}
			}
			else {
				p2papi_log(BCMP2P_LOG_MED, TRUE,
					"    peer %d: %02x:%02x:%02x:%02x:%02x:%02x\n",
					peer_idx,
					peer->mac_address[0], peer->mac_address[1],
					peer->mac_address[2], peer->mac_address[3],
					peer->mac_address[4], peer->mac_address[5]);
			}
		}

		/* Sleep 100 msec */
		OSL_DELAY(100 * 1000);
	}

	/* Peer not found. */
	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_wait_to_discover_peer:"
		" peer %02x:%02x:%02x:%02x:%02x:%02x not found\n",
		mac_addr[0], mac_addr[1], mac_addr[2],
		mac_addr[3], mac_addr[4], mac_addr[5]);
	return (BCMP2P_ERROR);
}

/* Clear the GON waiting flag used to initiate an automatic reverse GON after
 * WPS is provisioned.  Called only by the P2P Sigma API.
 */
BCMP2P_STATUS p2papp_clear_gon_waiting(void)
{
	p2papp_is_gon_waiting = FALSE;
	return BCMP2P_SUCCESS;
}
#endif /* not SOFTAP_ONLY */

BCMP2P_STATUS p2papp_set_listen_channel(BCMP2P_INT32 channel)
{
	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_set_listen_channel: %d\n",
		channel);
	p2papp_listen_channel.channel = channel;
	return BCMP2P_SUCCESS;
}

BCMP2P_INT32 p2papp_get_listen_channel(void)
{
	return p2papp_listen_channel.channel;
}

static void
p2papp_get_timestamped_log_name(char *buf, int buf_size, const char *prefix)
{
	char timestr[128];
	time_t t;
	struct tm *tmp;

	/* Get current time-stamp. */
	timestr[0] = '\0';
	t = time(NULL);
	tmp = localtime(&t);
	if (tmp == NULL) {
		p2papi_log(BCMP2P_LOG_ERR, TRUE, "%s: Error getting localtime!\n");
	}
	else {
		if (strftime(timestr, sizeof(timestr), "%b-%e-%Y__%H-%M-%S", tmp) == 0) {
			p2papi_log(BCMP2P_LOG_ERR, TRUE, "%s: Error getting strftime!\n");
		}
	}

	/* Generate logname using user specified prefix, and time-stamp. */
	snprintf(buf, buf_size, "%s-%s.log", prefix, timestr);
}

void
p2papp_set_log_file(const char *filename)
{
	char buf[256];

	if (p2papp_log_filename[0] == '\0') {
		p2papi_log(BCMP2P_LOG_MED, TRUE,
			"p2papp_set_log_file: ignored, no -l option. (%s)\n",
			filename);
		return;
	}

#ifndef TARGETENV_android
	p2papp_system("mkdir -p ./log");
	snprintf(buf, sizeof(buf), "./log/%s-%s.log", p2papp_friendly_name, filename);
#else
	p2papp_system("mkdir -p /data/local/log");
	snprintf(buf, sizeof(buf), "data/local/log/%s-%s.log", p2papp_friendly_name, filename);
#endif /* !TARGETENV_android */

	p2papi_set_log_file(buf);
	p2papp_print_version(FALSE);
}
