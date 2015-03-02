/* P2P API core
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_api.h,v 1.253 2011-01-19 20:14:58 $
 */

#ifndef _p2plib_api_h_
#define _p2plib_api_h_

#include <wpscli_api.h>
#include <typedefs.h>
#include <wlioctl.h>
#include <802.11.h>
#include <p2p.h>

/* P2P Library include files */
#include <BcmP2PAPI.h>
#include <p2plib_osl.h>
#include <bcmseclib_timer.h>
#include <p2plib_aftx.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants and Types
 */


#include <packed_section_start.h>
/* @@@TEMP: All definitions within this packed_section_start/end should be
 * moved to src/include/proto/p2p.h.
 */

/* P2P IE attribute IDs */
#define P2P_SEID_LISTEN_CHANNEL		6	/* Listen Channel */
#define P2P_SEID_OPERATING_CHANNEL	17	/* Operating Channel */
#define P2P_SEID_INVITATION_FLAGS	18	/* Invitation Flags */

/* Status attribute: Status Code definitions */
#define P2P_STATSE_FAIL_REJECTED_BY_USER	12
				/* Failed, rejected by user */

/* Invitation Flags attribute: bit values */
#define P2P_INVSE_MASK_INVITE_TYPE     0x1
#define P2P_INVSE_JOIN_ACTIVE_GRP      0
#define P2P_INVSE_REINVOKE_PERSIST_GRP 1

BWL_PRE_PACKED_STRUCT struct p2p_channel_se_s {
	uint8	eltId;		/* SE ID: P2P_SEID_STATUS */
	uint8	len[2];		/* SE length not including eltId, len fields */
	uint8	country[3];	/* Country String */
	uint8	band;		/* Regulatory Class (band) */
	uint8	channel;	/* Channel */
} BWL_POST_PACKED_STRUCT;
typedef struct p2p_channel_se_s p2p_channel_se_t;

/* The Listen Channel and Operating Channel attributes have the same data */
typedef p2p_channel_se_t wifi_p2p_listchan_se_t;
typedef p2p_channel_se_t wifi_p2p_opchan_se_t;

/* New, correct name for the P2P Capabilities attribute.  For now the old name
 * is maintained for compatibility with older code.
 */
#define P2P_SEID_P2P_CAPABILITY		P2P_SEID_P2P_INFO
typedef	wifi_p2p_info_se_t wifi_p2p_capability_se_t;

/* WiFi P2P IE's Device Info subelement */
/* This structure obsoletes wifi_p2p_devinfo_se_t in p2p.h */
BWL_PRE_PACKED_STRUCT struct wifi_p2p_device_info_se_s {
	uint8	eltId;			/* SE ID: P2P_SEID_DEVINFO */
	uint8	len[2];			/* SE length not including eltId, len fields */
	uint8	mac[6];			/* P2P Device MAC address */
	uint16	wps_cfg_meths;	/* Config Methods: reg_prototlv.h WPS_CONFMET_* */
	uint8	pri_devtype[8];	/* Primary Device Type */
	uint8	name_type_be[2]; /* friendly name TLV type (big endian) */
	uint8	name_len_be[2]; /* friendly name TLV len (big endian) */
	uint8	name_val[32]; /* friendly name TLV value (big endian) */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_p2p_device_info_se_s wifi_p2p_device_info_se_t;

/* Client Info Descriptor structure within the Group Info SE */
BWL_PRE_PACKED_STRUCT struct wifi_p2p_client_info_desc_s {
	uint8	cid_len;	/* Client Info Descriptor length */
	uint8	p2p_dev_addr[6]; /* P2P Device Address */
	uint8	p2p_int_addr[6]; /* P2P Interface Address */
	uint8	dev_cap_bitmap; /* Device Capability Bitmap */
	uint16	wps_cfg_meths; /* Config Methods: reg_prototlv.h WPS_CONFMET_* */
	uint8	pri_devtype[8];	/* Primary Device Type */
	uint8	num_sec_devs; /* Number of secondary devices */
	uint8	name_type_be[2]; /* friendly name TLV type (big endian) */
	uint8	name_len_be[2]; /* friendly name TLV len (big endian) */
	uint8	name_val[32]; /* friendly name TLV value (big endian) */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_p2p_client_info_desc_s wifi_p2p_client_info_desc_t;

/* WiFi P2P IE subelement: Group Info
 * This structure obsoletes p2p.h's wifi_p2p_grpinfo_se_t
 */
#define P2PAPI_GRPINFO_MAX_CIDS 8
BWL_PRE_PACKED_STRUCT struct wifi_p2p_group_info_se_s {
	uint8	eltId;			/* SE ID: P2P_SEID_GROUP_INFO */
	uint8	len[2];			/* SE length not including eltId, len fields */
	/* Temp: use a fix sized array of client info descriptors.  In the future
	 * this should be a pointer to a dynamically sized and allocated array.
	 */
	uint8	num_clients;
	wifi_p2p_client_info_desc_t client_info[P2PAPI_GRPINFO_MAX_CIDS];
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_p2p_group_info_se_s wifi_p2p_group_info_se_t;

/* WiFi P2P IE subelement: Group ID */
BWL_PRE_PACKED_STRUCT struct wifi_p2p_grpid_se_s {
	uint8	eltId;
	uint8	len[2];
	struct ether_addr	devaddr;		/* P2P Device MAC address */
	uint8	ssid[DOT11_MAX_SSID_LEN+1];	/* SSID */
	uint8	ssid_len;					/* SSID length */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_p2p_grpid_se_s wifi_p2p_grpid_se_t;

/* WiFi P2P IE subelement: Group BSSID */
BWL_PRE_PACKED_STRUCT struct wifi_p2p_grpbssid_se_s {
	uint8	eltId;
	uint8	len[2];
	struct ether_addr	bssid;		/* P2P Group BSSID */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_p2p_grpbssid_se_s wifi_p2p_grpbssid_se_t;

/* WiFi P2P IE subelement: Minor Reason Code */
BWL_PRE_PACKED_STRUCT struct wifi_p2p_minorrc_se_s {
	uint8	eltId;
	uint8	len[2];
	uint8	minor_rc;				/* Minor Reason Code */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_p2p_minorrc_se_s wifi_p2p_minorrc_se_t;

/* WiFi P2P IE subelement: P2P Interface */
BWL_PRE_PACKED_STRUCT struct wifi_p2p_interface_se_s {
	uint8	eltId;
	uint8	len[2];
	struct ether_addr devAddr;		/* P2P Device Address */
	uint8	pia_list_count;			/* P2P Interface Addresses Count */
	struct ether_addr *pia_list;	/* P2P Interface Addresses List */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_p2p_interface_se_s wifi_p2p_interface_se_t;

/* channel list attribute structure is implementation specific */
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
#define P2P_CHANLIST_SE_MAX_ENTRIES 19	/* max # of regulatory classes */
#else
#define P2P_CHANLIST_SE_MAX_ENTRIES 16	/* max # of regulatory classes */
#endif
#define P2P_CHANNELS_MAX_ENTRIES	16	/* max # channels per regulatory class */

/* Channel Entry structure within the Channel List SE */
BWL_PRE_PACKED_STRUCT struct p2p_chanlist_entry_s {
	uint8	band;						/* Regulatory Class (band) */
	uint8	num_channels;				/* # of channels in the channel list */
	uint8	channels[P2P_CHANNELS_MAX_ENTRIES];	/* Channel List */
} BWL_POST_PACKED_STRUCT;
typedef struct p2p_chanlist_entry_s p2p_chanlist_entry_t;

BWL_PRE_PACKED_STRUCT struct p2p_chanlist_s {
	uint8	num_entries;	/* # of channel entries */
	p2p_chanlist_entry_t	entries[P2P_CHANLIST_SE_MAX_ENTRIES];
						/* Channel Entry List */
} BWL_POST_PACKED_STRUCT;
typedef struct p2p_chanlist_s p2p_chanlist_t;

/* WiFi P2P IE subelement: Channel List */
BWL_PRE_PACKED_STRUCT struct p2p_chanlist_se_s {
	uint8	eltId;		/* SE ID: P2P_SEID_STATUS */
	uint8	len[2];		/* SE length not including eltId, len fields */
	uint8	country[3];	/* Country String */
	p2p_chanlist_t chanlist;	/* channel list */
} BWL_POST_PACKED_STRUCT;
typedef struct p2p_chanlist_se_s p2p_chanlist_se_t;

#define P2P_NOA_SE_MAX_DESC 2	/* max for presence request */
BWL_PRE_PACKED_STRUCT struct p2p_noa_se {
	uint8	eltId;		/* Subelement ID */
	uint8	len[2];		/* Length */
	uint8	index;		/* Index */
	uint8	ops_ctw_parms;	/* CTWindow and OppPS Parameters */
	wifi_p2p_noa_desc_t	desc[P2P_NOA_SE_MAX_DESC];	/* NoA Descriptor(s) */
} BWL_POST_PACKED_STRUCT;
typedef struct p2p_noa_se p2p_noa_se_t;

/* WiFi P2P IE subelement: Invitation Flags */
BWL_PRE_PACKED_STRUCT struct wifi_p2p_invflags_se_s {
	uint8	eltId;
	uint8	len[2];
	uint8	inv_flags;
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_p2p_invflags_se_s wifi_p2p_invflags_se_t;

#define P2P_DEV_TYPE_LEN	8
#include <packed_section_end.h>


/* P2P Information Element data decoded from received frames */
typedef struct {
	wifi_p2p_ie_t			p2p_ie;			/* P2P IE */
	wifi_p2p_minorrc_se_t	minorrc_subelt;	/* Minor RC attrib */
	wifi_p2p_status_se_t	status_subelt;	/* Status attrib */
	wifi_p2p_minorrc_se_t	minor_rc_subelt; /* Minor Reason Code attrib */
	wifi_p2p_capability_se_t capability_subelt;	/* P2P Capability attrib */
	wifi_p2p_devid_se_t		devid_subelt;	/* P2P Device ID attrib */
	wifi_p2p_intent_se_t	intent_subelt;	/* GO Intent attrib */
	wifi_p2p_cfg_tmo_se_t	cfg_tmo_subelt;	/* Config Timeout attrib */
	wifi_p2p_listchan_se_t	listen_chan_subelt; /* Listen Channel attrib */
	wifi_p2p_grpbssid_se_t	grp_bssid_subelt; /* P2P Group BSSID attrib */
	wifi_p2p_ext_se_t		extlisten_subelt; /* Extended Listen Timing attr */
	wifi_p2p_intintad_se_t	intintad_subelt; /* Intended P2P I/F addr attrib */
	wifi_p2p_mgbt_se_t		mgbility_subelt; /* Manageability attrib */
	p2p_chanlist_se_t		chanlist_subelt; /* Channel List attrib */
	p2p_noa_se_t			noa_subelt;		/* Notice of Absence attrib */
	wifi_p2p_device_info_se_t devinfo_subelt;	/* Device Info attrib */
	wifi_p2p_group_info_se_t grpinfo_subelt;	/* Group Info attrib */
	wifi_p2p_grpid_se_t		grpid_subelt;	/* P2P Group ID attrib */
	wifi_p2p_interface_se_t	interface_subelt; /* P2P Interface attrib */
	wifi_p2p_opchan_se_t	op_chan_subelt;	/* Operating Channel attrib */
	wifi_p2p_invflags_se_t	invflags_subelt; /* Invitation Flags attrib */

	/* Stores Device Info attrib's Device Name */
	uint8 devinfo_name[BCMP2P_MAX_SSID_LEN + 1];
	uint8 devinfo_name_len;

	/* Stores P2P Interface attrib's P2P Interface Address List.
	 * For now we only store the 1st address from this list.
	 */
	struct ether_addr interface_pia_list[1];
} p2papi_p2p_ie_t;

/* WPS Information Element data extracted from peer's probe response */
typedef struct {
	uint8				wps_version;
	uint8				req_type;
	uint16				cfg_methods;
	uint8				devname[32+1];	/* Device Name attribute */
	uint8				devname_len;
	uint16				devpwd_id;		/* eg. WPS_DEVICEPWDID_PUSH_BTN	*/

	/* Primary Device Type */
	uint16				devtype_cat_id;	/* eg. WPS_DEVICE_TYPE_CAT_TELEPHONE */
	uint16				devtype_subcat_id;
							/* eg. WPS_DEVICE_TYPE_SUB_CAT_PHONE_WM */

	/* Requested Device Type */
	uint16				req_devtype_cat; /* eg. WPS_DEVICE_TYPE_CAT_TELEPHONE */
	uint16				req_subcat; /* eg. WPS_DEVICE_TYPE_SUB_CAT_PHONE_WM */
} p2papi_wps_ie_t;

/* Information about a discovered peer */
typedef struct {
	uint8				ssid[DOT11_MAX_SSID_LEN+1];
	uint8				ssid_len;
	BCMP2P_CHANNEL		listen_channel; 	/* Listen channel */
	BCMP2P_CHANNEL		op_channel; 		/* Operating channel */
	int16				rssi;
	struct ether_addr	mac;
	struct ether_addr	bssid;
	p2papi_p2p_ie_t		p2p_ie;
	bool				is_p2p_group;
	bool				is_persistent_group;
	int16				expiry_count;	/* if 0, delete this entry */
	uint16				wps_device_pwd_id;	/* WPS device password id */
	uint16				wps_cfg_methods;	/* WPS config methods */
	bool				requesting_svc;  /* Requesting service or not */

	/* Peer IE data and size */
	uint8				*ie_data;
	uint32				ie_data_len;

	uint8				grp_ssid[DOT11_MAX_SSID_LEN];
	uint8				grp_ssid_len;
} p2papi_peer_info_t;

/* Max # of discovered peers */
#define P2PAPI_MAX_PEERS 64

/* Max # of connected peers */
#define P2PAPI_MAX_CONNECTED_PEERS BCMP2P_MAX_SOFTAP_CLIENTS

/* Connection states */
typedef enum {
	P2PAPI_ST_IDLE,				/* Idle, no connection pending */

	/* Negotiation started, waiting for common channel to tx or rx Neg Req */
	P2PAPI_ST_START_NEG,
	/* Negotiation Request sent, waiting to rx Neg Response */
	P2PAPI_ST_NEG_REQ_SENT,
	/* Negotiation Request received, waiting for app to accept or reject */
	P2PAPI_ST_NEG_REQ_RECVD,
	/* Negotiation accept response sent, waiting to rx Neg Confirm */
	P2PAPI_ST_NEG_RSP_SENT,
	/* Negotiation confirmed - Neg Confirm received or sent */
	P2PAPI_ST_NEG_CONFIRMED,

	P2PAPI_ST_WPS_HANDSHAKE,	/* In the WPS handshake */
	P2PAPI_ST_CONNECTING,		/* Setting up the final secure connection */
	P2PAPI_ST_CONNECTED,		/* Secure connection established */
} p2papi_state_t;

#define P2PAPI_HDL_MAGIC_NUMBER 0xcbc0 /* 52160 decimal */

#define P2PAPI_IOCTL_BUF_SIZE WLC_IOCTL_MAXLEN
#define P2PAPI_IOCTL_BUF_SIZE2 WLC_IOCTL_MEDLEN
#define P2PAPI_IOCTL_BUF(p2pHdl) p2pHdl->bufstruct_wlu.bufdata
#define P2PAPI_IOCTL_BUF2(p2pHdl) p2pHdl->bufstruct_wlu2.bufdata

#define P2PAPI_SCANRESULT_BUF_SIZE	40960	/* 20k in bytes */
#define P2PAPI_SCANRESULT_BUF(p2pHdl) p2pHdl->bufstruct_scanresult.bufdata

#define P2PAPI_SCANPARAM_BUF_SIZE	512
#define P2PAPI_SCANPARAM_BUF(p2pHdl) p2pHdl->bufstruct_scanparam.bufdata


/* Enumeration of the usages of the BSSCFGs used by the P2P Library.  Do not
 * confuse this with a bsscfg index.  This value is an index into the
 * saved_ie[] array of structures which in turn contains a bsscfg index field.
 */
typedef enum {
	P2PAPI_BSSCFG_PRIMARY, /* maps to driver's primary bsscfg */
	P2PAPI_BSSCFG_DEVICE, /* maps to driver's P2P device discovery bsscfg */
	P2PAPI_BSSCFG_CONNECTION, /* maps to driver's P2P connection bsscfg */
	P2PAPI_BSSCFG_MAX
} p2papi_bsscfg_type_t;

typedef struct p2papi_custom_ie_s {
	uint16 ie_buf_len;
	uint8 *ie_buf;
} p2papi_custom_ie_t;

/* Structure to hold all saved P2P and WPS IEs for a BSSCFG */
typedef struct p2papi_saved_ie_s {
	/* BSSCFG index that this set of IEs applies to */
	int		ie_bsscfg_idx;

	/* P2P IEs */
	uint8	*probreq_p2p_ie_buf;
	int		probreq_p2p_ie_len;
	uint8	*probrsp_p2p_ie_buf;
	int		probrsp_p2p_ie_len;
	uint8	*beacon_p2p_ie_buf;
	int		beacon_p2p_ie_len;
	uint8	*assocreq_p2p_ie_buf;
	int		assocreq_p2p_ie_len;
	uint8	*assocrsp_p2p_ie_buf;
	int		assocrsp_p2p_ie_len;

	/* WPS IEs */
	uint8	*probreq_wps_ie_buf;
	int		probreq_wps_ie_len;
	uint8	*probrsp_wps_ie_buf;
	int		probrsp_wps_ie_len;
	uint8	*beacon_wps_ie_buf;
	int		beacon_wps_ie_len;
	uint8	*assocreq_wps_ie_buf;
	int		assocreq_wps_ie_len;
	uint8	*assocrsp_wps_ie_buf;
	int		assocrsp_wps_ie_len;

	/* CUSTOM_IE */
	uint8	*probreq_custom_ie_buf;
	int		probreq_custom_ie_len;
	uint8	*probrsp_custom_ie_buf;
	int		probrsp_custom_ie_len;
	uint8	*beacon_custom_ie_buf;
	int		beacon_custom_ie_len;
	uint8	*assocreq_custom_ie_buf;
	int		assocreq_custom_ie_len;
	uint8	*assocrsp_custom_ie_buf;
	int		assocrsp_custom_ie_len;

} p2papi_saved_ie_t;

/* Callback fn type for handling received non-P2P action frames */
struct p2papi_instance_s;

#ifndef SOFTAP_ONLY
/* service discovery */
typedef struct p2plib_sd_s {
	bool is_service_discovery;		/* enable capabilities */
	uint8 dialog_token;				/* dialog_token */
	uint8 fragment_id;				/* fragment id */
	uint8 *svc_req_entries;			/* BCMP2P_SVC_LIST type */
	BCMP2P_SVC_LIST	*resp_list;		/* dynamic buffer for service response */
	BCMP2P_SVC_ENTRY *curr_entry;	/* current entry to send */
	uint32 num_entries;				/* remaining number of entries to send */
	bool sending_sd_af_piggyback;	/* tell if the sd af is being sent */
	BCMP2P_SERVICE_DISCOVERY_PARAM notify_params;	/* notification */
} p2plib_sd_t;

/* provision discovery */
typedef struct p2papi_pd_s {
	uint8				req_dialog_token;	/* request transaction ID */
	bool				response_received;	/* response received */
	uint8				rsp_dialog_token;	/* response transaction ID */
	uint16				config_methods;		/* config methods attribute */
	BCMP2P_UINT8		ssid[BCMP2P_MAX_SSID_LEN + 1];	/* SSID of peer GO */
	BCMP2P_UINT32		ssid_len;			/* SSID length of peer GO */
	BCMP2P_CHANNEL		channel;			/* send channel */
	struct ether_addr	peer_mac;			/* peer MAC address */
	/* null-terminated friendly name */
	BCMP2P_UINT8 device_name[BCMP2P_MAX_SSID_LEN + 1];
} p2papi_pd_t;

/* presence request/response */
typedef struct p2papi_presence_s {
	uint8					dialog_token;	/* transaction ID */
	BCMP2P_PRESENCE_PARAM 	notify_params;	/* notification parameters */
} p2papi_presence_t;

/* extended listen timing */
typedef struct p2papi_extended_listen_s {
	bool	enabled;	/* enable extended listen */
	uint32	period;		/* availability period */
	uint32	interval;	/* interval between start of periods */
} p2papi_extended_listen_t;
#endif /* not  SOFTAP_ONLY */

/* At a GO, this stores client Info obtained from client ASSOC_REQs */
struct p2papi_client_info_s {
	uint8	cid_len;			/* Client Info Descriptor length */
	BCMP2P_BOOL is_p2p_client;	/* Whether client is P2P or legacy */
	uint8	p2p_dev_addr[6];	/* P2P Device Address */
	uint8	p2p_int_addr[6];	/* P2P Interface Address */
	uint8	dev_cap_bitmap;		/* Device Capability Bitmap */
	uint16	namelen;			/* friendly name length */
	wifi_p2p_device_info_se_t devinfo;

	/* Buffer to hold client custom IE */
	uint8	ie_data[2048];		/* Maximum vendor IE data size */
	uint16	ie_data_len;
};
typedef struct p2papi_client_info_s p2papi_client_info_t;

/*
 * P2P Library instance data.
 * This should be replaced with an opaque pointer.  The actual structure
 * definition should be moved to p2plib_int.h.
 */
typedef struct p2papi_instance_s {
	uint32			magic;			/* Magic # to verify our struct type */
	void			*osl_hdl;

	/* ctx handle for external auth/supp */
	void 			*ext_auth_supp_ctx;

	/* Wireless network interface name (virtual) */
	char			if_name[100];
	/* Wireless network interface name (physical), needed for WPS */
	char			primary_if_name[100];

	/* null-terminated P2P IE country code from the WL driver */
	char			country[WLC_CNTRY_BUF_SZ];

	/* channel list from driver */
	p2p_chanlist_t channel_list;

	/* channel list with DFS channels removed */
	p2p_chanlist_t non_dfs_channel_list;

	/* channel list negotiated */
	p2p_chanlist_t negotiated_channel_list;

	/* user configured channel list */
	p2p_chanlist_t *user_channel_list;

	/* channels scanned during join */
	int 			num_join_chanspec;
	chanspec_t		join_chanspec[WL_NUMCHANSPECS];

	/* P2P Discovery parameters */
	uint32			scan_duration_ms;	/* Duration of initial discovery scan */
	int				discovery_timeout;	/* Discovery timeout in seconds */
	uint32			join_timeout_secs;	/* Association timeout */
	BCMP2P_CHANNEL	listen_channel;		/* Our P2P listen channel */
	unsigned char	fname_ssid[DOT11_MAX_SSID_LEN+1]; /* Our friendly name */
	uint8			fname_ssid_len;
	uint8			req_dev_type;		/* Requested Device Type */
	uint8			req_dev_subcat;		/* Requested Device Sub-category */
	/* Whether to run P2P Discovery in listen-only mode */
	BCMP2P_BOOL		is_listen_only;
	/* Whether to skip the initial 802.11 scan for P2P Groups */
	BCMP2P_BOOL		skip_group_scan;

	/* High level flag to indicate whether to suspend p2p discovery search or not.
	 * It will overwrite low level discovery resuming reacting to TX events
	 */
	bool			suspend_disc_search;

	bool			enable_p2p;		/* 1=P2P enabled, 0=SoftAP only */
	struct ether_addr	p2p_dev_addr;	/* Our P2P Device Address */

	/* Default parameter values */
	uint32			default_discovery_timeout_secs;
	uint32			default_scan_duration_ms;
	BCMP2P_CHANNEL	default_listen_channel;
	char			*default_friendly_name;
	uint32			cancel_discovery_timeout_ms;
	uint32			cancel_connect_timeout_ms;

	/* Flags to force acting only as a STA or AP in future P2P connections */
	bool			act_only_as_sta;
	bool			act_only_as_ap;

	/* Discovered peers list */
	p2papi_peer_info_t	peers[P2PAPI_MAX_PEERS];
	int32				peer_count;

	/* Info on the peer we want to connect to */
	char				peer_ssid[DOT11_MAX_SSID_LEN+1];
	uint8				peer_ssid_len;
	struct ether_addr	peer_dev_addr;		/* P2P Device Address */
	struct ether_addr	peer_int_addr;		/* P2P Interface Address */
	uint8				peer_intent;
	uint16				peer_go_cfg_tmo_ms;	/* GO Configuration Timeout */
	uint16				peer_cl_cfg_tmo_ms;	/* Client Configuration Timeout */
	BCMP2P_CHANNEL		peer_channel;		/* GON Listen/Operating channel */
	BCMP2P_WPS_DEVICE_PWD_ID peer_gon_device_pwd_id;	/* obtained from GON req */
	uint8				peer_assocrsp_ie_data[2048];
	uint16				peer_assocrsp_ie_len;

	/* DHCP server configuration parameters */
	bool				enable_dhcp;	/* Enable DHCP server or not */
	unsigned long		dhcp_subnet;	/* eg. 0xc0a81000 for 192.168.16.0 */
	unsigned char		dhcp_start_ip;	/* eg. 100 for 192.168.16.100 */
	unsigned char		dhcp_end_ip;	/* eg. 200 for 192.168.16.200 */

	/* WPS configuration parameters */
	BCMP2P_WPS_DEVICE_PWD_ID wps_device_pwd_id;	/* used during GON */
	uint8				pri_dev_type;	/* Primary Device Type */
	uint8				pri_dev_subcat;	/* Primary Device Sub-category */
	BCMP2P_BOOL			disable_pbc_overlap; /* disable PBC overlap detect */

	/* Set this to TRUE to cancel a p2papi_discover() in progress */
	bool			cancel_discovery;
	/* Set this to TRUE to cancel a p2papi_link_create() in progress */
	bool			cancel_link_create;
	/* Set this to TRUE to cancel a p2papi_group_owner_create() in progress */
	bool			cancel_group_create;

	/* State */
	bool			is_discovering;	/* Whether discovery is actively running */
	bool			is_connecting;
	bool			is_connected;
	bool			is_connection_secured;
	bool			disconnect_detected;
	bool			is_provisioning;
	bool			is_wps_enrolling;
	bool			is_wps_enrolling_old;
	bool			is_raw_rx_mgr_running;
	bool			is_disconnecting;
	BCMP2P_BOOL     is_in_discovery_disable;
	BCMP2P_BOOL		is_in_softap_cleanup;
	bool			is_ap;			/* Whether acting as an AP or STA */
	bool			is_p2p_group;	/* Whether we are a P2P Group Owner */
	p2papi_state_t	conn_state;
	bool			dhcp_on;
	/* Whether P2P is supported in the driver */
	bool			is_p2p_supported;
	/* Whether P2P discovery is enabled in the driver */
	bool			is_p2p_discovery_on;
	/* Whether P2P Discovery's Search state active scanning is enabled */
	BCMP2P_BOOL		discovery_search_enabled;
	/* WL driver's P2P discovery state */
	uint8			wl_p2p_state;


	/* Fields specific to a device acting as a P2P Group Owner.
	 * In client devices these fields should all have values of zero.
	 */

	/* List of connected peers */
	struct ether_addr	assoclist[P2PAPI_MAX_CONNECTED_PEERS];
	int32			assoclist_count;

	/* Stores recent changes detected in the list of connected peers */
	struct ether_addr	disassoc_sta_mac;
	int32			disassoc_sta_count;
	struct ether_addr	assoc_sta_mac;
	int32			assoc_sta_count;

	/* Client Info for our connected P2P clients */
	p2papi_client_info_t client_list[P2PAPI_MAX_CONNECTED_PEERS];
	int32			client_list_count;

	/* Device Discoverability Request data */
	uint8			tx_discb_dialog_token;	/* tx discb req dialog token */
	struct ether_addr	rx_discb_requestor;	/* source device */
	struct ether_addr	rx_discb_client;	/* target client */
	uint8 			rx_discb_dialog_token;	/* rx discb req dialog token */

	/* Our WPS registrar enrollment window duration */
	int				wps_auto_close_secs;
	/* WPS Registration Manager data */
	BCMP2P_BOOL		is_wpsreg_mgr_running;
	struct ether_addr	wpsreg_enrollee_mac;	/* MAC addr of STA to enroll */
	/* Memory of the previous enrolled STA. tick_count=0 means empty. */
	struct ether_addr	enrolled_sta_mac;

#ifndef SOFTAP_ONLY
	/* P2P Invitation data */
	uint8		inv_dialog_token;	/* transaction ID */
	BCMP2P_INVITE_PARAM	invite_req;
	BCMP2P_INVITE_PARAM	invite_rsp;
#endif /* not  SOFTAP_ONLY */

	/* Whether we have Persistent Group capability.  This is advertised in our
	 * P2P IE's Group Capabilities Bitmap's attribute's Persistent Group bit.
	 */
	BCMP2P_BOOL	persistent_grp;

	/* Whether we are currently in a Persistent Group */
	BCMP2P_BOOL	in_persist_grp;

	/* enable capabilities */
	BCMP2P_BOOL	is_intra_bss;
	BCMP2P_BOOL	is_concurrent;
	BCMP2P_BOOL	is_invitation;
	BCMP2P_BOOL	is_client_discovery;

#ifndef SOFTAP_ONLY
	/* service discovery */
	p2plib_sd_t sd;

	/* provision discovery */
	p2papi_pd_t pd;

	/* presence request/response */
	p2papi_presence_t presence;

	/* extended listen timing */
	p2papi_extended_listen_t extended_listen;
#endif /* not  SOFTAP_ONLY */

	/* Group Owner Negotiation data */
	uint8		gon_dialog_token;	/* GO negotiation transaction ID */
	bool		chsync_discov_enabled; /* P2P discovery enabled for chan sync */
	BCMP2P_CHANNEL	gon_channel;		/* GO negotiation channel */
	BCMP2P_CHANNEL	gon_peer_listen_channel; /* Requestor peer's listen channel */
	bool		gon_peer_wants_persist_grp;	/* Peer wants a persistent group */
	uint8		intent;			/* Our GO negotiation master intent */
	/* Tie breaker bit value to use in the next GONreq we will send */
	BCMP2P_BOOL	tx_tie_breaker;
	/* Tie breaker bit value in the previous received GONreq */
	BCMP2P_BOOL	rx_tie_breaker;
	/* GON result notification status code */
	BCMP2P_NOTIFICATION_CODE gon_notif;

	/* GON action frame to tx after syncing channels with the peer */
	wl_af_params_t		*pending_tx_act_frm;
	struct ether_addr	pending_tx_dst_addr;
	BCMP2P_CHANNEL			pending_tx_dst_listen_chan;
	BCMP2P_AFTX_CALLBACK	pending_tx_complete_cb;
	p2papi_aftx_instance_t** pending_tx_aftx_hdlp;
	const char*		pending_tx_dbg_name;

	struct ether_addr	af_last_src_mac;
	uint32		sending_af_pktid;

	/* SoftAP configuration settings */
	BCMP2P_CONFIG	ap_config;

	/* WPS connection security credentials */
	brcm_wpscli_nw_settings	credentials;

	/* Store passphrase for supporting legacy clients */
	char		passphrase[WSEC_MAX_PSK_LEN + 1];

	/* Whether we have already applied security to our soft AP */
	bool			ap_security_applied;

	/* Whether soft AP is up and ready for STAs to connect */
	bool			ap_ready;

	/* P2P Group Operating Channel */
	BCMP2P_CHANNEL	op_channel;
#ifdef BCM_P2P_OPTEXT
    BCMP2P_BOOL     opch_force;
    BCMP2P_CHANNEL      opch_force_store;
    BCMP2P_BOOL     opch_high;
#endif

	/* BSSCFG indices for our discovery and connection BSSCFGs */
	int				bssidx[P2PAPI_BSSCFG_MAX];

	/* Configuration option to make our P2P Interface Address the same as
	 * our P2P Device Address.
	 */
	bool use_same_int_dev_addrs;

	/* Use WPS in the current connection */
	BCMP2P_BOOL use_wps;

	/* P2P managed device */
	bool is_managed_device;

	/* P2P connection BSSCFG information */
	struct ether_addr conn_ifaddr;	/* Our P2P Interface Address */

#ifdef WIN32
	/* On Windows, the interface name is a null-terminated GUID string */
	char		conn_ifname[40];	/* BSSCFG's ifname */
#else
	char		conn_ifname[BCM_MSG_IFNAME_MAX];	/* BSSCFG's ifname */
#endif

	/* Is waiting for WLC_E_IF resulting from connection BSSCFG creation */
	BCMP2P_BOOL	conn_bsscfg_create_ack_wait;

	/* Default BSSCFG index when no P2P discovery or connection BSSCFG exists */
	int				default_bsscfg_idx;

	/* DHCP-server related fields that are only used on the AP peer */
	void			*dhcpd_hdl;	/* DHCP server handle */

	/* Action Frame Transmit */
	p2papi_aftx_instance_t	*provdis_aftx_hdl;	/* Provision Discovery AF tx hdl */
	p2papi_aftx_instance_t	*gon_aftx_hdl;		/* GO Negotiation AF tx hdl */
	p2papi_aftx_instance_t	*invite_aftx_hdl;	/* Invite AF tx hdl */
	p2papi_aftx_instance_t	*presence_aftx_hdl;	/* Invite AF tx hdl */
	p2papi_aftx_instance_t	*discb_aftx_hdl;	/* Device Discoverabilty AF tx hdl */
	p2papi_aftx_instance_t	*sd_aftx_hdl;		/* Service Discovery AF tx hdl */
	BCMP2P_UINT32	af_tx_max_retries;
	BCMP2P_UINT32	af_tx_retry_ms;

	/* Warning status generated by some internal operations.  Storing it
	 * here allows the status to be propagated up to the top level APIs
	 * where they can choose to return it to the application.
	 */
	BCMP2P_STATUS	warning;

	/* Allow/Deny MAC filter */

	/* Previous rx action frame key fields, for duplicate rx frame detection */
	uint8				prev_rx_frame_subtype;
	uint8				prev_rx_dialog_token;
	struct ether_addr	prev_rx_src_mac;

	/* Event masks to filter which events the WL driver will send up */
	uint8 orig_event_mask[WL_EVENTING_MASK_LEN]; /* original event mask */
	uint8 event_mask[WL_EVENTING_MASK_LEN];		/* adds our events */
	uint8 event_mask_prb[WL_EVENTING_MASK_LEN];	/* adds our events + probreq */

	/* Copies of the P2P and WPS IEs currently applied to the WL driver.
	 * These need to be saved for later deletion of the IEs.
	 */
	p2papi_saved_ie_t	saved_ie[P2PAPI_BSSCFG_MAX];

	/* dword aligned WL driver ioctl buffers */
	union {
		uint8 bufdata[P2PAPI_IOCTL_BUF_SIZE];
		uint32 alignme; /* dword align the structure */
	} bufstruct_wlu;
	union {
		uint8 bufdata[P2PAPI_IOCTL_BUF_SIZE2];
		uint32 alignme; /* dword align the structure */
	} bufstruct_wlu2;

	union {
		unsigned char bufdata[P2PAPI_SCANRESULT_BUF_SIZE];
		uint32 alignme; /* dword align the structure */
	} bufstruct_scanresult;
	union {
		unsigned char bufdata[P2PAPI_SCANPARAM_BUF_SIZE];
		uint32 alignme; /* dword align the structure */
	} bufstruct_scanparam;

	/* BCMP2P_SVC_LIST type */
	uint8	*svc_req_entries;
	uint8	sd_dialog_token; /* Current SD dialog token */

	/* Status code of p2p status attribute */
	uint8	status_code;

	/* Minor reason code */
	uint8	minor_rc;

	/* The following allows OSL to overwrite the HSL configuration at build-time and run-time */
	/* run-time option to turn on/off multi-social-channels during P2P discovery scan */
	bool enable_multi_social_channels;

	/* WPS GO Configuration Timeout */
	uint16	peer_wps_go_cfg_tmo_ms;

	/* extra GO Configuration Timeout */
	uint16	extra_peer_go_cfg_tmo_ms;

	/* Parameters for send Provision Discovery Request */
	uint16	max_provdis_retries;
	uint16	provdis_retry_delay_ms;
	uint16	provdis_resp_wait_ms;

	/* The Listen Interval field is used to indicate to the AP how often a
	 * STA in power save mode wakes to listen to Beacon management frames.
	 * Specified in beacons.
	 */
	unsigned int listen_interval;

	/* Timer manager. */
	bcmseclib_timer_mgr_t *timer_mgr;

	/* WPS registrar timer. */
	bcmseclib_timer_t *wps_reg_timer;

	/* WPS PBC timer. */
	bcmseclib_timer_t *wps_pbc_timer;

	/* Custom IE list used during P2P session */
	p2papi_custom_ie_t custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_TOTAL];
	p2papi_custom_ie_t custom_acf_ie[BCMP2P_ACF_IE_FLAG_TOTAL];

	/* Callback function to intercept GON Request to determine whether GON should
	 * continue or fail
	 */
	BCMP2P_GONREQ_CALLBACK gon_req_cb;
#ifdef SECONDARY_DEVICE_TYPE
		uint8 sec_dev_type; 	/* Secondary Device Type */
		uint8 sec_dev_subcat;		/* Secondary Device Sub-category */
		uint32 sec_dev_oui;
#endif
	uint32 maxSPLength;
	uint8  acBE;
	uint8  acBK;
	uint8  acVI;
	uint8  acVO;
} p2papi_instance_t;


/*
 * Public functions that correspond directly to the BcmP2PAPI API
 */


/* Initialize/Uninitialize the API */
extern BCMP2P_STATUS p2papi_init(uint32 version, void* reserved);
extern BCMP2P_STATUS p2papi_uninit(void);

/* Register/Unregister for event notifications */
extern BCMP2P_STATUS p2papi_register_notifications(int notificationType,
	BCMP2P_NOTIFICATION_CALLBACK funcCallback, void *pCallbackContext,
	void *pReserved);
extern BCMP2P_STATUS p2papi_unregister_notifications(void);


/* Open/Close an instance of the API */
BCMP2P_STATUS p2papi_open(char *if_name, char *primary_if_name,
	p2papi_instance_t **instanceHdl);
BCMP2P_STATUS p2papi_close(p2papi_instance_t *hdl);

/* save the bsscfg index */
int p2papi_save_bssidx(struct p2papi_instance_s* hdl, int usage, int bssidx);

#ifndef SOFTAP_ONLY
/* Transmit probe request using discover */
extern BCMP2P_STATUS p2papi_discover_tx_probe_request(p2papi_instance_t *hdl,
	uint32 nprobes, uint32 interval);

/* Discover peers */
extern BCMP2P_STATUS p2papi_discover(p2papi_instance_t *hdl,
	BCMP2P_DISCOVER_PARAM *params);

/* Cancel discovering peers - asynchronous */
BCMP2P_STATUS p2papi_discover_cancel(p2papi_instance_t *hdl);

/* Cancel discovering peers - synchronous */
BCMP2P_STATUS p2papi_discover_cancel_sync(p2papi_instance_t* hdl);

/* Enable the Search state (active scans) in P2P Discovery */
int p2papi_discover_enable_search(p2papi_instance_t* hdl,
	BCMP2P_BOOL search_enable);

/* Get discovery results */
extern BCMP2P_STATUS p2papi_get_discover_result(p2papi_instance_t *hdl,
    bool bPrunedList, PBCMP2P_DISCOVER_ENTRY pBuffer, uint32 buffLength,
    uint32 *numEntries, bool bDuplicateData);

/* This function walk thru each discover-entry in pBuffer (returned via p2papi_get_discover_result)
 * and free the 'ie_data/svc_resp' data associated with each discovery-entry
 */
extern BCMP2P_STATUS p2papi_free_discover_result_data(p2papi_instance_t* hdl,
	PBCMP2P_DISCOVER_ENTRY pBuffer, uint32 numEntries);

extern BCMP2P_STATUS p2papi_get_discover_peer(p2papi_instance_t* hdl,
	struct ether_addr *dev_addr, PBCMP2P_DISCOVER_ENTRY pBuffer);

BCMP2P_STATUS p2papi_get_peer_go_client_list(p2papi_instance_t *hdl,
        BCMP2P_DISCOVER_ENTRY *peer_go,
        BCMP2P_CLIENT_LIST *client_list,
        BCMP2P_UINT32 client_list_len,
        BCMP2P_UINT32 *client_list_count);

/* Get information about a client of a GO in our discovered peers list */
BCMP2P_STATUS p2papi_get_discovered_go_client(p2papi_instance_t *hdl,
	PBCMP2P_DISCOVER_ENTRY go, int client_index,
	struct ether_addr *out_dev_addr);

/* Do the Listen state of the p2p discovery Find phase */
uint32 p2papi_discovery_listen(p2papi_instance_t* hdl, BCMP2P_CHANNEL *channel,
	uint32 duration_ms);

/* Do an 802.11 scan for Group Owners. */
BCMP2P_STATUS
p2papi_discovery_scan(p2papi_instance_t* hdl,
	BCMP2P_INT32 nprobes, BCMP2P_INT32 active_dwell_ms,
	BCMP2P_INT32 num_channels, BCMP2P_UINT16 *channels,
	BCMP2P_UINT32 *out_time_used_ms);


/* Send a Provision Discovery request */
BCMP2P_STATUS
p2papi_send_provdis_req(p2papi_instance_t* hdl,	BCMP2P_UINT32 configMethods,
	BCMP2P_BOOL isPeerGo, uint8 *ssid, int ssid_len,
	BCMP2P_CHANNEL *channel, struct ether_addr *peerMac);

/* Send a Provision Discovery response to accept or reject a previously
 * received PD request.
 */
BCMP2P_STATUS p2papi_send_provdis_rsp(p2papi_instance_t* hdl,
	BCMP2P_UINT32 configMethods);

/* send a provision discovery request on invitation */
BCMP2P_STATUS
p2papi_send_provdis_req_on_invite(p2papi_instance_t* hdl,
	BCMP2P_UINT32 configMethods, uint8 *ssid, int ssid_len,
	BCMP2P_ETHER_ADDR *dstDevAddr, BCMP2P_CHANNEL *channel);

/* Process a received Provision Discovery frame */
int
p2papi_rx_provdis_frame(p2papi_instance_t *hdl,	struct ether_addr *src_mac,
	wifi_p2p_pub_act_frame_t *act_frm, uint32 act_frm_len, BCMP2P_CHANNEL *channel);


/* Generate a random link configuration */
extern BCMP2P_STATUS p2papi_generate_rnd_link_cfg(p2papi_instance_t *hdl,
	PBCMP2P_CONFIG pConfig);

/* Find a peer in our list given its mac address */
extern p2papi_peer_info_t *
p2papi_find_peer(p2papi_instance_t *hdl, uint8 *mac_addr);

/* Determine if we should act as an AP or a STA based on intents, MAC addrs,
 * and whether the peer is a P2P group.
 */
BCMP2P_STATUS p2papi_determine_ap_or_sta(p2papi_instance_t* hdl,
	bool peer_is_p2p_group);

/* Initiate a P2P connection to a peer. (blocking) */
extern BCMP2P_STATUS p2papi_link_create(p2papi_instance_t *hdl, uint32 timeout,
	p2papi_peer_info_t *peer);

BCMP2P_STATUS
p2papi_link_create_to_devaddr(p2papi_instance_t* hdl, uint32 timeout,
	struct ether_addr *peer_dev_addr, BCMP2P_CHANNEL *peer_listen_channel,
	BCMP2P_BOOL is_peer_go, struct ether_addr *peer_int_addr);

/* Associate to an existing P2P Group and start the WPS handshake */
BCMP2P_STATUS p2papi_join_group_with_wps(p2papi_instance_t* hdl,
	struct ether_addr *grp_bssid,
	uint8 *grp_ssid, uint32 grp_ssid_len, struct ether_addr *grp_dev_addr,
	BCMP2P_CHANNEL *grp_op_channel);

/* Associate to an existing P2P Group using credentials */
BCMP2P_STATUS p2papi_join_group_with_credentials(p2papi_instance_t *hdl,
	struct ether_addr *devAddr, BCMP2P_CHANNEL *channel,
	char *ssid, struct ether_addr *bssid,
	brcm_wpscli_authtype authType, brcm_wpscli_encrtype encrType,
	char *key, uint16 wepIndex);

/* Wait for a connected link to become disconnected */
int p2papi_wait_for_disconnect(void *p2pHdl);

/* Get a list of information about connected peer devices. */
BCMP2P_STATUS p2papi_get_peer_info(p2papi_instance_t *hdl,
	BCMP2P_PEER_INFO * pBuffer, uint32 buffLength, uint32 *numEntries);

/* Get a list of IP information about connected peer devices. */
BCMP2P_STATUS p2papi_get_peer_ip_info(p2papi_instance_t *hdl,
	PBCMP2P_PEER_IPINFO pBuffer, uint32 buffLength, uint32 *numEntries);


/* Initialize P2P Discovery (create P2P discovery BSS) */
int p2papi_init_discovery(p2papi_instance_t* hdl);

/* Deinitialize P2P Discovery */
int p2papi_deinit_discovery(p2papi_instance_t* hdl);

/* Enable P2P discovery in the WL driver and become discoverable */
int p2papi_enable_discovery(p2papi_instance_t* hdl);

/* Disable P2P discovery in the WL driver and become undiscoverable */
int p2papi_disable_discovery(p2papi_instance_t* hdl);

/* Check if P2P Discovery is enabled in the WL driver */
bool p2papi_is_discovery_enabled(void* p2pHdl);

/* Free IE data of discovered peers */
void p2papi_reset_peer_ie_data(p2papi_instance_t* hdl);

/* Process an incoming connection */
BCMP2P_STATUS p2papi_process_incoming_conn(p2papi_instance_t* hdl,
    int timeout_sec);

/*  Find out if this p2plib instance is in the discovering state */
BCMP2P_BOOL p2papi_is_discovering(p2papi_instance_t *hdl);

/*  Find out if this p2plib instance is in a listen-only discovery state */
BCMP2P_BOOL p2papi_is_listen_only(p2papi_instance_t* hdl);

/*  Find out if this p2plib instance is in the connecting state */
BCMP2P_BOOL p2papi_is_connecting(p2papi_instance_t *hdl);

/*  Find out if this p2plib instance is connected as a STA/non-group owner */
BCMP2P_BOOL p2papi_is_sta(p2papi_instance_t *hdl);

/*  Find out if this p2plib instance is connected as a AP/group owner */
BCMP2P_BOOL p2papi_is_ap(p2papi_instance_t *hdl);

/* Link teardown or link create cancel */
BCMP2P_STATUS p2papi_teardown(p2papi_instance_t *hdl);

bool p2papi_find_channel(BCMP2P_CHANNEL *channel, p2p_chanlist_t *chanlist);
bool p2papi_select_channel(BCMP2P_CHANNEL *channel, p2p_chanlist_t *chanlist);

#endif /* not  SOFTAP_ONLY */

/* refresh IEs based on updated configuration */
void p2papi_refresh_ies(p2papi_instance_t* hdl);

/* Set our link security configuration */
BCMP2P_STATUS p2papi_save_link_config(p2papi_instance_t* hdl, BCMP2P_CONFIG *pConfig,
	uint8 *ssid);

/* Set or update the WPA key */
BCMP2P_STATUS p2papi_save_wpa_key(p2papi_instance_t* hdl, char *key, char *passphrase);

/* Get WPS pin or pbc mode */
BCMP2P_BOOL p2papi_is_wps_pin_mode(p2papi_instance_t* hdl);

/* Set or update the WPS PIN in our link configuration. */
BCMP2P_STATUS p2papi_save_wps_pin(p2papi_instance_t* hdl, char *pin);

/* Create a P2P Group, acting as the Group Owner */
BCMP2P_STATUS p2papi_group_create(p2papi_instance_t* hdl, uint8 *ssid,
	bool bAutoRestartWPS);

/* End a P2P Group */
BCMP2P_STATUS p2papi_group_cancel(p2papi_instance_t* hdl);

/* Check if we are acting as an AP and the soft AP is enabled */
BCMP2P_BOOL p2papi_is_softap_on(p2papi_instance_t *hdl);

/* Check if we are acting as an AP and the soft AP is ready for use */
BCMP2P_BOOL p2papi_is_softap_ready(p2papi_instance_t* hdl);

/* Enable/Disable the DHCP server */
BCMP2P_STATUS p2papi_dhcp_enable(p2papi_instance_t* hdl, BCMP2P_BOOL on_off);

/* Check if the DHCP server is on (running) or off */
BCMP2P_BOOL p2papi_is_dhcp_on(p2papi_instance_t *hdl);


/* Enable/Disable P2P functionality for a Soft AP */
void p2papi_enable_p2p(p2papi_instance_t* hdl, BCMP2P_BOOL on_off);

/* Enable/Disable WPS functionality for a Soft AP.
 * When enabled, the WPS IE is added to beacons.
 */
void p2papi_enable_wps(p2papi_instance_t* hdl, BCMP2P_BOOL on_off);

/* Open/Close the WPS registrar enrollment window on a Soft AP.
 * This is only meaningful if WPS has been previously enabled.
 */
void p2papi_open_wpsreg_window(p2papi_instance_t* hdl, int auto_close_secs);
void p2papi_close_wpsreg_window(p2papi_instance_t* hdl);
BCMP2P_BOOL p2papi_is_wpsreg_window_open(p2papi_instance_t* hdl);

/*
*  Set WPS use version 1
*/
BCMP2P_STATUS p2papi_set_wps_use_ver_1(bool use_wps_ver_1);

/* Deauthenticate a STA */
BCMP2P_STATUS p2papi_deauth_sta(p2papi_instance_t* hdl, unsigned char* sta_mac);


/* Get a list of associated STAs */
BCMP2P_STATUS p2papi_get_assoclist(p2papi_instance_t* hdl,
	unsigned int in_maclist_max, struct ether_addr *maclist,
	unsigned int *out_maclist_count);

/* Get the current operating channel number */
BCMP2P_STATUS p2papi_get_channel(p2papi_instance_t* hdl,
	BCMP2P_CHANNEL *channel);

/* Get the SoftAP's IP address */
BCMP2P_STATUS p2papi_get_ip_addr(p2papi_instance_t* hdl,
	BCMP2P_IP_ADDR *out_ipaddr, BCMP2P_IP_ADDR *out_netmask);


/* Get the current MAC filter list and filter mode */
BCMP2P_STATUS p2papi_set_maclist_mode(p2papi_instance_t* hdl,
	BCMP2P_MAC_FILTER_MODE mode);

/* Set the MAC filter's MAC address list */
BCMP2P_STATUS p2papi_set_maclist(p2papi_instance_t* hdl,
	BCMP2P_ETHER_ADDR *macList, BCMP2P_UINT32 macListCount);

/* Get the current MAC filter list and filter mode */
BCMP2P_STATUS p2papi_get_maclist(p2papi_instance_t* hdl,
	BCMP2P_UINT32 macListMax, BCMP2P_ETHER_ADDR *macList,
	BCMP2P_UINT32 *macListCount, BCMP2P_MAC_FILTER_MODE *mode);

/* Generate our P2P Device Address and P2P Interface Address from our primary
 * MAC address.
 */
void p2papi_generate_bss_mac(bool same_int_dev_addrs,
	struct ether_addr *in_primary_mac,
	struct ether_addr *out_dev_addr, struct ether_addr *out_int_addr);

/* Get the OS network interface name of the connected P2P connection. */
char* p2papi_get_netif_name(p2papi_instance_t* hdl);

/* Get our P2P Device Address */
struct ether_addr* p2papi_get_p2p_dev_addr(void *handle);

/* Get our P2P Interface Address */
struct ether_addr* p2papi_get_p2p_int_addr(void *handle);

/* Get our randomly generated P2P Group Owner name */
char* p2papi_get_go_name(p2papi_instance_t* hdl);

/* Get credentials currently in use. */
BCMP2P_STATUS p2papi_get_go_credentials(p2papi_instance_t* hdl,
	BCMP2P_UINT8* outSSID, BCMP2P_UINT8* outKeyWPA,
	BCMP2P_UINT8* outPassphrase);

/* Get the P2P Device Address of the GO we are connected to */
struct ether_addr* p2papi_get_go_dev_addr(p2papi_instance_t* hdl);

/* Enable persistent capability */
BCMP2P_STATUS p2papi_enable_persistent(p2papi_instance_t* hdl,
	BCMP2P_BOOL enable);

/* Test if persistent capability is enabled */
BCMP2P_BOOL p2papi_is_persistent_enabled(p2papi_instance_t* hdl);

/* Whether we are in a persistent group */
BCMP2P_BOOL p2papi_in_persistent_group(p2papi_instance_t* hdl);

/*
 * Internal functions.  These should be moved to p2plib_int.h.
 */

#if P2PAPI_ENABLE_WPS
/* Main body of the WPS registrar enrollment thread */
void p2papi_start_wpsreg_mgr(void* p2papi_hdl);

/* Do OS-independent shutdown of the wpsreg mgr. */
void p2papi_shutdown_wpsreg_mgr(p2papi_instance_t* hdl);
#endif /* P2PAPI_ENABLE_WPS */


/* Functions to register OSL replacer functions for selected parts of the
 * BcmP2PAPI.
 *
 * An OSL's p2papi_osl_init() can call these APIs to register replacer fns.
 * The replacer fns can implement additional OS-specific policies such as
 * thread creation and usage, then calls the core code's p2papi_xxx() fns
 * to do most of the work.
 */

#ifndef SOFTAP_ONLY
/* BCMP2PDiscover override function type.
 * This must have exactly the same parameters as BCMP2PDiscover().
 */
typedef BCMP2P_STATUS(*BCMP2P_DISCOVER_OVERRIDE)(BCMP2PHandle p2pHandle,
	PBCMP2P_DISCOVER_PARAM pDiscoverParams);

/* Register an override fn for BCMP2PDiscover() */
BCMP2P_STATUS p2papi_register_discover_override(
	BCMP2P_DISCOVER_OVERRIDE funcOverride);


/* BCMP2PCancelDiscover override function type.
 * This must have exactly the same parameters as BCMP2PCancelDiscover().
 */
typedef BCMP2P_STATUS(*BCMP2P_CANCEL_DISCOVER_OVERRIDE)(BCMP2PHandle p2pHandle);

/* Register an override fn for BCMP2PCancelDiscover() */
BCMP2P_STATUS p2papi_register_cancel_discover_override(
	BCMP2P_CANCEL_DISCOVER_OVERRIDE funcOverride);


/* BCMP2PCreateLink override function type.
 * This must have exactly the same parameters as BCMP2PCreateLink().
 */
typedef BCMP2P_STATUS(*BCMP2P_CREATE_LINK_OVERRIDE)(BCMP2PHandle p2pHandle,
	PBCMP2P_DISCOVER_ENTRY pPeerInfo, unsigned int timeout);
typedef BCMP2P_STATUS(*BCMP2P_CREATE_LINK_DEVADDR_OVERRIDE)
	(BCMP2PHandle p2pHandle, BCMP2P_ETHER_ADDR *peerDevAddr,
	BCMP2P_CHANNEL *peerListenChannel, BCMP2P_BOOL isPeerGo,
	BCMP2P_ETHER_ADDR *peerIntAddr,	unsigned int timeout);

/* Register an override fn for BCMP2PCreateLink() */
BCMP2P_STATUS p2papi_register_create_link_override(
	BCMP2P_CREATE_LINK_OVERRIDE funcOverride,
	BCMP2P_CREATE_LINK_DEVADDR_OVERRIDE funcOverride2);


/* BCMP2PCancelCreateLink override function type.
 * This must have exactly the same parameters as BCMP2PCancelCreateLink().
 */
typedef BCMP2P_STATUS(*BCMP2P_CANCEL_CREATE_LINK_OVERRIDE)(BCMP2PHandle p2pHandle);

/* Register an override fn for BCMP2PCancelCreateLink() */
BCMP2P_STATUS p2papi_register_cancel_create_link_override(
	BCMP2P_CANCEL_CREATE_LINK_OVERRIDE funcOverride);


/* BCMP2PProcessIncomingConnection override function type.
 * This must have exactly the same parameters as
 * BCMP2PProcessIncomingConnection().
 */
typedef BCMP2P_STATUS(*BCMP2P_PROCESS_INCOMING_OVERRIDE)(
	BCMP2PHandle p2pHandle, BCMP2P_UINT32 timeout_secs);

/* Register an override fn for BCMP2PProcessIncomingConnection() */
BCMP2P_STATUS p2papi_register_process_incoming_override(
	BCMP2P_PROCESS_INCOMING_OVERRIDE funcOverride);


/* BCMP2PAcceptNegotiation override function type.
 * This must have exactly the same parameters as BCMP2PAcceptNegotiation().
 */
typedef BCMP2P_STATUS(*BCMP2P_ACCEPT_OVERRIDE)(BCMP2PHandle p2pHandle,
	PBCMP2P_DISCOVER_ENTRY pPeerInfo);

/* Register an override fn for BCMP2PAcceptNegotiation() */
BCMP2P_STATUS p2papi_register_accept_override(
	BCMP2P_ACCEPT_OVERRIDE funcOverride);

#endif /* SOFTAP_ONLY */

/* BCMP2PCreateGroup override function type.
 * This must have exactly the same parameters as BCMP2PCreateGroup().
 */
typedef BCMP2P_STATUS(*BCMP2P_CREATE_GROUP_OVERRIDE)(BCMP2PHandle p2pHandle,
	uint8 *ssid, bool bAutoRestartWPS);

/* Register an override fn for BCMP2PCreateGroup() */
BCMP2P_STATUS p2papi_register_create_group_override(
	BCMP2P_CREATE_GROUP_OVERRIDE funcOverride);


/* BCMP2PCancelCreateGroup override function type.
 * This must have exactly the same parameters as BCMP2PCancelCreateGroup().
 */
typedef BCMP2P_STATUS(*BCMP2P_CANCEL_CREATE_GROUP_OVERRIDE)(BCMP2PHandle p2pHandle);

/* Register an override fn for BCMP2PCancelCreateGroup() */
BCMP2P_STATUS p2papi_register_cancel_create_group_override(
	BCMP2P_CANCEL_CREATE_GROUP_OVERRIDE funcOverride);


#ifndef SOFTAP_ONLY
/*
 * Other public functions
 */



/* Get Group Owner Negotiation peer info */
BCMP2P_STATUS p2papi_get_neg_peer_info(p2papi_instance_t *hdl,
	BCMP2P_DISCOVER_ENTRY *peer_info);

/* GO Negotiation FSM: Reset the GO negotiation FSM. */
int p2papi_fsm_reset(p2papi_instance_t* hdl);

/* GO Negotiation FSM: abort anyy GO negotiation in progress. */
void p2papi_fsm_abort(p2papi_instance_t* hdl);

/* GO Negotiation FSM: Start a Group Owner Negotiation */
int p2papi_fsm_start_go_neg(p2papi_instance_t* hdl, struct ether_addr *peer_mac,
	BCMP2P_CHANNEL *peer_listen_channel, bool peer_is_p2p_group);

/* GO Negotiation FSM: Accept/Reject a received GO negotiation request */
BCMP2P_STATUS p2papi_fsm_accept_negotiation(p2papi_instance_t *hdl,
    PBCMP2P_DISCOVER_ENTRY pPeerInfo, uint16 dev_pwd_id);
BCMP2P_STATUS p2papi_fsm_reject_negotiation(p2papi_instance_t* hdl,
	wifi_p2p_pub_act_frame_t *act_frm, uint8 reason,
	PBCMP2P_DISCOVER_ENTRY pPeerInfo, uint16 dev_pwd_id);

/* GO Negotiation FSM: sending a GO Negotiation Request frame */
int p2papi_fsm_tx_go_neg_req(p2papi_instance_t* hdl,
	struct ether_addr *peer_mac, bool send_immed,
	BCMP2P_CHANNEL *peer_listen_channel);

/* GO Negotiation FSM: Process a received GO Negotiation frame */
int p2papi_fsm_rx_go_neg_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel);


/* Send a P2P Invitation Request */
int p2plib_tx_invite_req(p2papi_instance_t* hdl,
	struct ether_addr *dst, BCMP2P_CHANNEL *dst_listen_channel,
	BCMP2P_CHANNEL *op_channel, struct ether_addr *p2p_grp_bssid, uint8 invite_flags,
	struct ether_addr *p2pgrpid_dev_addr, char *p2pgrpid_ssid, int p2pgrpid_ssid_len);
int p2papi_tx_invite_req_from_active_go(p2papi_instance_t* hdl,
	struct ether_addr* dst, BCMP2P_CHANNEL *dst_listen_channel);
int p2papi_tx_invite_req_from_inactive_go(p2papi_instance_t* hdl,
	uint8 *ssid, uint8 ssidLen,
	struct ether_addr* grpid_dev_addr,
	struct ether_addr* dst, BCMP2P_CHANNEL *dst_listen_channel);
int p2papi_tx_invite_req_from_gc(p2papi_instance_t* hdl,
	uint8 *ssid, uint8 ssidLen, struct ether_addr* grpid_dev_addr,
	struct ether_addr* dst, BCMP2P_CHANNEL *dst_listen_channel);

/* Send a P2P Invitation Response */
int
p2papi_tx_invite_rsp(p2papi_instance_t* hdl,
	BCMP2P_INVITE_PARAM *invite_req, BCMP2P_INVITE_RESPONSE response,
	bool isGO);

int
p2papi_rx_invite_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel);

int
p2papi_rx_invite_rsp_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel);


/* Send a Device Discoverability Request */
int p2papi_tx_dev_discb_req(p2papi_instance_t* hdl, struct ether_addr *dest_go,
	uint8 *go_ssid, int go_ssid_len, BCMP2P_CHANNEL *dest_channel,
	struct ether_addr *target_client);

int
p2papi_rx_discb_rsp_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel);

int
p2papi_rx_dev_discb_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel);

int
p2papi_rx_go_discb_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_action_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel);


/* Process a received Wifi action frame */
int
p2papi_process_action_frame(p2papi_instance_t *hdl,
	struct ether_addr *src_mac, wifi_p2p_action_frame_t *frame,
	uint32 frame_nbytes, wl_event_rx_frame_data_t *rxframe_data);

/*
 * return true if the frame can be processed, otherwise, return false
 */
bool p2papi_process_rx_action_frame(p2papi_instance_t *hdl,
	struct ether_addr *src_mac, uint8 *act_frm,
	uint32 act_frm_len, wl_event_rx_frame_data_t *rxframe);
#endif /* SOFTAP_ONLY */

/* Generate random WPS security credentials */
extern void p2papi_wps_gen_rnd_cred(p2papi_instance_t *hdl,
	brcm_wpscli_nw_settings *outCredential);

/*
 * Process a received raw frame to look for WL driver events
 */
void p2papi_process_raw_rx_frame(p2papi_instance_t *p2pHdl, uint8 *frame,
	uint32 frame_bytes);

/* Process a received WL driver event */
void p2papi_rx_wl_event(p2papi_instance_t *hdl, wl_event_msg_t *event,
	void* data, uint32 data_len);

/* Create the static event masks needed by p2papi_enable_driver_events() */
void p2papi_init_driver_event_masks(p2papi_instance_t *hdl);

/* Restore the original event mask in the driver */
void p2papi_deinit_driver_event_masks(p2papi_instance_t *hdl);


/* Enable the reception of selected WLC_E_* driver events needed by
 * p2papi_process_raw_rx_frame()
 */
int p2papi_enable_driver_events(p2papi_instance_t *hdl, bool enab_probe_req);


/* Output a timestamped debug log at the given log level */
void p2papi_log(BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp,
	const char *fmt, ...);

/* Log mac address */
void p2papi_log_mac(const char *heading, struct ether_addr* src_mac);

/*
 * Common code implementations that can be called from OSLs.
 * Do not call these functions from the common code directly.
 */
void p2papi_common_do_notify_cb(p2papi_instance_t* hdl,
	BCMP2P_NOTIFICATION_TYPE type, BCMP2P_NOTIFICATION_CODE code);

int p2papi_common_apply_sta_security(p2papi_instance_t* hdl, char in_ssid[],
	brcm_wpscli_authtype in_authType, brcm_wpscli_encrtype in_encrType,
	char in_nwKey[], uint16 in_wepIndex);

int p2papi_common_apply_ap_security(p2papi_instance_t* hdl, char in_ssid[],
	brcm_wpscli_authtype in_authType, brcm_wpscli_encrtype in_encrType,
	char in_nwKey[], uint16 in_wepIndex);

int p2papi_common_do_sta_join(p2papi_instance_t* hdl, char in_ssid[],
	struct ether_addr *in_bssid);

int p2papi_cleanup_ap_security(p2papi_instance_t* hdl);

/*
 * Power management - presence request
 */
int p2papi_presence_request(p2papi_instance_t* hdl,
	bool isPreferred, uint32 preferredDuration, uint32 preferredInterval,
	bool isAcceptable, uint32 acceptableDuration, uint32 acceptableInterval);

int
p2papi_rx_presence_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_action_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel);

int
p2papi_rx_presence_rsp_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_action_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel);

/*
 * enable/disable extended listen timing
 */
BCMP2P_STATUS
p2papi_extended_listen_timing(p2papi_instance_t* hdl,
	bool enable, uint32 period, uint32 interval);

/* enable/disable persistent capability */
BCMP2P_STATUS p2papi_enable_intra_bss(p2papi_instance_t* hdl,
	BCMP2P_BOOL enable);

/* enable/disable concurrent operation capability */
BCMP2P_STATUS p2papi_enable_concurrent(p2papi_instance_t* hdl,
	BCMP2P_BOOL enable);

/* enable/disable P2P invitation capability */
BCMP2P_STATUS p2papi_enable_invitation(p2papi_instance_t* hdl,
	BCMP2P_BOOL enable);

/* enable/disable service discovery capability */
BCMP2P_STATUS p2papi_enable_service_discovery(p2papi_instance_t* hdl,
	BCMP2P_BOOL enable);

/* enable/disable client discovery capability */
BCMP2P_STATUS p2papi_enable_client_discovery(p2papi_instance_t* hdl,
	BCMP2P_BOOL enable);

/*
 * Set power saving mode
 */
BCMP2P_STATUS
p2papi_set_power_saving_mode(p2papi_instance_t* hdl, int mode);

/*
 * Get power saving mode
 */
BCMP2P_STATUS
p2papi_get_power_saving_mode(p2papi_instance_t* hdl, int *mode);

/*
 * WPS pushbutton
 */
BCMP2P_STATUS
p2papi_push_button(p2papi_instance_t *hdl);
BCMP2P_STATUS
p2papi_stop_pbc_timer(p2papi_instance_t *hdl);
BCMP2P_STATUS
p2papi_start_pbc_timer(p2papi_instance_t *hdl);
BCMP2P_STATUS
p2papi_stop_pbc_timer(p2papi_instance_t *hdl);
BCMP2P_STATUS
p2papi_start_pbc_timer(p2papi_instance_t *hdl);
BCMP2P_STATUS
p2papi_set_push_button(p2papi_instance_t *hdl, BCMP2P_BOOL isPushed);

/*
 * Provisioning to determine if pin/pbc has been activated
 */
BCMP2P_BOOL
p2papi_is_provision(p2papi_instance_t *hdl);
BCMP2P_STATUS
p2papi_set_provision(p2papi_instance_t *hdl);
BCMP2P_STATUS
p2papi_clear_provision(p2papi_instance_t *hdl);

/*
 * Ioctl/iovar functions.
 */
BCMP2P_STATUS p2papi_ioctl_get(p2papi_instance_t* hdl, int cmd, void *buf,
	int len, int bssidx);
BCMP2P_STATUS p2papi_ioctl_set(p2papi_instance_t* hdl, int cmd, void *buf,
	int len, int bssidx);
BCMP2P_STATUS p2papi_iovar_get(p2papi_instance_t* hdl, const char *iovar,
	void *outbuf, int len);
BCMP2P_STATUS p2papi_iovar_set(p2papi_instance_t* hdl, const char *iovar,
	void *param, int paramlen);
BCMP2P_STATUS p2papi_iovar_integer_get(p2papi_instance_t* hdl,
	const char *iovar, int *pval);
BCMP2P_STATUS p2papi_iovar_integer_set(p2papi_instance_t* hdl,
	const char *iovar, int val);
BCMP2P_STATUS p2papi_iovar_buffer_get(p2papi_instance_t* hdl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen);
BCMP2P_STATUS p2papi_iovar_buffer_set(p2papi_instance_t* hdl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen);


/* State machine event handlers. */
void
p2papi_wl_event_handler_discover(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
                                  wl_event_msg_t *event, void* data, uint32 data_len);
void
p2papi_wl_event_handler_negotiate(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
                                  wl_event_msg_t *event, void* data, uint32 data_len);
void
p2papi_wl_event_handler_formation(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
                                  wl_event_msg_t *event, void* data, uint32 data_len);

void
p2papi_wl_event_handler_connect(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
                                  wl_event_msg_t *event, void* data, uint32 data_len);

/* chanspec functions */
char *p2papi_chspec_ntoa(chanspec_t chspec, char *buf);
chanspec_t p2papi_chspec_aton(char *a);
BCMP2P_BOOL p2papi_is_valid_channel(BCMP2P_CHANNEL *channel);
BCMP2P_BOOL p2papi_chspec_to_channel(chanspec_t chspec,	BCMP2P_CHANNEL *channel);
BCMP2P_BOOL p2papi_channel_to_chspec(BCMP2P_CHANNEL *channel, chanspec_t *chspec);
#ifdef BCM_P2P_OPTEXT
BCMP2P_BOOL p2papi_channel_to_high_chspec(p2papi_instance_t *hdl, BCMP2P_CHANNEL *op_channel,
    chanspec_t *chspec);
#endif
BCMP2P_BOOL p2papi_find_channel_class(BCMP2P_UINT32 channel, bool is_40mhz,
	BCMP2P_CHANNEL_CLASS *channel_class);

#ifdef __cplusplus
}
#endif

#endif /* _p2plib_api_h_ */
