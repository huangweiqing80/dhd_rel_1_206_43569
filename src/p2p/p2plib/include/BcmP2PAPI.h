/****************************************************************************
*
* Copyright (C) 2014, Broadcom Corporation
* All Rights Reserved.
* 
* This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
* the contents of this file may not be disclosed to third parties, copied
* or duplicated in any form, in whole or in part, without the prior
* written permission of Broadcom Corporation.
*
* $Id: BcmP2PAPI.h,v 1.182 2011-01-19 20:14:28 $
*****************************************************************************
*/
/**
*  @file    BCMP2PAPI.h
*
*  @brief   Peer-to-peer API.
*
*  Definitions for the P2P library, which provides an API to establish secure
*  peer-to-peer connections for the following applications:
*    - SoftAP.
*    - WiFi Direct.
*
****************************************************************************
*/


/** \mainpage Introduction
 *
 *  \par
 *  This document provides an description of the APIs for the peer-to-peer (P2P)
 *  component of the Broadcom Host Support Libraries (HSL).
 *
 *  \par
 *  The P2P component provides application-level services to establish secure
 *  connections between peer WiFi devices. It supports the following types of
 *  applications:
 *     - SoftAP
 *     - WiFi Direct
 *
 *  \par
 *  The SoftAP APIs provide a set of high-level functions to simplify the
 *  creation, configuration, and management of a SoftAP. This includes the
 *  configuration of various security paramters:
 *     - WEP, WPA-PSK (TKIP), WPA2-PSK (TKIP+AES)
 *     - WiFi Protected Setup (WPS)
 *  \par
 *  In addition, the APIs allow the configuration of a lightweight DHCP service.
 *
 *  \par
 *  The WiFi Direct APIs provide a set of high-level functions to create,
 *  configure, and manage connections between peer WiFi devices according to
 *  the WFA WiFi Direct technical specification.
 */


/**
* @defgroup   Common Common definitions.
*
* @brief   Common APIs for all P2P applications.
*/

/**
* @defgroup   SoftAP     SoftAP definitions.
*
* @brief   Provides a set of APIs for creating and configuring a SoftAP.
*/

/**
* @defgroup   WiFiDirect WiFi Direct definitions.
*
* @brief   Provides a set of APIs for creating and configuring connections
*          using the WiFi Direct specification.
*/


#ifndef _BCMP2PAPI_H_
#define _BCMP2PAPI_H_

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif


/****************************************************************************
*/

/**
 * @addtogroup Common
 * @{
 */

/**
 * Function declaration prefix to allow building library as a DLL.
 * eg. A Windows project file can define this as __declspec(dllexport).
 */
#ifndef BCMP2P_API
#define BCMP2P_API
#endif


/** Version number of this API. */
#define BRCMP2P_VERSION		1

/* Product info for WPS IEs */
#define		WPS_IE_MANUF_NAME_LEN	64
#define		WPS_IE_MODEL_NAME_LEN	32
#define		WPS_IE_MODEL_NUM_LEN	32
#define		WPS_IE_SERIAL_NUM_LEN	32



/** Boolean type compatible with 'int'. 0 means false, non-zero means true. */
typedef int BCMP2P_BOOL;
#define BCMP2P_FALSE	0
#define BCMP2P_TRUE		1

/** Fixed width types */
typedef unsigned char		BCMP2P_UINT8;
typedef unsigned short		BCMP2P_UINT16;
typedef short			BCMP2P_INT16;
typedef unsigned int		BCMP2P_UINT32;
typedef int			BCMP2P_INT32;
typedef unsigned long long	BCMP2P_UINT64;
typedef BCMP2P_UINT32		BCMP2P_WPS_CONFIG_METHODS;

/** IP Address type in host order */
typedef BCMP2P_UINT32 BCMP2P_IP_ADDR;

#define	BCMP2P_ETHER_ADDR_LEN	6
/** 48-bit Ethernet MAC address */
typedef struct BCMP2P_ETHER_ADDR {
	BCMP2P_UINT8 octet[BCMP2P_ETHER_ADDR_LEN];
} BCMP2P_ETHER_ADDR;

/** P2P Handle definition */
typedef void* BCMP2PHandle;

/** P2P Service Discovery Handle */
typedef void* BCMSVCHandle;

/** P2P Connect timeout */
#define BCMP2P_CONNECT_TMO_SECS 60

/** P2P status/error codes */
typedef enum {
	BCMP2P_SUCCESS = 0,
	BCMP2P_INVALID_HANDLE = -1,
	BCMP2P_INVALID_PARAMS = -2,
	BCMP2P_NOT_ENOUGH_SPACE = -3,
	BCMP2P_INVALID_CHANNEL = -4,
	BCMP2P_INVALID_ENCRYPTION = -5,
	BCMP2P_INVALID_AUTH_TYPE = -6,
	BCMP2P_INVALID_KEY = -7,
	 /** Notify not registered */
	BCMP2P_NO_NOTIF_GROUP_OWNER_NEGOTIATION = -8,
	BCMP2P_FAIL_TO_START_DISCOVER_PROCESS = -9,
	BCMP2P_FAIL_TO_START_CONNECT_PROCESS = -10,
	BCMP2P_PEER_NOT_FOUND = -11,
	/** Generic wl_ioctl error */
	BCMP2P_CANT_TALK_TO_DRIVER = -12,
	BCMP2P_VERSION_MISMATCH = -13,
	BCMP2P_UNIMPLEMENTED = -14,
	BCMP2P_DISCOVERY_ALREADY_IN_PROGRESS = -15,
	BCMP2P_CONNECT_ALREADY_IN_PROGRESS = -16,
	BCMP2P_FAIL_TO_START_SOFT_AP = -17,
	BCMP2P_WPS_ENROLLEE_FAILED = -18,
	BCMP2P_WPS_REGISTRAR_FAILED = -19,
	BCMP2P_CONNECT_CANCELLED = -20,
	BCMP2P_PEER_HAS_SAME_MAC_ADDR = -21,
	BCMP2P_CANT_ACT_AS_AP = -22,
	BCMP2P_CANT_ACT_AS_STA = -23,
	BCMP2P_FAIL_TO_START_RAW_RX = -24,
	BCMP2P_FAIL_TO_SETUP_P2P_APSTA = -25,
	BCMP2P_SOFTAP_ALREADY_RUNNING = -26,
	BCMP2P_FAIL_TO_START_DHCPD_PROCESS = -27,
	BCMP2P_FAIL_TO_ENABLE_EVENTS = -28,
	BCMP2P_NO_GO_NEGOTIATE_REQ = -29,
	BCMP2P_GO_NEGOTIATE_TIMEOUT = -30,
	/** wl_ioctl failed because a specific operation is not allowed in the
	 *  current driver state. eg. some ioctl/iovar can only be set when the
	 *  driver is up or down.
	 */
	BCMP2P_IOCTL_OPERATION_NOT_ALLOWED = -31,
	BCMP2P_CONNECT_REJECTED = -32,
	BCMP2P_SOFTAP_DISABLE_FAIL = -33,
	BCMP2P_DISASSOC_FAIL = -34,
	BCMP2P_NESTED_CALL = -35,
	/** An ioctl failed because it requires the WL driver to be in a
	 *  down state. This is a non-fatal warning. The soft AP can continue
	 *  to operate but with reduced functionality (eg. unable to enable
	 *  WMM or WMM power save).
	 */
	BCMP2P_WARN_DRIVER_ALREADY_UP = -36,
	/** An ioctl failed because it is an optional driver feature that is
	 *  not supported by the current driver build.  This is a non-fatal
	 *  warning. The soft AP can continue to operate but with reduced
	 *  functionality (eg. unable to enable WMM or WMM power save.)
	 */
	BCMP2P_WARN_IOCTL_NOT_SUPPORTED = -37,
	BCMP2P_FAIL_TO_START_WPS_MGR = -38,
	/** GO negotiation failed because both peers have GO-only intent */
	BCMP2P_BOTH_GROUP_OWNER_INTENT = -39,
	BCMP2P_BAD_WPS_PIN = -40,
	/** GO negotiation failed because no WPS pin configured */
	/* Deprecated, use BCMP2P_GON_FAILED_NO_PROVIS_INFO instead. */
	BCMP2P_GON_FAILED_NO_PIN = -41,
	/* Generic/unknown error */
	BCMP2P_ERROR = -42,

	BCMP2P_FAILED_TO_SET_AP_IPADDR = -43,
	BCMP2P_FAIL_TO_START_STA = -44,
	BCMP2P_UNKNOWN_CMD = -45,

	/** GO negotiation failed because we have no provisioning info configured */
	BCMP2P_GON_FAILED_NO_PROVIS_INFO = -46,

	/** GO negotiation failed because peer is missing provisioning info */
	BCMP2P_GON_FAILED_INFO_UNAVAIL = -47,

	/** Must be last.  Update this value when adding new status codes.
	 *  To get this value, negate the last value above and add 1.
	 */
	BCMP2P_STATUS_LAST = 48
} BCMP2P_STATUS;


/** String table that corresponds to status codes (enum BCMP2P_STATUS). */
#define BCMP2P_STATUS_STR_TABLE {		\
	"Success",				\
	"Invalid handle",			\
	"Invalid params",			\
	"Not enough space",			\
	"Invalid channel",			\
	"Invalid encryption",			\
	"Invalid auth type",			\
	"Invalid key",				\
	"No notif group owner negotiation",	\
	"Fail to start discover process",	\
	"Fail to start connect process",	\
	"Peer not found",			\
	"Cannot talk to driver",		\
	"Version mismatch",			\
	"Unimplemented",			\
	"Discovery already in progress",	\
	"Connect already in progress",		\
	"Fail to start soft AP",		\
	"WPS enrollee failed",			\
	"WPS registrar failed",			\
	"Connect cancelled",			\
	"Peer has same MAC addr",		\
	"Cannot act as AP",			\
	"Cannot act as STA",			\
	"Fail to start raw rx",			\
	"Fail to setup p2p apsta",		\
	"SoftAP already running",		\
	"Fail to start dhcpd process",		\
	"Fail to enable events",		\
	"No go negotiate req",			\
	"Go negotiate timeout",			\
	"IOCTL operation not allowed",		\
	"Connect rejected",			\
	"SoftAP disable fail",			\
	"Disassoc fail",			\
	"Nested call",				\
	"Warn driver already up",		\
	"Warn IOCTL not supported",		\
	"Fail to start wps mgr",		\
	"Both group owner intent",		\
	"Bad WPS pin",				\
	"GON failed no pin",			\
	"Error",				\
	"Fail to set AP IP address",		\
	"Failed to start STA",			\
	"Unknown command",			\
	"GON failed we have no provis info",	\
	"GON failed peer missing provis info",	\
}


/**
 * Initialize the P2P library.
 *
 * @param p2pVersion   Specifies a BRCMP2P_VERSION.
 * @param pReserved    This is reserved and it should be set to NULL.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PInitialize(BCMP2P_UINT32 p2pVersion,
	void *pReserved);

/**
 * Uninitialize the P2P library.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PUninitialize(void);

/**
 * Open a wireless adapter device for P2P use.
 *
 * Once the P2P library is initialized, use BCMP2POpen to get a P2P device
 * handle for a specific wireless adapter and use BCMP2PClose to close a P2P
 * device handle.  This handle needs to be passed as the first parameter to
 * all other API.
 *
 * @param szAdapter   Specifies a wireless adapter.
 *  - For Linux this is a network interface name such as "eth1".
 *  - For Windows this specifies a GUID of a 'virtual' wireless adapter. This
 *    can be programmatically retrieved using the IPHelper Windows APIs.
 *    TBD: The adapter string can be used to retrieve a handle of a virtual
 *    adapter or it can be replaced with a 'virtual adapter handle'.
 * @param szPrimaryAdapter Specifies a 'physical'(primary) wireless adapter.
 *  - For Linux this is a network interface name such as "eth1"
 *  - For Windows this specifies a GUID of a 'physical' wireless adapter.
 *
 * @return   Returns a P2P device handle if successful, otherwise returns BCMP2P_INVALID_HANDLE.
 */
BCMP2P_API BCMP2PHandle  BCMP2POpen(char *szAdapter, char *szPrimaryAdapter);

/**
 * Close a wireless adapter device for P2P use.
 *
 * For each BCMP2POpen call, there must be a BCMP2PClose when the handle is
 * no longer needed.
 *
 * @param p2pHandle   Specifies a P2P device handle returned from BCMP2POpen.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PClose(BCMP2PHandle p2pHandle);


/**
 * Get string that corresponds to status enum.
 *
 * @param status  Enum to translate to string.
 *
 * @return String corresponding to enum, NULL on error.
 */
const char * BCMP2PStatusCodeToStr(BCMP2P_STATUS status);

/** Data encryption definition */
typedef enum {
	BCMP2P_ALGO_OFF = 0,
	BCMP2P_ALGO_TKIP = 2,
	BCMP2P_ALGO_WEP128 = 3,
	BCMP2P_ALGO_AES = 4,
	BCMP2P_ALGO_TKIP_AES = 5,

	BCMP2P_ALGO_DEFAULT = BCMP2P_ALGO_AES
} BCMP2P_WSEC_TYPE;

/** WPA authorization mode. */
typedef enum {
	BCMP2P_WPA_AUTH_NONE = 0x0001,
	BCMP2P_WPA_AUTH_SHARED = 0x0002,
	BCMP2P_WPA_AUTH_WPAPSK = 0x0004,
	BCMP2P_WPA_AUTH_WPA2PSK = 0x0080,
	BCMP2P_WPA_AUTH_WPAPSK_WPA2PSK = 0x0084,

	BCMP2P_AUTH_DEFAULT = BCMP2P_WPA_AUTH_WPA2PSK
} BCMP2P_AUTH_TYPE;


/** Whether DHCP Server should be on/off for a SoftAP/P2P group owner device */
typedef enum _DHCP_OPTION
{
	BCMP2P_DHCP_ON,		/**< Always turn on DHCP server */
	BCMP2P_DHCP_OFF,	/**< Always turn off DHCP server */
	BCMP2P_DHCP_AUTO	/**< Library will figure out if DHCP should be on or off */
} BCMP2P_DHCP_OPTION;

/** DHCP Server configuration */
typedef struct BCMP2P_DHCP_CONFIG
{
	/** Whether DHCP server is enabled */
	BCMP2P_DHCP_OPTION	DHCPOption;

	/**
	 * Starting and ending address of the allocatable IP address range,
	 * excluding the subnet. eg. if the subnet is 192.168.16.0 and the range
	 * is 192.168.16.100...192.168.16.199, then 'starting_ip' should be set
	 * to 100 and 'ending_ip' should be set to 200.
	 *
	 * The subnet of the range is determined from the BCMP2P_CONFIG structure's
	 * ip_addr and netmask fields.  eg. if ip_addr is 192.168.16.1 and netmask
	 * is 255.255.255.0, then the dhcp subnet is 192.168.16.0.
	 *
	 * eg. 100 for 192.168.16.100
	 */
	BCMP2P_UINT8		starting_ip;

	/** eg. 200 for 192.168.16.200 */
	BCMP2P_UINT8		ending_ip;
	BCMP2P_IP_ADDR		dns1;
} BCMP2P_DHCP_CONFIG;

/** Default DHCP config to use for if subnet and ip range are all zero:
 *  192.168.16.100...199.  The actual allocatable IP address range is
 *  BCMP2P_DHCP_DEFAULT_STARTING_IP...(BCMP2P_DHCP_DEFAULT_ENDING_IP-1).
 */
#define BCMP2P_DHCP_DEFAULT_SUBNET		0xc0a81000
#define BCMP2P_DHCP_DEFAULT_STARTING_IP		100
#define BCMP2P_DHCP_DEFAULT_ENDING_IP		200

/** DHCP server subnet netmask - this is not configurable */
#define BCMP2P_DHCP_NETMASK			0xffffff00

/** WPS device password ID */
typedef enum {
	BCMP2P_WPS_DEFAULT		= 0x0000,	/**< Default */
	BCMP2P_WPS_USER_SPEC		= 0x0001,	/**< User specified */
	BCMP2P_WPS_MACHINE_SPEC		= 0x0002,	/**< Machine specified */
	BCMP2P_WPS_REKEY		= 0x0003,	/**< Key in */
	BCMP2P_WPS_PUSH_BTN		= 0x0004,	/**< Pushbutton */
	BCMP2P_WPS_REG_SPEC		= 0x0005	/**< Read from peer display */
} BCMP2P_WPS_DEVICE_PWD_ID;

/** WPS config methods */
typedef enum {
	BCMP2P_WPS_USBA			= 0x0001,
	BCMP2P_WPS_ETHERNET		= 0x0002,
	BCMP2P_WPS_LABEL		= 0x0004,
	BCMP2P_WPS_DISPLAY		= 0x0008,
	BCMP2P_WPS_EXT_NFC_TOKEN	= 0x0010,
	BCMP2P_WPS_INT_NFC_TOKEN	= 0x0020,
	BCMP2P_WPS_NFC_INTERFACE	= 0x0040,
	BCMP2P_WPS_PUSHBUTTON 		= 0x0080,
	BCMP2P_WPS_KEYPAD		= 0x0100
} BCMP2P_WPS_CONFIG_METHOD_TYPE;

/** WPS pin */
#define BCMP2P_WPS_PIN_LEN 8
typedef char BCMP2P_WPS_PIN[BCMP2P_WPS_PIN_LEN + 1];

/** WPS configuration */
typedef struct BCMP2P_WPS_CONFIG
{
	/** Whether WPS is enabled */
	BCMP2P_BOOL			wpsEnable;
	BCMP2P_WPS_CONFIG_METHODS wpsConfigMethods;
	BCMP2P_WPS_PIN		wpsPin;
	BCMP2P_BOOL			wpsPinMode;
	BCMP2P_BOOL			wpsIsButtonPushed;
	BCMP2P_BOOL			wpsIsProvision;
} BCMP2P_WPS_CONFIG;

/** Passphrase */
#define BCMP2P_PASSPHRASE_MIN_LENGTH 8
#define BCMP2P_PASSPHRASE_MAX_LENGTH 64
typedef char BCMP2P_PASSPHRASE[BCMP2P_PASSPHRASE_MAX_LENGTH + 1];

#ifdef  SOFTAP_ONLY
#define BCMP2P_NUMRATES 16 /* max # of rates in a rateset */
typedef struct _BCMP2P_RATESET {
	BCMP2P_UINT32 count;			/* # rates in this set */
	BCMP2P_UINT8  rates[BCMP2P_NUMRATES];	/* rates in 500kbps units w/hi bit set if basic */
} BCMP2P_RATESET;
#endif /* SOFTAP_ONLY */

/* End of Common group. */
/** @} */


/****************************************************************************
*/

/**
 * @addtogroup WiFiDirect
 * @{
 */

#define BCMP2P_MAX_SVC_DATA_LEN		(4*1024)

/** Device Type categories for primary device types
 *  These values must match reg_prototlv.h's WPS_DEVICE_TYPE_CAT_*
 */
#define BCMP2P_DEVICE_TYPE_CAT_COMPUTER        1
#define BCMP2P_DEVICE_TYPE_CAT_INPUT_DEVICE    2
#define BCMP2P_DEVICE_TYPE_CAT_PRINTER         3
#define BCMP2P_DEVICE_TYPE_CAT_CAMERA          4
#define BCMP2P_DEVICE_TYPE_CAT_STORAGE         5
#define BCMP2P_DEVICE_TYPE_CAT_NW_INFRA        6
#define BCMP2P_DEVICE_TYPE_CAT_DISPLAYS        7
#define BCMP2P_DEVICE_TYPE_CAT_MM_DEVICES      8
#define BCMP2P_DEVICE_TYPE_CAT_GAME_DEVICES    9
#define BCMP2P_DEVICE_TYPE_CAT_TELEPHONE       10
#define BCMP2P_DEVICE_TYPE_CAT_AUDIO           11
#define BCMP2P_DEVICE_TYPE_CAT_OTHER           255


/** Device Type sub categories for primary device types
 *  These values must match reg_prototlv.h's WPS_DEVICE_TYPE_SUB_CAT_*
 */
#define BCMP2P_DEVICE_TYPE_SUB_CAT_COMP_PC         1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_COMP_SERVER     2
#define BCMP2P_DEVICE_TYPE_SUB_CAT_COMP_MEDIA_CTR  3
#define BCMP2P_DEVICE_TYPE_SUB_CAT_COMP_UMPC       4
#define BCMP2P_DEVICE_TYPE_SUB_CAT_COMP_NOTEBOOK   5
#define BCMP2P_DEVICE_TYPE_SUB_CAT_COMP_DESKTOP    6
#define BCMP2P_DEVICE_TYPE_SUB_CAT_COMP_MID        7
#define BCMP2P_DEVICE_TYPE_SUB_CAT_COMP_NETBOOK    8
#define BCMP2P_DEVICE_TYPE_SUB_CAT_INP_KBD         1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_INP_MOUSE       2
#define BCMP2P_DEVICE_TYPE_SUB_CAT_INP_JOYSTICK    3
#define BCMP2P_DEVICE_TYPE_SUB_CAT_INP_TRACKBALL   4
#define BCMP2P_DEVICE_TYPE_SUB_CAT_INP_CONTROLLER  5
#define BCMP2P_DEVICE_TYPE_SUB_CAT_INP_REMOTE      6
#define BCMP2P_DEVICE_TYPE_SUB_CAT_INP_TOUCHSCREEN 7
#define BCMP2P_DEVICE_TYPE_SUB_CAT_INP_BIO_READER  8
#define BCMP2P_DEVICE_TYPE_SUB_CAT_INP_BAR_READER  9
#define BCMP2P_DEVICE_TYPE_SUB_CAT_PRTR_PRINTER    1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_PRTR_SCANNER    2
#define BCMP2P_DEVICE_TYPE_SUB_CAT_PRTR_FAX        3
#define BCMP2P_DEVICE_TYPE_SUB_CAT_PRTR_COPIER     4
#define BCMP2P_DEVICE_TYPE_SUB_CAT_PRTR_ALLINONE   5
#define BCMP2P_DEVICE_TYPE_SUB_CAT_CAM_DGTL_STILL  1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_CAM_VIDEO       2
#define BCMP2P_DEVICE_TYPE_SUB_CAT_CAM_WEBCAM      3
#define BCMP2P_DEVICE_TYPE_SUB_CAT_CAM_SECURITY    4
#define BCMP2P_DEVICE_TYPE_SUB_CAT_STOR_NAS        1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_NW_AP           1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_NW_ROUTER       2
#define BCMP2P_DEVICE_TYPE_SUB_CAT_NW_SWITCH       3
#define BCMP2P_DEVICE_TYPE_SUB_CAT_NW_GATEWAY      4
#define BCMP2P_DEVICE_TYPE_SUB_CAT_DISP_TV         1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_DISP_PIC_FRAME  2
#define BCMP2P_DEVICE_TYPE_SUB_CAT_DISP_PROJECTOR  3
#define BCMP2P_DEVICE_TYPE_SUB_CAT_DISP_MONITOR    4
#define BCMP2P_DEVICE_TYPE_SUB_CAT_MM_DAR          1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_MM_PVR          2
#define BCMP2P_DEVICE_TYPE_SUB_CAT_MM_MCX          3
#define BCMP2P_DEVICE_TYPE_SUB_CAT_MM_STB          4
#define BCMP2P_DEVICE_TYPE_SUB_CAT_MM_MSMAME       5
#define BCMP2P_DEVICE_TYPE_SUB_CAT_MM_PVP          6
#define BCMP2P_DEVICE_TYPE_SUB_CAT_GAME_XBOX       1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_GAME_XBOX_360   2
#define BCMP2P_DEVICE_TYPE_SUB_CAT_GAME_PS         3
#define BCMP2P_DEVICE_TYPE_SUB_CAT_GAME_CONSOLE    4
#define BCMP2P_DEVICE_TYPE_SUB_CAT_GAME_PORTABLE   5
#define BCMP2P_DEVICE_TYPE_SUB_CAT_PHONE_WM        1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_PHONE_SINGLE    2
#define BCMP2P_DEVICE_TYPE_SUB_CAT_PHONE_DUAL      3
#define BCMP2P_DEVICE_TYPE_SUB_CAT_PHONE_SM_SINGLE 4
#define BCMP2P_DEVICE_TYPE_SUB_CAT_PHONE_SM_DUAL   5
#define BCMP2P_DEVICE_TYPE_SUB_CAT_AUDIO_TUNER     1
#define BCMP2P_DEVICE_TYPE_SUB_CAT_AUDIO_SPEAKER   2
#define BCMP2P_DEVICE_TYPE_SUB_CAT_AUDIO_PMP       3
#define BCMP2P_DEVICE_TYPE_SUB_CAT_AUDIO_HEADSET   4
#define BCMP2P_DEVICE_TYPE_SUB_CAT_AUDIO_HEADPHONE 5
#define BCMP2P_DEVICE_TYPE_SUB_CAT_AUDIO_MIC       6

/* End of WiFiDirect group. */
/** @} */


/****************************************************************************
*/

/**
 * @addtogroup Common
 * @{
 */

/* IEEE 802.11 Annex E */
typedef enum {
	IEEE_2GHZ_20MHZ_CLASS_12		= 81,	/* Ch 1-11			 */
	IEEE_5GHZ_20MHZ_CLASS_1			= 115,	/* Ch 36-48			 */
	IEEE_5GHZ_20MHZ_CLASS_2_DFS		= 118,	/* Ch 52-64			 */
	IEEE_5GHZ_20MHZ_CLASS_3			= 124,	/* Ch 149-161		 */
	IEEE_5GHZ_20MHZ_CLASS_4_DFS		= 121,	/* Ch 100-140		 */
	IEEE_5GHZ_20MHZ_CLASS_5			= 125,	/* Ch 149-165		 */
	IEEE_5GHZ_40MHZ_CLASS_22		= 116,	/* Ch 36-44,   lower */
	IEEE_5GHZ_40MHZ_CLASS_23_DFS 	= 119,	/* Ch 52-60,   lower */
	IEEE_5GHZ_40MHZ_CLASS_24_DFS	= 122,	/* Ch 100-132, lower */
	IEEE_5GHZ_40MHZ_CLASS_25		= 126,	/* Ch 149-157, lower */
	IEEE_5GHZ_40MHZ_CLASS_27		= 117,	/* Ch 40-48,   upper */
	IEEE_5GHZ_40MHZ_CLASS_28_DFS	= 120,	/* Ch 56-64,   upper */
	IEEE_5GHZ_40MHZ_CLASS_29_DFS	= 123,	/* Ch 104-136, upper */
	IEEE_5GHZ_40MHZ_CLASS_30		= 127,	/* Ch 153-161, upper */
	IEEE_2GHZ_40MHZ_CLASS_32		= 83,	/* Ch 1-7,     lower */
	IEEE_2GHZ_40MHZ_CLASS_33		= 84,	/* Ch 5-11,    upper */
    IEEE_5GHZ_80MHZ_CLASS_128       = 128,  /* Ch 42 - 155 Center Channels freq idx */
    IEEE_5GHZ_160MHZ_CLASS_129      = 129,  /* Ch 50 - 114 Center Channels freq idx */
    IEEE_5GHZ_8080MHZ_CLASS_130     = 130,  /* Ch 42 - 155 Center Channels freq idx */

	/* listen channel class */
	BCMP2P_LISTEN_CHANNEL_CLASS = IEEE_2GHZ_20MHZ_CLASS_12,

	/* default operating channel class */
	BCMP2P_DEFAULT_OP_CHANNEL_CLASS = IEEE_2GHZ_20MHZ_CLASS_12
} BCMP2P_CHANNEL_CLASS;

typedef struct BCMP2P_CHANNEL {
	BCMP2P_CHANNEL_CLASS channel_class;
	BCMP2P_UINT32 channel;
} BCMP2P_CHANNEL;

typedef struct BCMP2P_PRODUCT_INFO {
	/* Product info for WPS IEs */
	char		manufacturer[WPS_IE_MANUF_NAME_LEN + 1];
	char		modelName[WPS_IE_MODEL_NAME_LEN + 1];
	char		modelNumber[WPS_IE_MODEL_NUM_LEN + 1];
	char		serialNumber[WPS_IE_SERIAL_NUM_LEN + 1];
	BCMP2P_UINT32	osVersion;
} BCMP2P_PRODUCT_INFO;

/**
 * Link configuration.
 *
 * Apps that create an instance of this structure should call
 * BCMP2P_INIT_BCMP2P_CONFIG(pConfig) to set all fields to default values
 * before filling in the fields.  This allows compatibility with newer
 * versions of the library may add additional fields to the structure.
 */
typedef struct BCMP2P_CONFIG
{
	/** Specifies the operating channel. If zero, auto channel selection
	 *  will be used to find a quiet channel.
	 */
	BCMP2P_CHANNEL		operatingChannel;

	/** Specifies an encryption algorithm (none, TKIP, AES, etc). Default is AES. */
	BCMP2P_WSEC_TYPE 	encryption;

	/** Specifies an 802.11 authentication type (open, WPA2PSK). Default is WPA2PSK. */
	BCMP2P_AUTH_TYPE	authentication;

	/** Null terminated passphrase for PMK. A valid passphrase must be between
	 *  8 and 64 characters.
	 */
	BCMP2P_UINT8		keyWPA[64+1];

	/** Null terminated WEP key - 10 or 26 ascii hex characters.  */
	BCMP2P_UINT8		WEPKey[4][32];

	/** 0-based WEP key index (0...3). */
	BCMP2P_UINT32		WEPKeyIndex;

	/** DHCP server configuration parameters. */
	BCMP2P_DHCP_CONFIG	DHCPConfig;

	/** WPS configuration parameters. */
	BCMP2P_WPS_CONFIG	WPSConfig;

	/** Static IP address to apply to the soft AP network interface.
	 *  0 means do not configure the network interface IP address or netmask
	 *  (assume something else in the OS or the application will configure them).
	 *   Currently this IP address must end in .1.  eg. 192.168.16.1.
	 */
	BCMP2P_IP_ADDR		ip_addr;

	/** Static IP netmask to apply to the soft AP network interface.
	 *  Currently the netmask must be 255.255.255.0.
	 */
	BCMP2P_IP_ADDR		netmask;

	/** Whether to allow 11b clients. */
	BCMP2P_BOOL		allow11b;

	/** TRUE to enable WMM support in the soft AP, FALSE otherwise. */
	BCMP2P_BOOL		enableWMM;

	/** TRUE to enable WMM power save mode, 0 otherwise. */
	BCMP2P_BOOL		enableWMM_PS;

	/** Maximum number of STAs allowed to associate to soft AP.
	 *  0 or a value > BCMP2P_MAX_SOFTAP_CLIENTS means use the default of
	 *  BCMP2P_MAX_SOFTAP_CLIENTS.
	 */
	BCMP2P_UINT32		maxClients;		/* Max # allowed associations */

	/** TRUE to hide SSID in beacons and probe responses, FALSE otherwise. */
	BCMP2P_BOOL		hideSSID;

	/** P2P Group owner intent value. */
	BCMP2P_UINT8		grp_owner_intent;

#ifdef SOFTAP_ONLY
	BCMP2P_UINT32		Dtim;			/* DTIM interval */
	BCMP2P_UINT32		BeaconInterval; /* Beacon interval */
	BCMP2P_UINT32		TxPower;		/* Tx power in qdbm */
	BCMP2P_RATESET		RateSet;        /* b/g rateset */
	BCMP2P_UINT8		ccode[3];		/* Country code */
	BCMP2P_BOOL			PlcpShort;		/* PLCP short preambule */
#endif /* SOFTAP_ONLY */

	/** Our Primary device type - BCMP2P_DEVICE_TYPE_CAT_xxx. */
	BCMP2P_UINT8		primaryDevType;

	/** Our Primary device subtype - BCMP2P_DEVICE_TYPE_SUB_CAT_xxx. */
	BCMP2P_UINT8		primaryDevSubCat;

	/** Whether we want to form a Persistent Group during GO negotiation */
	BCMP2P_BOOL		wantPersistentGroup;

	/** Whether to enable Persistent Reconnect for Persistent Groups */
	BCMP2P_BOOL		enableReconnect;

	/** Make the P2P Interface Address the same as the P2P Device Address */
	BCMP2P_BOOL		sameIntDevAddrs;

	/** Enable P2P managed device */
	BCMP2P_BOOL		enableManagedDevice;

	/** Disable P2P functionality - for creating a non-P2P Soft AP */
	BCMP2P_BOOL		disableP2P;
#ifdef SECONDARY_DEVICE_TYPE
	BCMP2P_UINT32		secDevOui;	/* Secondary Device OUI */
	BCMP2P_UINT8		secDevType;	/* Secondary Device Type */
	BCMP2P_UINT8		secDevSubCat;	/* Secondary Device Subcategory ID */
#endif	
	BCMP2P_PRODUCT_INFO 	prodInfo;

#ifdef BCM_P2P_OPTEXT
    BCMP2P_BOOL         opch_force;
    BCMP2P_BOOL         opch_high;
#endif

} BCMP2P_CONFIG, *PBCMP2P_CONFIG;

/** Macro to initialize the BCMP2P_CONFIG structure to default values.
 *  Use this macro insted of just zeroing it.
 */
#define BCMP2P_INIT_BCMP2P_CONFIG(pConfig) \
	memset(pConfig, 0, sizeof(*pConfig)); \
	(pConfig)->grp_owner_intent = 8;

/* End of Common group. */
/** @} */


/****************************************************************************
*/

/**
 * @addtogroup SoftAP
 * @{
 */
/** Maximum number of STAs that can associate to the soft AP */
#define BCMP2P_MAX_SOFTAP_CLIENTS	8

/**
 * Set WPS version into Soft AP to use different WPS version
 * Soft AP support WPA/WPA2 in WPS version 1
 * Soft AP only support WPA2 in WPS version 2
 * P2P Device should not called this function, this function is design for SoftAP
 *
 * @param useWPSv1  useWPSv1 to set the WPS version.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PSetSoftAPUseWPSVersion1(BCMP2P_BOOL useWPSv1);


/**
 * Set up device as a Soft AP and wait for STA clients to connect.
 * This function only returns when BCMP2PCancelCreateSoftAP is called.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PCreateSoftAP(BCMP2PHandle p2pHandle,
	BCMP2P_UINT8 *ssid);

/**
 * Stop the created soft AP, disconnecting all clients.
 * Also stops the WPS registrar and DHCP server if running.
 *
 * @param p2pHandle P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PCancelCreateSoftAP(BCMP2PHandle p2pHandle);

/**
 * Get the maximum number of allowed STA clients for a soft AP
 *
 * @return Maximum number of allowed STA clients for a soft AP. This returns
 *         the absolute maximum limit for the number of allowed clients
 *         regardless of whether a lower number has been specified when creating a
 *         SoftAP (in the BCMP2P_CONFIG 'maxClients' field).
 */
BCMP2P_API BCMP2P_UINT32 BCMP2PGetMaxSoftAPClients(void);

/**
 * This function is DEPRECATED. Please use BCMP2PSetWPSPin(), BCMP2PPushButton(),
 * BCMP2PSetWPSRegistrarTimeout(), and BCMP2PCancelWPSRegistrar() instead.
 *
 * Open or close the WPS registrar enrollment window on a running Soft AP.
 *
 * This is only meaningful if WPS was previously specified to be enabled by the
 * PBCMP2P_CONFIG parameter when creating a P2P connection/P2P group/soft AP.
 * Opening the window will cause the WPS registrar to be run whenever a STA
 * associates to the soft AP.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param enable     Open or close the WPS enrollment window
 * @param autoCloseSecs
 *   - If opening the window, this specifies the duration of the window.
 *     This value must be > 0.
 *   - If closing the window, this value is ignored.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2POpenWPSWindow(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL enable, BCMP2P_UINT32 autoCloseSecs);
#define BCMP2PCloseWPSWindow(hdl)	BCMP2POpenWPSWindow(hdl, FALSE, 0)

/**
 * This function is DEPRECATED. Please use BCMP2PIsWPSRegistrarRunning() instead.
 *
 * Check if the SoftAP's WPS registrar enrollment window is open.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return TRUE if successful, FALSE if not.
 */
BCMP2P_API BCMP2P_BOOL  BCMP2PIsWPSWindowOpen(BCMP2PHandle p2pHandle);

/**
 * Set the WPS registrar timeout (default 120 seconds).
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param seconds    Timeout value in seconds.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetWPSRegistrarTimeout(
	BCMP2PHandle p2pHandle, BCMP2P_UINT32 seconds);

/**
 * Cancel/stop the WPS registrar.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PCancelWPSRegistrar(BCMP2PHandle p2pHandle);

/** MAC address filter mode */
typedef enum _BCMP2P_MAC_FILTER_MODE
{
	BCMP2P_MAC_FILTER_OFF,		/**< Turn off MAC address filter */
	BCMP2P_MAC_FILTER_DENY,		/**< Deny association to MAC address list */
	BCMP2P_MAC_FILTER_ALLOW,	/**< Allow association to MAC address list */
	BCMP2P_MAC_FILTER_MAX		/**< number of values in this enum */
} BCMP2P_MAC_FILTER_MODE;

/**
 * Sets the function of the MACList: either allow or deny.
 *
 * @param p2pHandle  Specifies a P2P device handle returned from the previous
 *                   BCMP2POpen call.
 * @param mode       Filter mode.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetMACListMode(BCMP2PHandle p2pHandle,
	BCMP2P_MAC_FILTER_MODE mode);

/**
 * Set the MAC address list to allow/deny.
 *
 * @param p2pHandle     Specifies a P2P device handle returned from the previous
 *                      BCMP2POpen call.
 * @param macList       Array of STA MAC addresses to allow/deny.  Use the function
 *                      BCMP2PSetMACListMode() to set mode.
 * @param macListCount  Number of items in macList.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetMACList(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *macList, BCMP2P_UINT32 macListCount);

/**
 * Get the previously set MAC address list to allow/deny
 *
 * @param p2pHandle     Specifies a P2P device handle returned from the previous
 *                      BCMP2POpen call.
 * @param macListMax    Array size of macList (max # of entries that can be copied).
 * @param macList       Copy the allow/deny list of STA MAC addresses into this array
 *                      provided by the caller.
 * @param macListCount  This will be set to the number of items copied to macList.
 * @param mode          Filter mode.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetMACList(BCMP2PHandle p2pHandle,
	BCMP2P_UINT32 maxListMax, BCMP2P_ETHER_ADDR *macList,
	BCMP2P_UINT32 *macListCount, BCMP2P_MAC_FILTER_MODE *mode);


/**
 * Deauthenticate a STA
 *
 * @param p2pHandle    Specifies a P2P device handle returned from the previous
 *                     BCMP2POpen call.
 * @param mac_address  MAC address of the associated STA to deauthenticate.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PDeauth(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *mac_address);

/**
 * Get a list of associated STAs
 *
 * @param p2pHandle    Specifies a P2P device handle returned from the previous
 *                     BCMP2POpen call.
 * @param maclist_max  Maximum # of elements in the 'maclist' array.
 * @param maclist      Array of MAC addresses to be filled in.
 * @maclist_count      Number of filled in elements in 'maclist'.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetAssocList(BCMP2PHandle p2pHandle,
	BCMP2P_UINT32 maclist_max, BCMP2P_ETHER_ADDR *maclist,
	BCMP2P_UINT32 *maclist_count);

/**
 * Get the current operating channel number
 *
 * @param p2pHandle  Specifies a P2P device handle returned from the previous
 *                   BCMP2POpen call.
 * @param channel    Will be set to the current operating channel number.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetChannel(BCMP2PHandle p2pHandle,
	BCMP2P_CHANNEL *channel);

/**
 * Get the SoftAP's static IP address that was applied to the softAP's network
 * interface by BCMP2PCreateSoftAP().
 *
 * @param p2pHandle  Specifies a P2P device handle returned from the previous
 *                   BCMP2POpen call.
 * @param ipaddr     Filled in with SoftAP IP address. eg. 0xc0a81001 for 192.168.16.1.
 *                   If BCMP2PCreateSoftAP() did not apply an IP address to the softAP's
 *                   network interface, then 'ipaddr' will be set to 0.
 * @param netmask    Filled in with SoftAP netmask. eg. 0xffffff00 for 255.255.255.0.
 *                   If BCMP2PCreateSoftAP() did not apply an IP address to the softAP's
 *                   network interface, then 'netmask' will be set to 0.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetIP(BCMP2PHandle p2pHandle,
	BCMP2P_IP_ADDR *ipaddr, BCMP2P_IP_ADDR *netmask);


/**
 * P2P device statistics.
 *
 * @param rxPackets       Indicates the number of frames that the SoftAP receives without
 *                        errors. (OID_GEN_RCV_OK request is sent to the driver.)
 * @param rxErrorPackets  Indicates the number of frames that a SoftAP receives but
 *                        does not indicate to the protocols due to errors.
 *                        (OID_GEN_RCV_ERROR is sent to the driver.)
 * @param txPackets       Indicates the number of frames that the SoftAP has successfully
 *                        transmitted. (OID_GEN_XMIT_OK request is sent to the driver.)
 * @param txErrorPackets  Indicates the number of frames that a SoftAP fails to
 *                        transmit. (OID_GEN_XMIT_ERROR is sent to the driver.)
 * @param connectionTime  For a STA, it indicates the number of seconds elapsed
 *                        since the STA is connected to the AP; For a SoftAP,
 *                        it indicates the number of seconds elapsed since the
 *                        SoftAP capability was enabled.
 */
typedef struct BCMP2P_STAT
{
	BCMP2P_UINT32		rxPackets;
	BCMP2P_UINT32		rxErrorPackets;
	BCMP2P_UINT32		txPackets;
	BCMP2P_UINT32		txErrorPackets;
	time_t			connectionTime;
} BCMP2P_STAT, *PBCMP2P_STAT;

/**
 * Get SoftAP/STA statistics. Get the current WLAN driver statistics.
 *
 * @param szAdapter   Specifies a wireless adapter.
 *  - For Linux this is a network interface name such as "eth1".
 *  - For Windows this specifies a GUID of a 'virtual' wireless adapter. This
 *    can be programmatically retrieved using the IPHelper Windows APIs.
 *    TBD: The adapter string can be used to retrieve a handle of a virtual
 *    adapter or it can be replaced with a 'virtual adapter handle'.
 * @param pStatistics  Specifies a caller-provided buffer to store the current
 *                     statistics.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetStatistics(char* szAdapter,
	PBCMP2P_STAT pStatistics);

/**
 * Macro to calculate the percent packets lost, rounded to the nearest integer
 * percentage, e.g.
 *    BCMP2P_STAT s;
 *    BCMP2PGetStatistics(..., &s);
 *    tx_lost_percent = BCMP2P_PKTS_LOST_PERCENT(s.txPacket, s.txErrorPackets);
 */
#define BCMP2P_PKTS_LOST_PERCENT(pkts, errpkts) \
	(BCMP2P_UINT32)((((BCMP2P_UINT64)errpkts * 1000 / pkts) + 5) / 10)


/**
 * P2P link status.
 *
 * @param linkSpeed         Indicates the maximum speed of the SoftAP in kbps
 *                          (see WLC_GET_RATE).
 * @param channelFrequency  Indicates a channel frequency converted from the
 *                          channel number in Mhz.
 * @param numAntennas       Indicates the number of antennas being used (query OID
 *                          name-value-pair  'antennas' from the driver).
 * @param rssi              Indicates the number of received signal strength in
 *                          dBm (see WLC_GET_RSSI).
 * @param noise             Indicates a noise value (right after tx) in dBm (see
 *                          WLC_GET_PHY_NOISE).
 * @param bandWidth         Indicates the current band width in Mhz. Possible
 *                          values are 10, 20 or 40. This is converted from an 11n
 *                          chanspec.
 */
typedef struct BCMP2P_LINK_STATUS {
	BCMP2P_UINT32	linkSpeed;
	BCMP2P_UINT32	channelFrequency;
	BCMP2P_UINT32	numAntennas;
	BCMP2P_INT32 	rssi;
	BCMP2P_INT32	noise;
	BCMP2P_INT32 	bandWidth;
} BCMP2P_LINK_STATUS, *PBCMP2P_LINK_STATUS;

/**
 * Get SoftAP link status. Get the current link status of the SoftAP for a
 * device running in the AP/group owner role.
 *
 * @param p2pHandle    Specifies a P2Pdevice handle returned from the previous
 *                     BCMP2POpen call.
 * @param pLinkStatus  Specifies a buffer to store the current link status.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetLinkStatus(BCMP2PHandle p2pHandle,
	PBCMP2P_LINK_STATUS  pLinkStatus);


/**
 * Get SoftAP operational status
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.

 * @return TRUE if SoftAP is on, otherwise returns FALSE. If this function is
 *         called from a P2P device which is connected as a STA/non-group owner,
 *         it always returns FALSE.
 */
BCMP2P_API BCMP2P_BOOL  BCMP2PIsSoftAPOn(BCMP2PHandle p2pHandle);

/**
 * Get DHCP Server operational status.
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 *
 * @return TRUE if DHCP server is running (only in AP mode), otherwise
 *         returns FALSE. If this function is called from a P2P device which is
 *         connected as a STA/non-group owner, it always returns FALSE.
 */
BCMP2P_API BCMP2P_BOOL  BCMP2PIsDHCPOn(BCMP2PHandle p2pHandle);

/* End of SoftAP group. */
/** @} */


/****************************************************************************
*/

/**
 * @addtogroup Common
 * @{
 */

/*
 * Data types related to event notification registration:
 */

/** Event notification type (bits) */
typedef enum {
	BCMP2P_NOTIF_DISCOVER			= 0x0001,
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION	= 0x0002,
	BCMP2P_NOTIF_CREATE_LINK		= 0x0004,
	BCMP2P_NOTIF_WPS_STATE			= 0x0008,
	BCMP2P_NOTIF_PROVISION_DISCOVERY	= 0x0010,
	BCMP2P_NOTIF_PRESENCE			= 0x0020,
	BCMP2P_NOTIF_SERVICE_DISCOVERY		= 0x0040,
	BCMP2P_NOTIF_PRIMARY_IF                 = 0x0080,
	BCMP2P_NOTIF_DEVICE_DISCOVERABILITY	= 0x0100,
	BCMP2P_NOTIFY_ALL			= BCMP2P_NOTIF_DISCOVER |
	                                          BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION |
	                                          BCMP2P_NOTIF_CREATE_LINK |
	                                          BCMP2P_NOTIF_WPS_STATE |
	                                          BCMP2P_NOTIF_PROVISION_DISCOVERY |
	                                          BCMP2P_NOTIF_PRESENCE |
	                                          BCMP2P_NOTIF_SERVICE_DISCOVERY |
	                                          BCMP2P_NOTIF_PRIMARY_IF |
	                                          BCMP2P_NOTIF_DEVICE_DISCOVERABILITY
} BCMP2P_NOTIFICATION_TYPE;

/** Event notification code */
typedef enum {
	BCMP2P_NOTIF_NONE = 0,

	/* ---------- Discovery --------------------------------------------- */
	/** Started the initial 802.11 scan phase */
	BCMP2P_NOTIF_DISCOVER_START_80211_SCAN = 0x1001,

	/** Started the subsequent search-listen phase */
	BCMP2P_NOTIF_DISCOVER_START_SEARCH_LISTEN,

	/** Sent on each iteration of the search-listen phase. */
	BCMP2P_NOTIF_DISCOVER_SEARCH_LISTEN_ITERATION,

	/** Have results from the initial 802.11 scan */
	BCMP2P_NOTIF_DISCOVER_FOUND_P2P_GROUPS,

	/** Have results from subsequent search-listen phase */
	BCMP2P_NOTIF_DISCOVER_FOUND_PEERS,

	BCMP2P_NOTIF_DISCOVER_CANCEL,
	BCMP2P_NOTIF_DISCOVER_FAIL,
	BCMP2P_NOTIF_DISCOVER_COMPLETE,

	/** Discovery suspended due to start of GO Negotiation */
	BCMP2P_NOTIF_DISCOVER_SUSPENDED,

	/** Discovery resumed after GO Negotiation failure */
	BCMP2P_NOTIF_DISCOVER_RESUMED,

	/** Started discovery in listen-only state */
	BCMP2P_NOTIF_DISCOVER_START_LISTEN_ONLY,


	/* ---------- Provision Discovery ----------------------------------- */
	BCMP2P_NOTIF_PROVISION_DISCOVERY_REQUEST = 0x2101,
	BCMP2P_NOTIF_PROVISION_DISCOVERY_RESPONSE,
	BCMP2P_NOTIF_PROVISION_DISCOVERY_TIMEOUT,


	/* ---------- Group Owner Negotiation ------------------------------- */
	/** Sent GON request
		pNotificationData: NULL
		*/
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_START = 0x2201,

	/** pNotificationData: PBCMP2P_DISCOVER_ENTRY */
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_AP_ACK,

	/** pNotificationData: PBCMP2P_DISCOVER_ENTRY */
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_STA_ACK,

	/** pNotificationData: NULL */
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_COMPLETE,

	/** pNotificationData: NULL */
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL,

	/** pNotificationData: PBCMP2P_DISCOVER_ENTRY */
	/* Deprecated, use BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_NO_PROV_INFO. */
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_NO_PIN,

	/** Peer has no provisioning info.
	    pNotificationData: PBCMP2P_DISCOVER_ENTRY
	    */
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL,

	/** pNotificationData: NULL */
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL_INTENT,

	/** We have no provisioning info.
	    pNotificationData: PBCMP2P_DISCOVER_ENTRY
	    */
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_NO_PROV_INFO,

	/** We are already in an existing P2P connection.
	    pNotificationData: NULL
	    */
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_ALREADY_CONNECTED,

	/** Received GON request
		pNotificationData: PBCMP2P_DISCOVER_ENTRY
		*/
	BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_REQUEST_RECEIVED,

	/* ---------- P2P Invite -------------------------------------------- */
	/** pNotificationData: PBCMP2P_INVITE_PARAM */
	BCMP2P_NOTIF_P2P_INVITE_REQ = 0x2301,

	BCMP2P_NOTIF_P2P_INVITE_RSP,

	/* ---------- P2P Presence------------------------------------------- */
	BCMP2P_NOTIF_P2P_PRESENCE_REQ = 0x2401,
	BCMP2P_NOTIF_P2P_PRESENCE_RSP,

	/* ---------- P2P Device Discoverability ---------------------------- */
	BCMP2P_NOTIF_DEV_DISCOVERABILITY_REQ = 0x2501,
	BCMP2P_NOTIF_GO_DISCOVERABILITY_REQ,
	BCMP2P_NOTIF_DEV_DISCOVERABILITY_RSP,

	/* ---------- Link Creation ------------------------------------------ */
	BCMP2P_NOTIF_CREATE_LINK_START = 0x3001,
	BCMP2P_NOTIF_CREATE_LINK_CANCEL,
	BCMP2P_NOTIF_CREATE_LINK_TIMEOUT,
	BCMP2P_NOTIF_CREATE_LINK_AUTH_FAIL,
	BCMP2P_NOTIF_CREATE_LINK_FAIL,

	/* ---------- SoftAP ------------------------------------------ */
	/** SoftAP-creation process starts */
	BCMP2P_NOTIF_SOFTAP_START,

	/** SoftAP is ready to provide the service */
	BCMP2P_NOTIF_SOFTAP_READY,

	/** SoftAP has stopped */
	BCMP2P_NOTIF_SOFTAP_STOP,

	/** SoftAP-creation failed */
	BCMP2P_NOTIF_SOFTAP_FAIL,
	BCMP2P_NOTIF_DHCP_START,
	BCMP2P_NOTIF_DHCP_STOP,
	/** Successful P2P connection - pNotificationData: BCMP2P_PERSISTENT */
	BCMP2P_NOTIF_CREATE_LINK_COMPLETE,
	BCMP2P_NOTIF_SOFTAP_STA_ASSOC,
	BCMP2P_NOTIF_SOFTAP_STA_DISASSOC,

	/** P2P GC loss of link */
	BCMP2P_NOTIF_LINK_LOSS,

	/* ---------- WPS status -------------------------------------------- */
	BCMP2P_NOTIF_WPS_START = 0x4001,
	BCMP2P_NOTIF_WPS_STATUS_SCANNING,
	BCMP2P_NOTIF_WPS_STATUS_SCANNING_OVER,
	BCMP2P_NOTIF_WPS_STATUS_ASSOCIATING,
	BCMP2P_NOTIF_WPS_STATUS_ASSOCIATED,
	BCMP2P_NOTIF_WPS_STATUS_WPS_MSG_EXCHANGE,
	BCMP2P_NOTIF_WPS_STATUS_DISCONNECTING,
	BCMP2P_NOTIF_WPS_COMPLETE,
	BCMP2P_NOTIF_WPS_PROTOCOL_FAIL,
	BCMP2P_NOTIF_WPS_WRONG_PIN,
	BCMP2P_NOTIF_WPS_TIMEOUT,
	BCMP2P_NOTIF_WPS_SESSION_OVERLAP,
	BCMP2P_NOTIF_WPS_FAIL, /* generic errors */

	/* ---------- Service Discovery-------------------------------------- */
	/** Service Response received - pNotificationData: PBCMP2P_SERVICE_DISCOVERY_PARAM */
	BCMP2P_NOTIF_SVC_RESP_RECEIVED = 0x5001,

	/** Service Request received. */
	BCMP2P_NOTIF_SVC_REQ_RECEIVED,

	/** Failed to decode service frame */
	BCMP2P_NOTIF_SVC_FAIL_TO_DECODE,

	/** Service Comeback Response received. */
	BCMP2P_NOTIF_SVC_COMEBACK_RESP_RECEIVED,

	/** Service Comeback Request received. */
	BCMP2P_NOTIF_SVC_COMEBACK_REQ_RECEIVED,

	/** Session to request service completed */
	BCMP2P_NOTIF_SVC_REQ_COMPLETED,

	/** Session to respond service completed */
	BCMP2P_NOTIF_SVC_RSP_COMPLETED,

	/* ---------- Miscellaneous ----------------------------------------- */
	/* Primary Interface disconnected */
	BCMP2P_NOTIF_PRIMARY_IF_DISCONNECTED = 0x6001

} BCMP2P_NOTIFICATION_CODE;

/**
 *  Notification callback function type.
 *
 * @param notificationCode  Notification type.
 * @param pCallbackContext  Application handle provided in the
 *                          BCMP2PRegisterNotification() call.
 * @param pNotificationData Temporary structure containing additional data
 *                          specific to the notification type.  The data type
 *                          of this structure is documented next to each entry
 *                          in the BCMP2P_NOTIFICATION_CODE enum. If no data
 *                          type is mentioned there then there is no data and
 *                          this pointer will be NULL.
 * @param notificationDataLength Length of data pointed to by pNotificationData.
 */
typedef void (*BCMP2P_NOTIFICATION_CALLBACK) (BCMP2P_NOTIFICATION_CODE
	notificationCode, void *pCallbackContext,
	void *pNotificationData, int notificationDataLength);

/**
 * Register for Notifications.
 *
 * Register for notifications of when certain events occur. Notifications can
 * occur at the P2P devices discovery or link-creation time. After this function
 * has been called, it can be called again later to replace the callback function
 * or the notification bitmask.
 *
 * @param notificationType  Specifies the types of notifications which the client
 *                          would like to be notified of, using values from
 *                          BCMP2P_NOTIFICATION_TYPE OR'd together.
 * @param funcCallback      Client specified callback which will receive the
 *                          notifications.
 * @param pCallbackContext  Client specified context - it will be passed to the
 *                          funcCallback as a parameter when the notification occurs.
 * @param pReserved         This is reserved and it should be set to NULL.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PRegisterNotification(int notificationType,
	BCMP2P_NOTIFICATION_CALLBACK funcCallback, void *pCallbackContext,
	void *pReserved);

/**
 * Unregister for Notifications.
 *
 *   Unregister for all notifications of when certain events occur.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PUnRegisterNotification(void);


/** Debug log levels */
typedef enum {
	/** Must be first - used as parameter in log functions to specify always
	 *  output the log independent of log level set by user.
	 */
	BCMP2P_LOG_ALWAYS,
	BCMP2P_LOG_OFF,			/**< No logs */
	BCMP2P_LOG_ERR,			/**< Only ERR level logs outputted */
	BCMP2P_LOG_WARN,		/**< ERR + WARN + MED level logs outputted */
	BCMP2P_LOG_MED,			/**< ERR + WARN + MED level logs outputted */
	BCMP2P_LOG_INFO,		/**< ERR + WARN + MED + INFO level logs outputted */
	BCMP2P_LOG_VERB,		/**< ERR + WARN + MED + INFO + VERB logs outputted */
	BCMP2P_LOG_VERB_EVENT,		/**< BCMP2P_LOG_VERB + VERB_EVENT logs outputted */
	BCMP2P_LOG_VERB_DATALOCK,	/**< BCMP2P_LOG_VERB_EVENT + DATALOCK logs outputted */
	BCMP2P_LOG_VERB_CLIENT_ASSOC, /**< BCMP2P_LOG_VERB+VERB_EVENT+DATALOCK+CLIENT_ASSOC logs */
	BCMP2P_LOG_LEVEL_MAX
} BCMP2P_LOG_LEVEL;

/**
 *  Enable/Disable logging at run time
 *
 * @param logLevel  Controls which level of logs are printed.
 */
BCMP2P_API void  BCMP2PLogEnable(BCMP2P_LOG_LEVEL logLevel);

/**
 *  Get the current log level
 */
BCMP2P_API BCMP2P_LOG_LEVEL  BCMP2PGetLogEnable(void);

/**
 * Application-specific log output function type.
 *
 * @param pCallbackContext  Client specified context - it will be passed to the
 *                          funcCallback as a parameter when the notification occurs.
 * @param pReserved         This is reserved and it should be set to NULL.
 * @param level             Logging level.
 * @param print_timestamp   Should time-stamp be printed?
 * @param logStr            String to log.
 */
typedef void (*BCMP2P_LOG_CALLBACK) (void *pCallbackContext, void *pReserved,
	BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp, char *logStr);

/**
 * Register an application-specific log output handler.
 *
 * When an app-specific log handler is registered, calls to p2papi_osl_log()
 * will be replaced with calls to this handler.
 *
 * @param funcCallback  Application log output handler function. Set to NULL
 *                      to unregister.
 * @param pCallbackContext  Client specified context - it will be passed to the
 *                          funcCallback as a parameter when the notification occurs.
 * @param pReserved         This is reserved and it should be set to NULL.
 */
BCMP2P_API void BCMP2PLogRegisterLogHandler(BCMP2P_LOG_CALLBACK funcCallback,
	void *pCallbackContext, void *pReserved);


/* End of Common group. */
/** @} */


/****************************************************************************
*/

/**
 * @addtogroup WiFiDirect
 * @{
 */


/*
 * Data types related to peer discovery:
 */

#define BCMP2P_MAX_SSID_LEN	32


#ifndef SOFTAP_ONLY

/** Discovery parameters */
typedef struct BCMP2P_DISCOVER_PARAM
{
	/** Specifies a time interval for device discovery, in seconds. After this
	 *  interval, the device will stop discovering peers and will
	 *  also stop being discoverable by other peers. If 0, a default value
	 *  will be used.
	 */
	BCMP2P_UINT32	social_timeout;

	/** Specifies a scan-interval value, in ms. It specifies the duration of
	 *  the Discovery's initial 802.11 scan for existing P2P groups and legacy
	 *  APs. If 0, a default value will be used.
	 */
	BCMP2P_UINT32 	scan_interval;

	/** ASCII string containing the friendly name of the device.  Does not
	 *  need to be null-terminated. If 'ssid' is an empty string, the MAC
	* address of the device will be used instead.
	 */
	BCMP2P_UINT8	ssid[BCMP2P_MAX_SSID_LEN];

	/** Number of characters in 'ssid'. */
	BCMP2P_UINT32	ssidLength;

	/** Our L2 services to advertise to other peers - bit flags defined
	 *  by BCMP2P_SERVICES. This field will be added to the P2P IE and will
	 *  show up in probe requests/responses.
	 */
	BCMP2P_UINT32	services;

	/** Specifies the listen channel to park on to listen for probe requests
	 *  during the Listen phases of the P2P SIG discovery procedure. If 0,
	 *  a default value will be used.
	 */
	BCMP2P_CHANNEL	socialChannel;

	/** Requested device type - BCMP2P_DEVICE_TYPE_CAT_xxx */
	BCMP2P_UINT8	reqDevType;		/*  */

	/** Requested device subtype - BCMP2P_DEVICE_TYPE_SUB_CAT_xxx */
	BCMP2P_UINT8	reqDevSubCat;

	/** Listen-only mode: if true, skip the initial 802.11 scan and then enter
	 *  Listen state instead of cycling between Search and Listen.
	 */
	BCMP2P_BOOL	isListenOnly;

	/** Whether to skip the initial 802.11 scan for P2P Groups */
	BCMP2P_BOOL	skipGroupScan;

	/** Whether to keep the previous discovered peers list */
	BCMP2P_BOOL	keepPrevPeersList;

	/** Whether to show non-P2P WPS APs in the initial 802.11 scan. */
/*	BCMP2P_BOOL		showNonp2pAPs; */


	/** Service query list size. */
	BCMP2P_UINT32	svcQueryListSize;

	/** Pointing to query list buffer */
	BCMP2P_UINT8	*svcQueryEntries;
} BCMP2P_DISCOVER_PARAM, *PBCMP2P_DISCOVER_PARAM;

/** P2P Capability subelement's Device Capability Bitmap bit values
 *  (supported by the device and the discovered device)
 */
typedef enum {
	BCMP2P_CAPSE_DEV_SERVICE_DIS	= 0x1,	/* Service Discovery */
	BCMP2P_CAPSE_DEV_CLIENT_DIS		= 0x2,	/* Client Discoverability */
	BCMP2P_CAPSE_DEV_CONCURRENT		= 0x4,	/* Concurrent Operation */
	BCMP2P_CAPSE_DEV_INFRA_MAN		= 0x8,	/* P2P Infrastructure Managed */
	BCMP2P_CAPSE_DEV_LIMIT			= 0x10,	/* P2P Device Limit */
	BCMP2P_CAPSE_INVITE_PROC		= 0x20	/* P2P Invitation Procedure */
} BCMP2P_DEVICE_CAPABILITY;

/** P2P Capability subelement's Group Capability Bitmap bit values
 *  (supported by the device and the discovered device)
 */
typedef enum {
	BCMP2P_CAPSE_GRP_OWNER		= 0x1,	/* P2P Group Owner */
	BCMP2P_CAPSE_PERSIST_GRP	= 0x2,	/* Persistent P2P Group */
	BCMP2P_CAPSE_GRP_LIMIT		= 0x4,	/* P2P Group Limit */
	BCMP2P_CAPSE_GRP_INTRA_BSS	= 0x8,	/* Intra-BSS Distribution */
	BCMP2P_CAPSE_GRP_X_CONNECT	= 0x10,	/* Cross Connection */
	BCMP2P_CAPSE_GRP_PERSISTENT	= 0x20,	/* Persistent Reconnect */
	BCMP2P_CAPSE_GRP_FORMATION	= 0x40	/* Group Formation */
} BCMP2P_GROUP_CAPABILITY;

/** Discovered peer's state. */
typedef struct BCMP2P_DISCOVER_ENTRY
{
	/** Specifies the length of this entry in bytes. */
	BCMP2P_UINT32	length;

	/** Null-terminated device friendly name. */
	BCMP2P_UINT8	ssid[BCMP2P_MAX_SSID_LEN + 1];

	/** Length of a SSID in bytes. */
	BCMP2P_UINT32	ssidLength;

	/** Device's P2P Device Address */
	BCMP2P_UINT8	mac_address[6];

	/** Channel the device is listening on. */
	BCMP2P_CHANNEL	channel;

	/** RSSI of discovered device */
	BCMP2P_INT16	rssi;

	/** L2 services supported by the device - bit flags defined by BCMP2P_SERVICES. */
	BCMP2P_UINT32	services;

	/** Is an active P2P Group Owner */
	BCMP2P_BOOL 	is_p2p_group;

	/** Device's P2P Interface Address.  Valid only if device is a P2P GO. */
	BCMP2P_UINT8	int_address[6];

	/** Is a stored Persistent GO */
	BCMP2P_BOOL 	is_persistent_go;

	/** Defined by WPS device password ID IE. */
	BCMP2P_UINT32		wps_device_pwd_id;

	/** Bits defined by WPS config methods IE */
	BCMP2P_UINT32	wps_cfg_methods;

	/** BCMP2P_SVC_LIST type */
	BCMP2P_UINT8	*svc_resp;

	/** Primary device type */
	struct {
		BCMP2P_UINT8	oui[3];
		BCMP2P_UINT16	category;
		BCMP2P_UINT16	subcategory;
	} primary_dev;

	/* Device Capability Bitmap -- bit flags defined by BCMP2P_DEVICE_CAPABILITY */
	BCMP2P_UINT8		device_capability;
	/* Group Capability Bitmap -- bit flags defined by BCMP2P_GROUP_CAPABILITY */
	BCMP2P_UINT8		group_capability;

	/** Peer IE data */
	BCMP2P_UINT8	*ie_data;
	BCMP2P_UINT16	ie_data_len;

	/** SSID of P2P Group. */
	BCMP2P_UINT8	grp_ssid[BCMP2P_MAX_SSID_LEN];

	/** Length of a group SSID in bytes (non-zero when is_p2p_group is TRUE). */
	BCMP2P_UINT32	grp_ssidLength;

} BCMP2P_DISCOVER_ENTRY, *PBCMP2P_DISCOVER_ENTRY;

typedef struct BCMP2P_CLIENT_LIST {
	BCMP2P_ETHER_ADDR	dev_addr;
	BCMP2P_BOOL		discoverable;
	BCMP2P_ETHER_ADDR	int_addr;
} BCMP2P_CLIENT_LIST, *PBCMP2P_CLIENT_LIST;

/**
 * Start a discovery to find all P2P capable devices.
 *   - Once the discovery process started, applications will be notified via
 *     callbacks. Applications must register BCMP2P_NOTIF_DISCOVER via
 *     BCMP2PRegisterNotification before this call in order to receive these
 *     notifications.
 *   - Applications will receive a BCMP2P_NOTIF_DISCOVER_RESULT_READY via
 *     callback when an intermediate discovery result is available (after each
 *     scan), applications may then call BCMP2PGetDiscoverResult (setting
 *     bPrunedList to false) to get the intermediate result.
 *   - Once the whole discovery process is completed, applications will receive
 *     a BCMP2P_NOTIF_DISCOVER_COMPLETE via callback.  Applications may then
 *     call BCMP2PGetDiscoverResult (setting bPrunedList to true) to get the
 *     final result.  With the intermediate or final list of P2P capable devices,
 *     applications can update their UI if needed.  It is up to the applications
 *     to control how often to update their UI display.
 *
 * @param p2pHandle        P2Pdevice handle returned from the previous
 *                         BCMP2POpen() call.
 * @param pDiscoverParams  Input parameters for discovery.
 *
 * @return  If this function succeeds, a discovery process will be started and a
 *          BCMP2P_SUCCESS is returned to the caller, otherwise an error code,
 *          e.g. BCMP2P_INVALID_PARAMS is returned.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PDiscover(BCMP2PHandle p2pHandle,
                                         PBCMP2P_DISCOVER_PARAM pDiscoverParams);

/**
 * Get the result of a previous discovery issued via BCMP2PDiscover and/or
 * BCMP2PDiscover80211Scan.
 *
 * @param p2pHandle   P2Pdevice handle returned from the previous
 *                    BCMP2POpen call.
 * @param bFinal:     TRUE specifies to retrieve a pruned list (final result),
 *                    otherwise to retrieve a non-pruned list (intermediate result)
 *                    discovered through the latest scan on a social channel.
 * @param pBuffer     Caller-provided buffer to store the result which
 *                    consists of numEntries entries of type BCMP2P_DISCOVERY_ENTRY.
 * @param buffLength  Length of the caller-provided buffer in bytes.
 * @param numEntries  Points to a location to store the number of entries which
 *                    have been copied to the caller-provided buffer.
 *
 * @return If successful, 'numEntries' will be set, a number of entries will be
 *         copied to the pBuffer and a BCMP2P_SUCCESS is returned. If the
 *         caller-provided buffer is not large enough, the function will set
 *         a number of entries it needed in 'numEntries' and return
 *         BCMP2P_NOT_ENOUGH_SPACE.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PGetDiscoverResult(BCMP2PHandle p2pHandle,
                                                  BCMP2P_BOOL bFinal,
                                                  PBCMP2P_DISCOVER_ENTRY pBuffer,
                                                  BCMP2P_UINT32 buffLength,
                                                  BCMP2P_UINT32 *numEntries);

/**
 * Get the result of a previous discovery issued via BCMP2PDiscover and/or
 * BCMP2PDiscover80211Scan.
 *
 * @param p2pHandle   P2Pdevice handle returned from the previous
 *                    BCMP2POpen call.
 * @param bFinal:     TRUE specifies to retrieve a pruned list (final result),
 *                    otherwise to retrieve a non-pruned list (intermediate result)
 *                    discovered through the latest scan on a social channel.
 * @param pBuffer     Caller-provided buffer to store the result which
 *                    consists of numEntries entries of type BCMP2P_DISCOVERY_ENTRY.
 * @param buffLength  Length of the caller-provided buffer in bytes.
 * @param numEntries  Points to a location to store the number of entries which
 *                    have been copied to the caller-provided buffer.
 *
 * @return If successful, 'numEntries' will be set, a number of entries will be
 *         copied to the pBuffer and a BCMP2P_SUCCESS is returned. If the
 *         caller-provided buffer is not large enough, the function will set
 *         a number of entries it needed in 'numEntries' and return
 *         BCMP2P_NOT_ENOUGH_SPACE.
 *
 * Different from BCMP2PGetDiscoverResult(), if an entry has service-response-data/ie-data associated,
 * duplicate copies of HSL data will be allocated and the pointers will be stored in BCMP2P_DISCOVERY_ENTRY.
 * Caller should call BCMP2PFreeDiscoverResultData() to free these memory when they are no longer needed.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PGetDiscoverResult2(BCMP2PHandle p2pHandle,
                                                  BCMP2P_BOOL bFinal,
                                                  PBCMP2P_DISCOVER_ENTRY pBuffer,
                                                  BCMP2P_UINT32 buffLength,
                                                  BCMP2P_UINT32 *numEntries);

/**
 * Get the result of a previous discovery issued via BCMP2PDiscover for a
 * specific peer.
 *
 * @param p2pHandle   P2Pdevice handle returned from the previous
 *                    BCMP2POpen call.
 * @param peerAddr	  Device address of peer.
 * @param pBuffer     Caller-provided buffer to store the result which
 *                    consists of type BCMP2P_DISCOVERY_ENTRY.
 *
 * @return BCMP2P_SUCCESS is returned if peer is found.
 * If peer has service-response-data/ie-data, duplicate copies of HSL data will be allocated and the pointers
 * will be stored in BCMP2P_DISCOVERY_ENTRY. Caller should call BCMP2PFreeDiscoverResultData() to
 * free these memory when they are no longer needed.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetDiscoverPeer(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *peerAddr, PBCMP2P_DISCOVER_ENTRY pBuffer);

/**
 * Free the ie-data/svc-resp buffer associated with each entry returned via BCMP2PGetDiscoverResult2()
 * and BCMP2PGetDiscoverPeer.
 *
 * @param p2pHandle   P2Pdevice handle returned from the previous
 *                    BCMP2POpen call.
 * @param pBuffer     Caller-specified discovered-result buffer which
 *                    consists of numEntries entries of type BCMP2P_DISCOVERY_ENTRY.
 * @param numEntries  number of entries in caller-specified discovered-result buffer
 *
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PFreeDiscoverResultData(BCMP2PHandle p2pHandle,
                                                  PBCMP2P_DISCOVER_ENTRY pBuffer,
                                                  BCMP2P_UINT32 numEntries);

/**
 * Cancel the discovery process started from BCMP2PDiscover.
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 *
 * @return Returns BCMP2P_SUCCESS if successful, otherwise an error code is
 *         returned. If applications have registered for BCMP2P_NOTIF_DISCOVER
 *         notifications, applications will receive a BCMP2P_NOTIF_DISCOVER_CANCEL
 *         via callback when the discovery process is cancelled.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PCancelDiscover(BCMP2PHandle p2pHandle);

/* Suspend discovery */
BCMP2P_STATUS BCMP2PSuspendDiscovery(BCMP2PHandle p2pHandle);

/* Resume discovery */
BCMP2P_STATUS BCMP2PResumeDiscovery(BCMP2PHandle p2pHandle);

/* Do a blocking 802.11 scan to discover Group Owners.  Scan results will be
 * added to the internal discovery results which can obtained by calling
 * BCMP2PGetDiscoverResult.
 * - nprobes    : number of probe reqs per channel, use -1 for default.
 * - dwell_ms   : active dwell time per channel, use -1 for default.
 * - numChannels: Number of channels in the channel list to scan.
 *                use 0 to specify scan all driver-supported channels.
 * - channels:    Channel list to scan or NULL.
 */
BCMP2P_STATUS BCMP2PDiscover80211Scan(BCMP2PHandle p2pHandle,
	BCMP2P_INT32 nprobes, BCMP2P_INT32 dwell_ms,
	BCMP2P_INT32 numChannels, BCMP2P_UINT16* channels);

/** Services supported by us or by a discovered peer */
typedef enum {
	BCMP2P_SVC_FILETFR	= 0x0001,	/**< File Transfer service */
	BCMP2P_SVC_PRINT	= 0x0002,	/**< Print service */
	BCMP2P_SVC_DISPLAY	= 0x0004	/**< Display service */
} BCMP2P_SERVICES;

/** Service Protocol types */
typedef enum {
	BCMP2P_SVC_PROTYPE_ALL		= 0,
	BCMP2P_SVC_PROTYPE_BONJOUR	= 1,
	BCMP2P_SVC_PROTYPE_UPNP		= 2,
	BCMP2P_SVC_PROTYPE_WSD		= 3,
	BCMP2P_SVC_PROTYPE_VENDOR	= 255
} BCMP2P_SVC_PROTYPE;

/** Service Discovery status code */
typedef enum {
	BCMP2P_SD_STATUS_SUCCESS	= 0,
	BCMP2P_SD_STATUS_PROTYPE_NA	= 1,
	BCMP2P_SD_STATUS_INFO_NA	= 2,
	BCMP2P_SD_STATUS_BAD_REQUEST	= 3
} BCMP2P_SD_STATUS;

/**
 * Service Response entry
 */
typedef struct BCMP2P_SVC_ENTRY {
	BCMP2P_UINT8	svcProtol;	/**< BCMP2P_SVC_PROTYPE type */
	BCMP2P_UINT8	tsc_id;
	BCMP2P_UINT8	status;
	BCMP2P_UINT32	dataSize;
	BCMP2P_UINT8	svcData[1];
} BCMP2P_SVC_ENTRY, *PBCMP2P_SVC_ENTRY;

/**
 * List of Service Response entries
 */
typedef struct BCMP2P_SVC_LIST {
	BCMP2P_SD_STATUS	status;
	BCMP2P_UINT32		svcNum;
	BCMP2P_UINT32		dataSize;
	/** List of BCMP2P_SVC_ENTRY bodies with variable size */
	BCMP2P_UINT8		svcEntries[1];
} BCMP2P_SVC_LIST, *PBCMP2P_SVC_LIST;

/**
 * Service discovery notification data
 */
typedef struct BCMP2P_SERVICE_DISCOVERY_PARAM
{
	/** Service discovery peer address */
	BCMP2P_ETHER_ADDR   peerAddress;

	/** Dialog token of request/response, comeback request/response */
	BCMP2P_UINT8 dialogToken;

	/** Comeback delay of response, comeback response */
	BCMP2P_UINT32 comebackDelay;

	/** Fragment ID of comeback response */
	BCMP2P_UINT8 fragmentId;

	/** Length of query request/response */
	BCMP2P_UINT32 length;

} BCMP2P_SERVICE_DISCOVERY_PARAM, *PBCMP2P_SERVICE_DISCOVERY_PARAM;

/**
 * Initiate service discovery with a discovered peer device.
 *
 * @param p2pHandle        Specifies a P2P device handle returned from the previous
 *                         BCMP2POpen call.
 * @param p2pDevice        Peer device to initiate service discovery with.
 * @param svcQueryEntries  A list of service query entries to request from peer.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PDiscoverService(BCMP2PHandle p2pHandle,
                                               BCMP2P_DISCOVER_ENTRY *p2pDevice,
                                               BCMP2P_SVC_LIST *svcQueryEntries);

/**
 * Cancel service discovery with the responding peer device.
 *
 * @param p2pHandle        Specifies a P2P device handle returned from the previous
 *                         BCMP2POpen call.
 * @rspDeviceAddr		   Mac address of the peer device
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PCancelDiscoverService(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *rspDeviceAddr);

/**
 * Retrieve services at the completion of BCMP2PDiscoverService as notified by
 * BCMP2P_NOTIF_SVC_REQ_COMPLETED event.
 *
 * @param p2pHandle        Specifies a P2P device handle returned from the previous
 *                         BCMP2POpen call.
 * @param peerAddr         Peer address of services to be retrieved.
 * @param svcEntries       Pointer returned with services of peer device.
 *                         Returned pointer is valid until BCMP2PDiscoverService
 *                         is invoked again to the same device.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetDiscoverService(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *peerAddr, BCMP2P_SVC_LIST **svcEntries);

/**
 * Register a service to P2P library and return a handle to it.
 *
 * @param p2pHandle     Specifies a P2P device handle returned from the previous
 *                      BCMP2POpen call.
 * @param tscId         Service transaction id.
 * @param svcProtocol   Service protocol.
 * @param queryData     Query data.
 * @param queryDataSize Size of query data.
 * @param respData      Response data.
 * @param respDataSize  Size of response data.
 *
 * @return  Service discovery handle.
 */
BCMP2P_API BCMSVCHandle BCMP2PRegService(BCMP2PHandle p2pHandle, BCMP2P_UINT32 svcId,
                                         BCMP2P_SVC_PROTYPE svcProtocol,
                                         const BCMP2P_UINT8 *queryData,
                                         BCMP2P_UINT32 queryDataSize,
                                         const BCMP2P_UINT8 *respData,
                                         BCMP2P_UINT32 respDataSize);

/**
 * Deregister a service from P2P library.
 *
 * @param p2pHandle     Specifies a P2P device handle returned from the previous
 *                      BCMP2POpen call.
 * @param svcHandle     Service discovery handle.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PDeregService(BCMP2PHandle p2pHandle, BCMP2PHandle svcHandle);

/**
 * Get the current registered service data from the Service Data Store.
 *
 * @param p2pHandle     Specifies a P2P device handle returned from the previous
 *                      BCMP2POpen call.
 * @param svcProtocol   Protocol to search for.
 * @param queryData     Query data used for comparison.
 * @param queryDataLen  Query data size.
 * @param respDataBuf   Buffer to hold response data matching the query.
 * @param respDataLen   Contains the buffer size and service response data size.
 * @param tscId         Generate a service id in SDS for the service request.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetRegisteredService(BCMP2PHandle p2pHandle,
                                                    BCMP2P_SVC_PROTYPE svcProtocol,
                                                    BCMP2P_UINT8 *queryData,
                                                    BCMP2P_UINT32 queryDataLen,
                                                    BCMP2P_UINT8 *respDataBuf,
                                                    BCMP2P_UINT32 *respDataLen,
                                                    BCMP2P_UINT32* svcId);

/**
 * Send provision discovery request to peer.
 *
 * When the peer receives the provision discovery request sent by this call,
 * the peer app will receive the BCMP2P_NOTIF_PROVISION_DISCOVERY_REQUEST
 * notification via a callback.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param configMethod  Config method to be specified in provision discovery request.
 * @param isPeerGo	TRUE if sending provision discovery request to GO
 * @param ssid  SSID of the GO (for isPeerGo is TRUE).
 * @param ssidLen   Length of SSID string (for isPeerGo is TRUE).
 * @param channel  Channel to send provision discovery request.
 * @param dstDevAddr  Device address of destination peer.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSendProvisionDiscoveryRequest(
	BCMP2PHandle p2pHandle, BCMP2P_UINT32 configMethod,
	BCMP2P_BOOL isPeerGo, BCMP2P_UINT8 *ssid, BCMP2P_UINT32 ssidLen,
	BCMP2P_CHANNEL *channel, BCMP2P_ETHER_ADDR *dstDevAddr);

/**
 *  Send provision discovery response to peer.
 *
 *  When the peer receives the provision discovery request sent by this call,
 *  the peer app will receive the BCMP2P_NOTIF_PROVISION_DISCOVERY_RESPONSE
 *  notification via a callback.
 *
 * @param p2pHandle      P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param configMethod   Config method to be specified in provision discovery response.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PSendProvisionDiscoveryResponse(BCMP2PHandle p2pHandle,
                                                               BCMP2P_UINT32 configMethod);

/**
 * This function is DEPRECATED. Please use BCMP2PSendProvisionDiscoveryRequest() instead.
 *
 * Send provision discovery request on invitation.
 *
 * When the peer receives the provision discovery request sent by this call,
 * the peer app will receive the BCMP2P_NOTIF_PROVISION_DISCOVERY_REQUEST
 * notification via a callback.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param configMethods  Config methods to be specified in provision discovery request.
 * @param ssid  SSID of the GO.
 * @param ssidLen   Length of SSID string.
 * @param dstDevAddr  Destination to send the provision discovery request to.
 * @param channel  Channel to send the provision discovery request on.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_STATUS
BCMP2PSendProvisionDiscoveryRequestOnInvite(
	BCMP2PHandle p2pHandle,	BCMP2P_UINT32 configMethods,
	BCMP2P_UINT8 *ssid, BCMP2P_UINT32 ssidLen,
	BCMP2P_ETHER_ADDR *dstDevAddr, BCMP2P_CHANNEL *channel);

/** P2P InviteFlags Bit Field */
#define BCMP2P_INVITE_FLAG_REINVOKE     0x01

/** P2P Invitation Request/Response notification data */
typedef struct BCMP2P_INVITE_PARAM
{
	/** Sender of the P2P Invitation Req action frame */
	BCMP2P_ETHER_ADDR	srcDevAddr;

	/** Dialog token in the received P2P Invitation Req action frame */
	BCMP2P_UINT8		dialogToken;

	/** Rx channel of he received P2P Invitation Request/Response frame */
	BCMP2P_CHANNEL		afChannel;

	/** P2P IE attributes in the received P2P Invitation Req or Rsp frame */
	BCMP2P_ETHER_ADDR	groupBssid;
	BCMP2P_ETHER_ADDR	groupDevAddr;
	BCMP2P_UINT8		groupSsid[BCMP2P_MAX_SSID_LEN];
	BCMP2P_UINT32		groupSsidLength;
	BCMP2P_CHANNEL		operatingChannel;
	BCMP2P_UINT32		goConfigTimeoutMs;
	BCMP2P_UINT32		gcConfigTimeoutMs;
	BCMP2P_UINT8		inviteFlags; /* Invite Req only */

	/** P2P IE attributes in the received P2P Invitation Response frame */
	BCMP2P_UINT8		status;

	/* device name of the inviting device */
	BCMP2P_UINT8		devName[BCMP2P_MAX_SSID_LEN + 1];
} BCMP2P_INVITE_PARAM, *PBCMP2P_INVITE_PARAM;


/**
 * This function is DEPRECATED. Please use BCMP2PSendInviteRequest() instead.
 *
 * Send a P2P Invitation Request from an active Group Owner to a target device
 * to request it to join the group. The target device must be first discovered
 * using P2P discovery.
 *
 *   This API has 2 use cases.  Both are almost the same except for the actions
 *   of the target device.
 *      -  This device is the GO of an invoked persistent group and wants to
 *         invite a former GC to rejoin the group.
 *         - This device's app calls BCMP2PSendInviteReq() to send a P2P
 *           Invitation Request to the former GC of the persistent group.
 *         - This device's app gets a BCMP2P_NOTIF_P2P_INVITE_RSP notification
 *           callback with status=ACCEPT indicating the GC has accepted the
 *           request and will join the group using the GC's saved persistent
 *           group credentials.
 *      - This device is the GO of a non-persistent group and wants to
 *        invite another device to join the group.  (The target device has no
 *        stored credentials for the group.)
 *         - This device's app calls BCMP2PSendInviteReq() to send a P2P
 *           Invitation Request to the target device.
 *         - This device's app gets a BCMP2P_NOTIF_P2P_INVITE_RSP notification
 *           callback with status=ACCEPT indicating the target has accepted the
 *           request and will join the group and start the WPS handshake as
 *           an enrollee.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param pPeerInfo  Points to the information of a P2P peer device, see the
 *                   definition under BCMP2PGetDiscoverResult.
 *
 * @return Returns BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSendInviteReqFromActiveGO(BCMP2PHandle p2pHandle,
                                                         PBCMP2P_DISCOVER_ENTRY pDestPeer);

/**
 * This function is DEPRECATED. Please use BCMP2PSendInviteRequest() instead.
 *
 *  Send a P2P Invitation Request from an inactive Persistent Group Owner to an
 *  inactive former client of this persistent group to request it to join the
 *  group.
 *
 * @param p2pHandle           P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param grp_dev_addr        Group device addresss.
 * @param dst_listen_channel  Listen channel of the target device.
 * @param dstDevAddr          Target device to send the P2P Invitation Request to.
 * @param ssid                SSID of the persistent group owner.
 * @param ssidLen             Length of SSID string.
 *
 * @return Returns BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_STATUS
BCMP2PSendInviteReqFromInactiveGO(BCMP2PHandle p2pHandle,
                                  BCMP2P_ETHER_ADDR *grp_dev_addr,
                                  BCMP2P_CHANNEL *dst_listen_channel,
                                  BCMP2P_ETHER_ADDR *dstDevAddr,
                                  BCMP2P_UINT8 *ssid,
                                  BCMP2P_UINT32 ssidLen);

/**
 * This function is DEPRECATED. Please use BCMP2PSendInviteRequest() instead.
 *
 * Send a P2P Invitation Request from a former Persistent Group Client to a
 * former Persistent Group Owner to request invoking the Persistent Group.
 *
 * The use case for this API:
 *   - This device was a GC in a former persistent group and wants to invoke
 *     the persistent group.
 *   - This device's app calls BCMP2PSendInviteReq() to send a P2P
 *     Invitation Request to the former GO of the persistent group.
 *   - This device's app gets a BCMP2P_NOTIF_P2P_INVITE_RSP notification
 *     callback with status=ACCEPT indicating the GO has accepted the
 *     request and will recreate the group.
 *   - This device's app waits for the GO's configuration timeout and then
 *     calls BCMP2PJoinGroupWithCredentials() to connect to the GO using the
 *     app's saved persistent group credentials.
 *
 * @param p2pHandle           P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param grp_dev_addr        Device address of the persistent group owner.
 * @param ssid                SSID of the persistent group owner.
 * @param ssidLen             Length in bytes of the SSID.
 * @param dstAddr             Target device to send the P2P Invitation Request to.
 * @param dst_listen_channel  listen channel of the target device.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSendInviteReqFromGC(BCMP2PHandle p2pHandle,
                                                   BCMP2P_ETHER_ADDR *grp_dev_addr,
                                                   BCMP2P_UINT8 *ssid,
                                                   BCMP2P_UINT32 ssidLen,
                                                   BCMP2P_ETHER_ADDR *dstAddr,
                                                   BCMP2P_CHANNEL *dst_listen_channel);

/**
 * Send a P2P Invitation Request to a target device to request it to join the group.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param dst				  Target device to send the P2P Invitation Request to.
 * @param dst_listen_channel  Listen channel of the target device.
 * @param op_channel          Operating channel of group (required if target is not GO).
 * @param grp_bssid			  BSSID of group (required if target is not GO).
 * @param is_reinvoke         TRUE if reinvoking persistent group.
 * @param grpid_dev_addr      Group device address.
 * @param grpid_ssid		  SSID of the group owner.
 * @param grpid_ssid_len	  Length of SSID.
 *
 *
 * @return Returns BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSendInviteRequest(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *dst, BCMP2P_CHANNEL *dst_listen_channel,
	BCMP2P_CHANNEL *op_channel,
	BCMP2P_ETHER_ADDR *grp_bssid, BCMP2P_BOOL is_reinvoke,
	BCMP2P_ETHER_ADDR *grpid_dev_addr,
	BCMP2P_UINT8 *grpid_ssid, BCMP2P_UINT32 grpid_ssid_len);

/** Specifies how to respond to a received P2P Invite Response */
typedef enum {
	BCMP2P_INVITE_PENDING	= 0x0000,
	BCMP2P_INVITE_ACCEPT	= 0x0001,
	BCMP2P_INVITE_REJECT	= 0x0002,
	BCMP2P_INVITE_REJECT_UNKNOWN_GROUP = 0x0004,
	BCMP2P_INVITE_REJECT_NO_COMMON_CHANNEL = 0x0008
} BCMP2P_INVITE_RESPONSE;

/**
 * Send a P2P Invitation Response.
 *
 *   The application calls this API in response to receiving the
 *   BCMP2P_NOTIF_P2P_INVITE_REQ notification callback.
 *
 *   This API can be used in 3 cases:
 *   - This device is a GC in a former persistent group.
 *      - A GO of a persistent group that this device was a member of has
 *        recreated the persistent group sends a P2P Invitation Request to this
 *        device to invite it to rejoin the persistent group.
 *      - This device's app gets a BCMP2P_NOTIF_P2P_INVITE_REQ notification
 *        callback indicating it has received a P2P Invitation Request.
 *      - This device's app immediately calls
 *        BCMP2PSendInviteResp(BCMP2P_INVITE_PENDING) to send back a P2P
 *        Invitation Response with a status code of "The request has been
 *        received and passed up to higher layers".
 *      - The app compares the group ID in the notification data with all of
 *        its stored persistent group IDs.  It finds a match.  (A match means
 *        this is a request to join the persistent group.  No match means this
 *        is a request to join a new P2P group.)
 *      - This device's app prompts the user to accept or reject the request.
 *         - If the user accepts the request:
 *           - the app calls BCMP2PSendInviteResp(BCMP2P_INVITE_ACCEPT) to
 *             send back a P2P Invitation Response with a status code of Success.
 *           - the app waits for the GO's configuration timeout
 *           - the app calls BCMP2PJoinGroupWithCredentials() to connect to the
 *             GO using the app's saved persistent group credentials.
 *         - If the user rejects the request, this device's app calls
 *           BCMP2PSendInviteResp(BCMP2P_INVITE_REJECT) to send back a P2P
 *           Invitation Response with a status code of "Fail; unable to
 *           accomodate request".
 *   - This device was a GO in a former persistent group.
 *      - This device's app gets a BCMP2P_NOTIF_P2P_INVITE_REQ notification
 *        callback indicating it has received a P2P Invitation Request from
 *      - This device receives an P2P Invitation Request from a GC who wants to
 *        invoke the persistent group.
 *      - This device's app calls BCMP2PSendInviteResp() to send an ACCEPT
 *        P2P Invitation Response to the GC.
 *      - This device's app then calls BCMP2PCreatePersistentGroup() to
 *        recreate the persistent group.
 *      - This device's app optionally calls BCMP2PSendInviteReq() for each
 *        of the persistent group's GCs to invite the GCs to rejoin the
 *        persistent group.
 *   - (Unrelated to persistent groups) This device is being invited to join
 *     a P2P group for which this device has no stored credentials.
 *      - A GO of a P2P group sends a P2P Invitation Request to this device to
 *        invite it to join the group.
 *      - This device's app gets a BCMP2P_NOTIF_P2P_INVITE_REQ notification
 *        callback indicating it has received a P2P Invitation Request.
 *      - This device's app immediately calls
 *        BCMP2PSendInviteResp(BCMP2P_INVITE_PENDING) to send back a P2P
 *        Invitation Response with a status code of "The request has been
 *        received and passed up to higher layers".
 *      - The app compares the group ID in the notification data with all of
 *        its stored persistent group IDs.  It finds no match so the app
 *        concludes this is a request to join an unknown P2P group.
 *      - This device's app prompts the user to accept or reject the request.
 *         - If the user accepts the request:
 *            - the app calls BCMP2PSendInviteResp(BCMP2P_INVITE_ACCEPT) to
 *              send back a P2P Invitation Response with a status code of Success.
 *            - the app calls BCMP2PJoinGroupWithWps() to connect to the GO and
 *              start the WPS handshake as an enrollee.
 *        - If the user rejects the request, this device's app calls
 *          BCMP2PSendInviteResp(BCMP2P_INVITE_REJECT) to send back a P2P
 *          Invitation Response with a status code of "Fail; unable to
 *          accomodate request".
 *
 * @param p2pHandle       P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param invitation_req  The data received with the previous
 *                        BCMP2P_NOTIF_P2P_INVITE_REQ P2P Invitation Request
 *                        notification. This identifies who to send the Invitation
 *                        Response to.
 * @param response        Whether to accept, reject, or pend the invitation.
 * @param isGO            Is group owner?
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSendInviteResponse(BCMP2PHandle p2pHandle,
                                                  BCMP2P_INVITE_PARAM *invitation_req,
                                                  BCMP2P_INVITE_RESPONSE response,
                                                  BCMP2P_BOOL isGO);


/**
 * Send a Device Discoverability Request action frame to a P2P Group Owner to
 * request a GO client to become available for communication with us.
 * See section 3.2.4 of WFA P2P spec 1.08.
 *
 * @param p2pHandle     P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param pDstGO     	Destination GO in our discovered peers list
 * @param clientAddr    Target GO client's device address
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSendDevDiscoverabilityReq(BCMP2PHandle p2pHandle,
                                                         PBCMP2P_DISCOVER_ENTRY pDstGO,
                                                         BCMP2P_ETHER_ADDR *clientAddr);

/**
 * Get a discovered GO's Nth GO client from the GO's probe response P2P IE
 * Group Info attribute.
 *
 * @param p2pHandle     P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param pDstGO     	GO in our discovered peers list
 * @param clientIndex  	Index of GO client in GO's P2P IE Group Info attribute.
 * @param clientAddr    output: GO client's device address
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetDiscoveredGOClientInfo(BCMP2PHandle p2pHandle,
                                                         PBCMP2P_DISCOVER_ENTRY pGO,
                                                         int clientIndex,
                                                         BCMP2P_ETHER_ADDR *outClientAddr);


/**
 * Join an existing P2P Group without GO Negotiation, using WPS to obtain the
 * credentials.
 *
 * This function blocks.  It only returns when either:
 *   - A secure connection has been established.
 *   - A WPS or connection error/timeout occurred.
 *   - BCMP2PCancelCreateLink is called before the connection is established.
 *
 * @param p2pHandle     P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param grpBssid      Group BSSID
 * @param grpSsid       P2P Group's SSID.
 * @param grpSsidLen    P2P Groups SSID length, max is BCMP2P_MAX_SSID_LEN.
 * @param grpDevAddr    P2P Group's device address
 * @param grpOpChannel  P2P Group's operating channel
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS
BCMP2PJoinGroupWithWps(BCMP2PHandle p2pHandle, BCMP2P_ETHER_ADDR *grpBssid,
                       BCMP2P_UINT8 *grpSsid, BCMP2P_UINT32 grpSsidLen,
                       BCMP2P_ETHER_ADDR *grpDevAddr, BCMP2P_CHANNEL *grpOpChannel);

/**
 * Join an existing P2P Group using the given WPA2-PSK AES credentials, without
 * GO negotiation, without WPS.
 *
 * This function blocks.  It only returns when either:
 *   - A secure connection has been established
 *   - A WPS or connection error/timeout occurred
 *   - BCMP2PCancelCreateLink is called before the connection is established
 *
 * @param p2pHandle   P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param devAddr	  Device address of Group Owner.
 * @param channel     Group's operating channel.
 * @param ssid        P2P Group's SSID.
 * @param ssidLength  SSID length, max is BCMP2P_MAX_SSID_LEN.
 * @param bssid       BSSID of Group Owner.
 * @param keyWPA      NULL-terminated WPA2-PSK passphrase.
 * @param timeout     Time (in seconds) to try connection before giving up.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS
BCMP2PJoinGroupWithCredentials(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *devAddr, BCMP2P_CHANNEL *channel,
	BCMP2P_UINT8 *ssid, BCMP2P_UINT32 ssidLength,
	BCMP2P_ETHER_ADDR *bssid, BCMP2P_UINT8 *keyWPA,
	BCMP2P_UINT32 timeout);

/**
 * This function is DEPRECATED. Please use BCMP2PCreateLinkToDevAddr() instead.
 *
 * Initiate a P2P connection with a peer device that is on the the discovered
 * peers list.
 *
 * This function will start a P2P Group Owner Negotiation to figure out
 * which device should play a group owner role in the P2P link.  Before this
 * call, client applications must register for
 * BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION to handle the negotiation
 * notifications and accept or reject the connection.  Otherwise the link
 * may not be established.
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 * @param pPeerInfo  Points to the information of a P2P peer device, see the
 *                   definition under BCMP2PGetDiscoverResult.
 * @para timeout     Specifies a time interval in seconds. If the link cannot be
 *                   established within the interval, a timeout notification will
 *                   be sent to the application if such notification has been
 *                   registered.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PCreateLink(BCMP2PHandle p2pHandle,
                                          PBCMP2P_DISCOVER_ENTRY pPeerInfo,
                                          BCMP2P_UINT32 timeout);

/**
 * Cancel the link-creation process started from BCMP2PCreateLink.
 *
 * If applications have registered for BCMP2P_NOTIF_LINK_CREATE
 * notifications, applications will receive a BCMP2P_NOTIF_LINK_CREATE_CANCEL
 * via callback when the link-creation process is cancelled.
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PCancelCreateLink(BCMP2PHandle p2pHandle);

/* Initiate a P2P connection to a device not necessarily on the discovered
 * peers list.
 */
/**
 * Initiate a P2P connection with a peer device that is not necessarily on
 * the discovered peers list.
 *
 * This function will start a P2P Group Owner Negotiation to figure out
 * which device should play a group owner role in the P2P link.  Before this
 * call, client applications must register for
 * BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION to handle the negotiation
 * notifications and accept or reject the connection.  Otherwise the link
 * may not be established.
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 * @param peerDevAddr  Specifies the Device Address of the peer device.
 * @param peerListenChannel  Specifies the listen channel of the peer device.
 * @param isPeerGo   Specifies true if peer is group owner.
 * @param peerIntAddr  Specifies interface address of peer device (0 if isPeerGo is FALSE).
 * @para timeout     Specifies a time interval in seconds. If the link cannot be
 *                   established within the interval, a timeout notification will
 *                   be sent to the application if such notification has been
 *                   registered.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PCreateLinkToDevAddr(BCMP2PHandle p2pHandle,
                                                    BCMP2P_ETHER_ADDR *peerDevAddr,
                                                    BCMP2P_CHANNEL *peerListenChannel,
                                                    BCMP2P_BOOL isPeerGo,
                                                    BCMP2P_ETHER_ADDR *peerIntAddr,
                                                    BCMP2P_UINT32 timeout);

/**
 * Return the clinet list of a peer GO
 *
 * @param peerGO	the intended GO.
 * @param peerGOClientList	the client list of the intended GO
 * @param peerGOClientListLen	the size of the client list buffer
 * @param peerGOClientCount	the count of clients
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetPeerGOClientInfo(BCMP2PHandle p2pHandle,
                                                   BCMP2P_DISCOVER_ENTRY *peerGO,
                                                   BCMP2P_CLIENT_LIST *peerGOClientList,
                                                   BCMP2P_UINT32 peerGOClientListLen,
                                                   BCMP2P_UINT32 *peerGOClientCount);

/**
 *  Process an incoming P2P connection.
 *
 * Call this after receiving BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_COMPLETE
 * if we did not call BCMP2PCreateLink() to initiate a connection.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param timeout_secs Specifies a time interval in seconds. If the link cannot be
 *                     established within the interval, a timeout notification
 *                     will be sent to the applications if such notification has
 *                     been registered.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PProcessIncomingConnection(BCMP2PHandle p2pHandle,
    BCMP2P_UINT32 timeout_secs);
#define BCMP2PCancelProcessIncomingConnection(p2pHandle) \
	BCMP2PCancelCreateLink(p2pHandle)


/* End of WiFiDirect group. */
/** @} */
#endif /* not  SOFTAP_ONLY */

/****************************************************************************
*/

/**
 * @addtogroup Common
 * @{
 */

/**
 * Set the link configuration security to use for incoming connections if
 * the Group Owner Negotiation determines this device will act as an AP.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param pConfig    Specifies a link configuration to use.
 * @param ssid       Specifies the SSID when this device acts as an AP.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetLinkConfig(BCMP2PHandle p2pHandle,
                                             PBCMP2P_CONFIG pConfig, char *ssid);

/* End of Common group. */
/** @} */

/****************************************************************************
*/

/**
 * @addtogroup WiFiDirect
 * @{
 */

/**
 * Set or update the WPA key.
 *
 * @param p2pHandle   P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param key         Buffer of size WSEC_MAX_PSK_LEN to update the
 *                    current WPA2-PSK 64 hex digit PMK.
 * @param passphrase  Buffer of size WSEC_MAX_PSK_LEN to update the current
 *                    WPA2-PSK passphrase.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PUpdateWPAKey(BCMP2PHandle p2pHandle, char *key,
                                            char *passphrase);

#ifndef SOFTAP_ONLY
/**
 * Set up the Group Owner name (prepend "DIRECT-xy" if needed)
 *  - uses the friendly name set with BCMP2PSetFname(), generates a random name if not set
 *
 * @param p2pHandle     P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS
BCMP2PGenerateGoSsid(BCMP2PHandle p2pHandle);


/**
 * Set up device as a Group Owner and wait for clients to connect. Create a soft
 * AP, start the WPS registrar, start the DHCP server.
 *
 * @param p2pHandle     P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param name          NULL-terminated friendly name
 * @param bWaitForever  If FALSE, the group waits up to 3 seconds for client
 *                      connections. When the wait times out, BCMP2PCancelCreateGroup()
 *                      is automatically called. If TRUE, the created Group waits
 *                      forever for client connections, until the application
 *                      calls BCMP2PCancelCreateGroup().
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PCreateGroup(BCMP2PHandle p2pHandle,
                                            BCMP2P_UINT8 *name,
                                            BCMP2P_BOOL bWaitForever);


/**
 * Set frend name.
 *
 * @param p2pHandle     P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param name          NULL-terminated friendly name
 *
 * @return BCMP2P_SUCCESS.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PSetFname(BCMP2PHandle p2pHandle,
                                           char *name);

/**
 * Cancel our created group, disconnecting all clients. Stop the soft AP,
 * WPS registrar, and the DHCP server.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PCancelCreateGroup(BCMP2PHandle p2pHandle);
#endif /* not  SOFTAP_ONLY */

/* End of WiFiDirect group. */
/** @} */

/****************************************************************************
*/

/**
 * @addtogroup SoftAP
 * @{
 */

/**
 *  Set the WPS PIN and starts WPS.
 *
 * - This function only checks the PIN length. It does not check if the PIN
 *   digits make up a valid PIN.
 * - The link configuration should have been previously set via a call one
 *   of the APIs that have a PBCMP2P_CONFIG parameter, eg. BCMP2PSetLinkConfig
 *   BCMP2PCreateGroup, or BCMP2PCreateLink.  Note that subsequent calls
 *   of those APIs will overwrite the PIN set by BCMP2PSetWPSPin.
 * - Sample usage sequence:
 *    - This device's app calls BCMP2PCreateGroup() to create a standalone GO.
 *    - Another P2P device discovers this GO and wants to connect.  The P2P
 *      device generates a random PIN and displays it.
 *    - This device's app prompts the user to enter the PIN, then calls
 *      BCMP2PSetWPSPin() to update the PIN in the running GO.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param pin        Points to an 8-digit null-terminated WPS PIN.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetWPSPin(BCMP2PHandle p2pHandle, char *pin);

/**
 * Get WPS PIN.
 *
 * @param p2pHandle  P2P device handle returned from the previous BCMP2POpen call.
 *
 * @return null terminated PIN or null string if PIN not configured.
 */
char *BCMP2PGetWPSPin(BCMP2PHandle p2pHandle);

/**
 * Generate a random WPS PIN.
 *
 * @param p2pHandle  P2P device handle returned from the previous BCMP2POpen call.
 * @param pin		 Points to BCMP2P_WPS_PIN for random PIN to be returned.
 *
 * - This function only generates a PIN and does not configure WPS with the PIN.
 *   Use BCMP2PSetLinkConfig or BCMP2PSetWPSPin to configure WPS with the PIN.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PRandomWPSPin(BCMP2PHandle p2pHandle, BCMP2P_WPS_PIN *pin);

/**
 * Generate a random passphrase.
 *
 * @param p2pHandle  P2P device handle returned from the previous BCMP2POpen call.
 * @param length	 Length of passphrase to generate
 *                   (between BCMP2P_PASSPHRASE_MIN_LENGTH to BCMP2P_PASSPHRASE_MAX_LENGTH)
 * @param passphrase Points to BCMP2P_PASSPHRASE for random passphrase to be returned.
 *
 * - This function returns a random passphrase.
 *   Use BCMP2PSetLinkConfig to intialize with the passphrase.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PRandomPassphrase(BCMP2PHandle p2pHandle,
	int length,	BCMP2P_PASSPHRASE *passphrase);

/* End of SoftAP group. */
/** @} */


/****************************************************************************
*/

/**
 * @addtogroup WiFiDirect
 * @{
 */

/**
 * This function is DEPRECATED. Please use BCMP2PRandomWPSPin() and
 * BCMP2PRandomPassphrase() instead.
 *
 * Generate a random link configuration for establishing a P2P connection.
 *
 * @param p2pHandle  P2P device handle returned from the previous BCMP2POpen call.
 * @param pConfig    Points a caller-provided buffer that receives the configuration.
 *                   If successful, the link configuration will be set as follows:
 *                      - channelNumber: set to 11.
 *                      - encryption: set to BCMP2P_ALGO_DEFAULT, i.e. AES.
 *                      - authentication: set to BCMP2P_AUTH_DEFAULT, i.e. WPA2-PSK.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGenerateRandomLinkConfig(BCMP2PHandle p2pHandle,
                                                        PBCMP2P_CONFIG pConfig);


/** Peer information. */
typedef struct BCMP2P_PEER_INFO
{
	BCMP2P_UINT32	length;                     /**< Size of this structure */
	BCMP2P_UINT32	ssidLength;
	BCMP2P_UINT8	ssid[BCMP2P_MAX_SSID_LEN];  /**< Not NULL-terminated */
	BCMP2P_UINT8	mac_address[6];
	BCMP2P_UINT32	services;                   /* Bit-flags defined by BCMP2P_SERVICES */
	BCMP2P_BOOL	is_p2p;             /* whether peer is a P2P device */
	BCMP2P_UINT8	ie_data[2048];	/* Allocate max vendor IE data size */
	BCMP2P_UINT16	ie_data_len;
//	BCMP2P_UINT32	customIELength;
//	BCMP2P_UINT8	customIE[1];
} BCMP2P_PEER_INFO, *PBCMP2P_PEER_INFO;

#ifndef SOFTAP_ONLY
/**
 * Get a list of information about connected peer devices.
 *
 * If this function is called from a device which plays a Group Owner role, it
 * returns a list of connected peer devices. If this function is called from a
 * device which plays a non-group owner role, it returns the info of the device
 * which plays a group owner role in the P2P connection.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param pBuffer    Specifies a caller-provided buffer to store the peer information.
 * @param buffLength Specifies the length of the caller-provided buffer in bytes.
 * @param numEntries Points to a location to store the number of entries which
 *                   have been copied to the caller-provided buffer.
 *
 * @return If successful, 'numEntries' will be set, a number of entries will be
 *         copied to the pBuffer and a BCMP2P_SUCCESS is returned. If the
 *         caller-provided buffer is not large enough, the function will set
 *         the number of entries it needed in 'numEntries' and returns
 *         BCMP2P_NOT_ENOUGH_SPACE.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetPeerInfo(BCMP2PHandle p2pHandle,
                                           BCMP2P_PEER_INFO *pBuffer,
                                           BCMP2P_UINT32 buffLength,
                                           BCMP2P_UINT32 *numEntries);


/** Peer address information. */
typedef struct BCMP2P_PEER_IPINFO
{
	BCMP2P_UINT8 mac_address[6];	/**< 48-bit MAC address of peer device */
	BCMP2P_UINT8 ip_address[4];	/**< IP address of peer device */
} BCMP2P_PEER_IPINFO, *PBCMP2P_PEER_IPINFO;

/**
 * Get a list of IP information about connected peer devices.
 *
 * If this function is called from a device which plays a group owner role, it
 * returns a list of the IP info of the connected peer devices. If this function
 * is called from a device which plays a non-group owner role, it returns the
 * IP info of the device which plays a group owner role in the P2P connection.
 *
 * @param p2pHandle   P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param pBuffer     Specifies a caller-provided buffer to store the IP information
 *                    of the peer devices.
 * @param buffLength  Specifies the length of the caller-provided buffer in bytes.
 * @param numEntries  Points to a location to store the number of entries which
 *                    have been copied to the caller-provided buffer.
 *
 * @return If successful, 'numEntries' will be set, a number of entries will be
 *         copied to the pBuffer and a BCMP2P_SUCCESS is returned. If the
 *         caller-provided buffer is not large enough, the function will set
 *         the number of entries it needed in 'numEntries' and returns
 *         BCMP2P_NOT_ENOUGH_SPACE.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetPeerIPInfo(BCMP2PHandle p2pHandle,
                                             PBCMP2P_PEER_IPINFO pBuffer,
                                             BCMP2P_UINT32 buffLength,
                                             BCMP2P_UINT32 *numEntries);


/**
 * Find out if the device is in the discovery state.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return Returns TRUE if the device is in the discovery state, otherwise
 *         returns FALSE.
 */
BCMP2P_API BCMP2P_BOOL BCMP2PIsDiscovering(BCMP2PHandle p2pHandle);

/**
 * Find out if the device is in the listen-only discovery state.
 *
 * @param p2pHandle  P2Pdevice handle from a previous BCMP2POpen call.
 *
 * @return Returns TRUE if the device is in the listen-only discovery state
 */
BCMP2P_API BCMP2P_BOOL BCMP2PIsListenOnly(BCMP2PHandle p2pHandle);

/**
 * Find out if a device is in the link-creation state.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return TRUE if the device is in the link-creation state, otherwise returns FALSE.
 */
BCMP2P_API BCMP2P_BOOL BCMP2PIsConnecting(BCMP2PHandle p2pHandle);

/*
 * Find out if the device is connected as a STA/group-client.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return TRUE if the device is connected as a STA/group client, otherwise
 *         returns FALSE.
 */
BCMP2P_API BCMP2P_BOOL  BCMP2PIsSTA(BCMP2PHandle p2pHandle);

/**
 * Find out if the device is connected as an AP/group owner.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return TRUE if the device is connected as an AP/group owner, otherwise
 *         returns FALSE.
 */
BCMP2P_API BCMP2P_BOOL  BCMP2PIsAP(BCMP2PHandle p2pHandle);

/**
 * Find out if the device is connected as a group owner.
 *
 * This function is different from BCMP2PIsAP(), if a device is running
 * as a SoftAP (not a real P2P group owner), this function will return FALSE.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return TRUE if the device is connected as a group owner, otherwise returns FALSE.
 */
BCMP2P_API BCMP2P_BOOL  BCMP2PIsGroupOwner(BCMP2PHandle p2pHandle);


/**
 * Find out if the device is set provisioning info
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return TRUE if the device is set provisioning info, otherwise return FALSE.
 */
BCMP2P_API BCMP2P_BOOL BCMP2PIsProvision(BCMP2PHandle p2pHandle);


/** Connection status. */
typedef enum {
	BCMP2P_CONNECTED = 1,
	BCMP2P_CONNECTING,
	BCMP2P_AUTHENTICATING,
	BCMP2P_AUTHENTICATED,
	BCMP2P_AUTH_FAILED,
	BCMP2P_NOT_CONNECTED, /**< not connected for other reasons */
} BCMP2P_CONN_STATUS;

/**
 * Find out the connection status of a device.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param outStatus  Points to a location to store the 'connection status'.
 *
 * @return TRUE if successful, otherwise return FALSE.
 */
BCMP2P_API BCMP2P_BOOL  BCMP2PGetConnStatus(BCMP2PHandle p2pHandle,
                                            BCMP2P_CONN_STATUS *outStatus);

#endif /* SOFTAP_ONLY */

/**
 * Get our P2P Device Address.
 *
 * @param p2pHandle   P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param outDevAddr  Our 6-byte P2P Device Address will be copied to here.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetDevAddr(BCMP2PHandle p2pHandle,
                                          BCMP2P_ETHER_ADDR *outDevAddr);

/**
 * Get our P2P Interface Address.
 *
 * @param p2pHandle   P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param outIntAddr  Our 6-byte P2P Interface Address will be copied to here.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetIntAddr(BCMP2PHandle p2pHandle,
                                          BCMP2P_ETHER_ADDR *outIntAddr);

/* End of WiFiDirect group. */
/** @} */

/****************************************************************************
*/

/**
 * @addtogroup Common
 * @{
 */

/**
 * Get WL driver IOCTL.
 *   - WL driver ioctl and iovar definitions are in wlioctl.h.
 *   - These functions operate on the primary BSSCFG.
 *   - They cannot be used to operate on the discovery or connection BSSCFGs.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param cmd        IOCTL command.
 * @param buf        Buffer to place result.
 * @param len        Size of 'buf'.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PIoctlGet(BCMP2PHandle p2pHandle,
                                        int cmd,
                                        void *buf,
                                        int len);

/**
 * Set WL driver IOCTL.
 *   - WL driver ioctl and iovar definitions are in wlioctl.h.
 *   - These functions operate on the primary BSSCFG.
 *   - They cannot be used to operate on the discovery or connection BSSCFGs.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param cmd        IOCTL command.
 * @param buf        IOCTL data to set.
 * @param len        Size of IOCTL data.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PIoctlSet(BCMP2PHandle p2pHandle,
                                        int cmd,
                                        void *buf,
                                        int len);

/**
 * Get WL driver IOVAR.
 *   - WL driver ioctl and iovar definitions are in wlioctl.h.
 *   - These functions operate on the primary BSSCFG.
 *   - They cannot be used to operate on the discovery or connection BSSCFGs.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param iovar      IOVAR command.
 * @param buf        Buffer to place result.
 * @param len        Size of 'buf'.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PIovarGet(BCMP2PHandle p2pHandle,
                                        const char *iovar,
                                        void *buf,
                                        int len);

/**
 * Set WL driver IOVAR.
 *   - WL driver ioctl and iovar definitions are in wlioctl.h.
 *   - These functions operate on the primary BSSCFG.
 *   - They cannot be used to operate on the discovery or connection BSSCFGs.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param iovar      IOVAR command.
 * @param buf        IOVAR data to set.
 * @param len        Size of IOVAR data.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PIovarSet(BCMP2PHandle p2pHandle,
                                        const char *iovar,
                                        void *buf,
                                        int len);

/**
 * Get WL driver IOVAR integer.
 *   - WL driver ioctl and iovar definitions are in wlioctl.h.
 *   - These functions operate on the primary BSSCFG.
 *   - They cannot be used to operate on the discovery or connection BSSCFGs.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param iovar      IOVAR command.
 * @param val        Retrieved integer.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PIovarIntegerGet(BCMP2PHandle p2pHandle,
                                               const char *iovar,
                                               int *val);

/**
 * Set WL driver IOVAR integer.
 *   - WL driver ioctl and iovar definitions are in wlioctl.h.
 *   - These functions operate on the primary BSSCFG.
 *   - They cannot be used to operate on the discovery or connection BSSCFGs.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param iovar      IOVAR command.
 * @param val	     Value to set.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PIovarIntegerSet(BCMP2PHandle p2pHandle,
                                               const char *iovar,
                                               int val);

/**
 * Get WL driver IOVAR buffer.
 *   - WL driver ioctl and iovar definitions are in wlioctl.h.
 *   - These functions operate on the primary BSSCFG.
 *   - They cannot be used to operate on the discovery or connection BSSCFGs.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param iovar      IOVAR command.
 * @param param      IOVAR input parameters.
 * @param paramlen   Length of input parameters.
 * @param bufptr     Client buffer to use to get IOVAR.
 * @param buflen     Length of 'bufptr'.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PIovarBufferGet(BCMP2PHandle p2pHandle,
                                              const char *iovar,
                                              void *param,
                                              int paramlen,
                                              void *bufptr,
                                              int buflen);

/**
 * Set WL driver IOVAR buffer.
 *   - WL driver ioctl and iovar definitions are in wlioctl.h.
 *   - These functions operate on the primary BSSCFG.
 *   - They cannot be used to operate on the discovery or connection BSSCFGs.
 *
 * @param p2pHandle  P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param iovar      IOVAR command.
 * @param param      IOVAR data to set.
 * @param paramlen   Length of IOVAR data to set.
 * @param bufptr     Client buffer to use to set IOVAR.
 * @param buflen     Length of 'bufptr'.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PIovarBufferSet(BCMP2PHandle p2pHandle,
                                              const char *iovar,
                                              void *param,
                                              int paramlen,
                                              void *bufptr,
                                              int buflen);


/* End of Common group. */
/** @} */

/****************************************************************************
*/

/**
 * @addtogroup WiFiDirect
 * @{
 */

/*
 * Data types related to configuring P2P Power Save
 */

/** Special value for the 'count' field in BCMP2P_NOA_DESC */
#define BCMP2P_NOA_DESC_CONTINUOUS	255	/* NoA schedule is continuous */

/** NoA schedule type */
typedef enum {
	BCMP2P_NOA_TYPE_ABS	= 0,	/* Scheduled Absence */
	BCMP2P_NOA_TYPE_REQ_ABS	= 1,	/* Requested Absence */
} BCMP2P_NOA_TYPE;

/** NoA schedule action during absence periods */
typedef enum {
	BCMP2P_NOA_ACTION_NONE	= 0,	/**< No action */
	BCMP2P_NOA_ACTION_DOZE	= 1,	/**< Doze */
	BCMP2P_NOA_ACTION_GOOFF = 2,	/**< Turn off GO beacon/prbrsp functions */
	BCMP2P_NOA_ACTION_RESET	= 255	/**< Reset */
} BCMP2P_NOA_ACTION;


/**
 * NoA schedule option: either specified as a start/interval/duration/count
 * or specified as a percentage of the beacon interval.
 */
typedef enum {
	BCMP2P_NOA_OPTION_NORMAL = 0,	/**< Start/interval/duration/count */
	BCMP2P_NOA_OPTION_BCNPCT = 1,	/**< Beacon interval percentage */
	BCMP2P_NOA_OPTION_TSFOFS = 2	/**< Start being an offset of the 'current' TSF */
} BCMP2P_NOA_OPTION;

/** NoA Descriptor - defines a Notice of Absence timing schedule */
typedef struct BCMP2P_NOA_DESC {
	BCMP2P_UINT32 start;	/**< Schedule start time, TSF timer lower 4 bytes */
	BCMP2P_UINT32 interval;	/**< In microseconds, > 0 */
	BCMP2P_UINT32 duration;	/**< In microseconds, > 0 */
	BCMP2P_UINT32 count;	/**< 1-255, 255 means a continuous schedule */
} BCMP2P_NOA_DESC;

/**
 * Enable P2P Opportunistic Power Save.
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 * @param enable:    Enable/disable opportunistic power save
 * @param ctwindow   Client transmit window
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_STATUS BCMP2PEnableOppPwrSave(BCMP2PHandle p2pHandle, BCMP2P_BOOL enable,
                                     BCMP2P_UINT8 ctwindow);

/**
 * Set the P2P Notice of Absence Schedule
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 * @param type       Scheduled or request
 * @param action     None, doze, or reset
 * @param option     Normal, or beacon percentage
 * @param numDesc    Num descriptors
 * @param desc       Pointer to descriptors
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_STATUS BCMP2PSetNoaSchedule(BCMP2PHandle p2pHandle, BCMP2P_NOA_TYPE type,
                                   BCMP2P_NOA_ACTION action, BCMP2P_NOA_OPTION option,
                                   int numDesc, BCMP2P_NOA_DESC *desc);


/** P2P Presence Request/Response notification data */
typedef struct BCMP2P_PRESENCE_PARAM
{
	/** P2P IE attributes in the received P2P Presence Response frame */
	BCMP2P_UINT8 status;
} BCMP2P_PRESENCE_PARAM, *PBCMP2P_PRESENCE_PARAM;

/**
 * Send presence request to group owner.
 *    - Only a connected client can send presence request to group owner.
 *    - BCMP2P_NOTIF_P2P_PRESENCE_REQ and BCMP2P_NOTIF_P2P_PRESENCE_RSP notifications
 *      will be be received upon receiving request/response.
 *
 * @param p2pHandle           Specifies a P2Pdevice handle returned from the previous
 *                            BCMP2POpen call.
 * @param isPreferred         Set to TRUE to specify preferred duration/interval
 * @param preferredDuration   Preferred duration in microseconds
 * @param prefeffedInterval   Preferred interval in microseconds
 * @param isAcceptable        Set to TRUE to specify acceptable duration/interval
 * @param acceptableDuration  Acceptable duration in microseconds
 * @param acceptableInterval  Acceptable interval in microseconds

 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSendPresenceRequest(BCMP2PHandle p2pHandle,
                                                   BCMP2P_BOOL isPreferred,
                                                   BCMP2P_UINT32 preferredDuration,
                                                   BCMP2P_UINT32 preferredInterval,
                                                   BCMP2P_BOOL isAcceptable,
                                                   BCMP2P_UINT32 acceptableDuration,
                                                   BCMP2P_UINT32 acceptableInterval);


/**
 * Get the OS network interface name of the connected P2P connection.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return Network interface name (eg. "wl0.1") or an empty string if not connected.
 */
BCMP2P_API char* BCMP2PGetNetifName(BCMP2PHandle p2pHandle);

/**
 * Get our randomly generated P2P Group Owner name.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return Pointer to our generated GO name (eg. "DIRECT-xx"). (This is a
 *         pointer to the library's copy of the string, do not attempt to free it.)
 */
BCMP2P_API char* BCMP2PGetGOName(BCMP2PHandle p2pHandle);


/**
 * Get our Group Owner connection credentials.
 *
 * @param p2pHandle      P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param outSSID        Points to a buffer of size BCMP2P_MAX_SSID_LEN to store the
 *                       retrieved SSID.
 * @param outKeyWPA      Buffer of size WSEC_MAX_PSK_LEN to store the retrieved
 *                       WPA2-PSK 64 hex digit PMK.
 * @param outPassphrase  Buffer of size WSEC_MAX_PSK_LEN to store the
 *                       retrieved WPA2-PSK passphrase.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS  BCMP2PGetGOCredentials(BCMP2PHandle p2pHandle,
                                                 BCMP2P_UINT8 *outSSID,
                                                 BCMP2P_UINT8 *outKeyWPA,
                                                 BCMP2P_UINT8 *outPassphrase);

/**
 * Get the P2P Device Address of the Group owner that we are connect to.
 *
 * @param p2pHandle     P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param outGODevAddr  6-byte P2P Device Address will be copied to here.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetGODevAddr(BCMP2PHandle p2pHandle,
                                            BCMP2P_ETHER_ADDR *outGODevAddr);


/**
 * Enable persistent group capability.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param enable       Enable/disable persistent group capability.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PEnablePersistent(BCMP2PHandle p2pHandle,
                                                BCMP2P_BOOL enable);

/**
 * Determine if persistent group capability is set.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return TRUE if persistent group capability, else FALSE.
 */
BCMP2P_API BCMP2P_BOOL BCMP2PIsPersistentEnabled(BCMP2PHandle p2pHandle);

/**
 * Determine if we are in a persistent group.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_BOOL BCMP2PInPersistentGroup(BCMP2PHandle p2pHandle);

/**
 * Enable/disable extended listen timing.
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 * @param isEnable   TRUE to enable, FALSE to disable
 * @param period     Extended listen timing period in msec (cannot be greater than interval)
 * @param interval   Extended listen timing interval in msec
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PExtendedListenTiming(BCMP2PHandle p2pHandle,
       BCMP2P_BOOL isEnable, BCMP2P_UINT32 period, BCMP2P_UINT32 interval);


/**
 *  Wait for the peer to disconnect. Returns only when the peer disconnects.
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 *
 * @return TRUE if in persistent group, else FALSE.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PWaitForDisconnect(BCMP2PHandle p2pHdl);

/* Power saving mode */
typedef enum {
	BCMP2P_PS_WAKEUP = 0,	/* No power saving */
	BCMP2P_PS_LEGACY,	/* 802.11 standard */
	BCMP2P_PS_ENHANCED	/* Broadcom enhanced */
} BCMP2P_PS_MODE;

/**
 * Set power saving mode
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 * @param mode       power saving mode
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetPowerSavingMode(BCMP2PHandle p2pHandle,
                                                  BCMP2P_PS_MODE mode);

/**
 * Get power saving mode
 *
 * @param p2pHandle  Specifies a P2Pdevice handle returned from the previous
 *                   BCMP2POpen call.
 * @param mode       power saving mode
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetPowerSavingMode(BCMP2PHandle p2pHandle,
                                                  BCMP2P_PS_MODE *mode);

/**
 * Enable intra-BSS capability.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param enable       Enable/disable intra-BSS capability.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PEnableIntraBss(BCMP2PHandle p2pHandle,
                                              BCMP2P_BOOL enable);


/**
 * Enable concurrent operation capability.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param enable       Enable/disable concurrent operaion.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PEnableConcurrent(BCMP2PHandle p2pHandle,
                                                BCMP2P_BOOL enable);


/**
 * Enable P2P invitation capability.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param enable       Enable/disable P2P invitation.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PEnableInvitation(BCMP2PHandle p2pHandle,
                                                BCMP2P_BOOL enable);


/**
 * Enable service discovery capability.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param enable       Enable/disable service discovery.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PEnableServiceDiscovery(BCMP2PHandle p2pHandle,
                                                      BCMP2P_BOOL enable);


/**
 * Enable client discovery capability.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param enable       Enable/disable client discovery.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PEnableClientDiscovery(BCMP2PHandle p2pHandle,
                                                     BCMP2P_BOOL enable);


/**
 * Set the operating channel.
 *
 * @param p2pHandle     P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param channel_class	Channel class.
 * @param channel       Operating channel.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetOperatingChannel(BCMP2PHandle p2pHandle,
	BCMP2P_CHANNEL_CLASS channel_class, BCMP2P_UINT32 channel);

/**
 * Get the operating channel.
 *
 * @param p2pHandle     P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param channel_class	Channel class returned.
 * @param channel       Operating channel returned.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 *
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetOperatingChannel(BCMP2PHandle p2pHandle,
	BCMP2P_CHANNEL_CLASS *channel_class, BCMP2P_UINT32 *channel);

/**
 * Set the intent value.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param intent       Intent value.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetIntent(BCMP2PHandle p2pHandle,
                                         BCMP2P_UINT32 intent);

/**
 * Get the intent value.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return BCMP2P_UINT32 Intent value.
 */
BCMP2P_API BCMP2P_UINT32 BCMP2PGetIntent(BCMP2PHandle p2pHandle);

/**
 * Select the WPS config method to be used for group owner negotiation.
 *
 * This function is required if provision discovery is not used.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param configMethod Config method to be used for connection.
 *                     BCMP2P_WPS_DISPLAY or BCMP2P_WPS_KEYPAD for pin input.
 *                     BCMP2P_WPS_PUSHBUTTON for pushbutton input.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSelectWpsConfigMethod(BCMP2PHandle p2pHandle,
	BCMP2P_WPS_CONFIG_METHOD_TYPE configMethod);

/**
 * Set the supported WPS config methods.
 *
 * WPS config methods supported by device which consists of one or more config methods
 * to be advertised in WPS config methods IE in probe request/response.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param configMethods Bit OR'ed supported config methods.
 *                      eg. BCMP2P_WPS_DISPLAY | BCMP2P_WPS_KEYPAD | BCMP2P_WPS_PUSHBUTTON
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetSupportedWpsConfigMethods(
	BCMP2PHandle p2pHandle, BCMP2P_WPS_CONFIG_METHODS configMethods);

/**
 * Get the supported WPS config methods.
 *
 * WPS config methods supported by device which consists of one or more config methods
 * to be advertised in WPS config methods IE in probe request/response.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return BCMP2P_WPS_CONFIG_METHODS config methods supported.
 */
BCMP2P_API BCMP2P_WPS_CONFIG_METHODS BCMP2PGetSupportedWpsConfigMethods(
	BCMP2PHandle p2pHandle);


/**
 * Push WPS pushbutton and starts WPS.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PPushButton(BCMP2PHandle p2pHandle);


/**
 * Set the listen interval - used to indicate to the AP how often a STA in power
 *                           save mode wakes to listen to Beacon management frames.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param interval     Listen interval in beacons. Set to 0 for default.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetListenInterval(BCMP2PHandle p2pHandle,
                                                 unsigned int interval);

/**
 * Set the primary device type in the WPS IE attribute.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param category	   Category defined by BCMP2P_DEVICE_TYPE_CAT_XYZ.
 * @param subCategory  Subcategory defined by BCMP2P_DEVICE_TYPE_SUB_CAT_XYZ.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetPrimaryDeviceType(BCMP2PHandle p2pHandle,
	BCMP2P_UINT8 category, BCMP2P_UINT8 subCategory);

/**
 * Get channel class for a specified channel.
 *
 * @param chanspec          Channel to be converted.
 * @param channel_class     Channel class returned.
 *
 * @return BCMP2P_TRUE if successful, otherwise BCMP2P_FALSE.
 */
BCMP2P_API BCMP2P_BOOL BCMP2PChanspecToChannel(BCMP2P_UINT16 inChanspec,
	BCMP2P_CHANNEL *outChannel);

/*
 * Get channel in 'chanspec' format from a HSL channel
 */
BCMP2P_API BCMP2P_BOOL BCMP2PChannelToChanspec(BCMP2P_CHANNEL *inChannel,
	BCMP2P_UINT16 *outChanspec);

/**
 * Get channel class for a specified channel.
 *
 * @param channel           Channel to be converted.
 * @param is_40mhz          TRUE if channel is 40Mhz else FALSE.
 * @param channel_class     Channel class returned.
 *
 * @return BCMP2P_TRUE if successful, otherwise BCMP2P_FALSE.
 */
BCMP2P_API BCMP2P_BOOL BCMP2PGetChannelClass(BCMP2P_UINT32 channel,
	BCMP2P_BOOL is_40mhz, BCMP2P_CHANNEL_CLASS *channel_class);


/** Channel string buffer */
typedef char BCMP2P_CHANNEL_STRING[8];

/**
 * Convert channel to string.
 *
 * @param channel      Channel to be converted.
 * @param buffer       Buffer for converted string output.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PChannelToString(BCMP2P_CHANNEL *channel,
	BCMP2P_CHANNEL_STRING buffer);

/**
 * Convert string to channel.
 *
 * @param string       String to be converted.
 * @param channel      Channel for converted channel output.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PStringToChannel(char *string,
	BCMP2P_CHANNEL *channel);

/**
 * Set channel list and override the default channel list defined by
 * the WLAN interface.
 * Channel list of zero length restores the default channel list defined
 * by the WLAN interface.
 * The channel list will be used until default channel list is restored.
 * The channel list must include the operating channel.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param numChannels  Number of channels in channels parameter (0 to restore default).
 * @param channels     Array of channels.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetChannelList(BCMP2PHandle p2pHandle,
	int numChannels, BCMP2P_CHANNEL *channels);

/**
 * Channel list returned will either be the default channel list defined
 * by WLAN interface or channel list overriden by BCMP2PSetChannelList.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param maxNumChannels Max channels to be returned.
 * @param channels     Array of channels returned (maxNumChannels capacity).
 * @param numChannels  Number of channels returned in channels parameter.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetChannelList(BCMP2PHandle p2pHandle,
	int maxNumChannels, BCMP2P_CHANNEL *channels, int *numChannels);

/**
 * Channel list returned will be the default channel list defined
 * by WLAN interface
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param maxNumChannels Max channels to be returned.
 * @param channels     Array of channels returned (maxNumChannels capacity).
 * @param numChannels  Number of channels returned in channels parameter.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetDefaultValidChannelList(BCMP2PHandle p2pHandle,
	int maxNumChannels, BCMP2P_CHANNEL *channels, int *numChannels);

/** Persistent data */
typedef struct {
	BCMP2P_BOOL		is_go;				/** TRUE if WE are GO */
	BCMP2P_BOOL		peer_supports_persistence;	/** TRUE if peer supports persistence */
	BCMP2P_ETHER_ADDR	peer_dev_addr;			/** Device address of peer */
	BCMP2P_UINT8		ssid[BCMP2P_MAX_SSID_LEN + 1];	/** SSID of persistent group */
	BCMP2P_UINT8		pmk[64 + 1];			/** PMK credential */
	BCMP2P_UINT8		passphrase[64 + 1];		/** Passphrase (GO only) */
} BCMP2P_PERSISTENT;


/**
 * Connect to specified peer by automatically determining whether to perform group
 * formation, join an existing group, invite, re-invoke a group. The decision is
 * based on the current state of the peers (i.e. GO, STA, not connected) and the
 * availability of persistent data.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param peerDeviceAddr  Device address of target peer.
 * @param persist  Persistent data of target peer (NULL of not available).
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PConnect(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *peerDeviceAddr, BCMP2P_PERSISTENT *persist);

/**
 * Same as BCMP2PConnect except parameters are explicitly specified.
 * These parameters may be obtained from BCMP2P_DISCOVER_ENTRY.
 *
 * @param p2pHandle    P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param peerDeviceAddr  Device address of target peer.
 * @param peerChannel  Channel of target peer.
 * @param isPeerGo     TRUE if target peer is GO.
 * @param peerIntAddr  Interface address of target peer.
 * @param peerSsid     SSID of target peer.
 * @param persist  Persistent data of target peer (NULL of not available).
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PConnect2(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *peerDeviceAddr, BCMP2P_CHANNEL *peerChannel,
	BCMP2P_BOOL isPeerGo, BCMP2P_ETHER_ADDR *peerIntAddr,
	char *peerSsid, BCMP2P_PERSISTENT *persist);


/**
 * Select the operating channel when re-invoke persistent group.
 *
 * @param p2pHandle     P2Pdevice handle returned from the previous BCMP2POpen call.
 * @param opChannel       Operating channel returned.
 *
 * @return BCMP2P_SUCCESS if successful, otherwise an error code indicate no common channel is found.
 *
 */
BCMP2P_API BCMP2P_STATUS
BCMP2PGetReinvokeChannel(BCMP2PHandle p2pHandle, BCMP2P_CHANNEL *opChannel);


/** Generic enhancement to support a P2P application like Wi-Fi Display */
typedef enum { 
	BCMP2P_MGMT_IE_FLAG_BEACON,
	BCMP2P_MGMT_IE_FLAG_PRBREQ,
	BCMP2P_MGMT_IE_FLAG_PRBRSP,
	BCMP2P_MGMT_IE_FLAG_ASSOCREQ,
	BCMP2P_MGMT_IE_FLAG_ASSOCRSP,

	BCMP2P_MGMT_IE_FLAG_TOTAL
} BCMP2P_MGMT_IE_FLAG;

typedef enum { 
	BCMP2P_ACF_IE_FLAG_GONREQ,
	BCMP2P_ACF_IE_FLAG_GONRSP,
	BCMP2P_ACF_IE_FLAG_GONCONF,
	BCMP2P_ACF_IE_FLAG_INVREQ,
	BCMP2P_ACF_IE_FLAG_INVRSP,
	BCMP2P_ACF_IE_FLAG_PDREQ,
	BCMP2P_ACF_IE_FLAG_PDRSP,

	BCMP2P_ACF_IE_FLAG_TOTAL
} BCMP2P_ACF_IE_FLAG;

BCMP2P_API BCMP2P_STATUS
BCMP2PAddMgmtCustomIE(BCMP2PHandle p2pHandle, BCMP2P_MGMT_IE_FLAG ie_flag,
	BCMP2P_UINT8 *ie_buf, BCMP2P_UINT16 ie_buf_len, BCMP2P_BOOL set_immed);

BCMP2P_API BCMP2P_STATUS
BCMP2PAddAcfCustomIE(BCMP2PHandle p2pHandle, BCMP2P_ACF_IE_FLAG ie_flag,
	BCMP2P_UINT8 *ie_buf, BCMP2P_UINT16 ie_buf_len);

BCMP2P_API BCMP2P_STATUS
BCMP2PRemoveMgmtCustomIE(BCMP2PHandle p2pHandle, BCMP2P_MGMT_IE_FLAG ie_flag);

BCMP2P_API BCMP2P_STATUS
BCMP2PRemoveAcfCustomIE(BCMP2PHandle p2pHandle, BCMP2P_ACF_IE_FLAG ie_flag);

typedef BCMP2P_STATUS (*BCMP2P_GONREQ_CALLBACK) (
	BCMP2P_NOTIFICATION_CODE notificationCode, void *pCallbackContext,
	void *pNotificationData, int notificationDataLength);

BCMP2P_API BCMP2P_STATUS
BCMP2PRegisterGonReqCallabck(BCMP2PHandle p2pHandle,
	int notificationType, BCMP2P_GONREQ_CALLBACK funcCallback, 
	void *pCallbackContext,	void *pReserved);

BCMP2P_STATUS
BCMP2PStaStoreUAPSD(BCMP2PHandle p2pHandle, BCMP2P_UINT8 maxSPLength, BCMP2P_UINT8 acBE,
	BCMP2P_UINT8 acBK, BCMP2P_UINT8 acVI, BCMP2P_UINT8 acVO);

/* End of WiFiDirect group. */
/** @} */
#ifdef __cplusplus
}
#endif

#endif /* _BCMP2PAPI_H_ */
