#ifndef _WFD_CAPD_H_
#define _WFD_CAPD_H_

#ifdef __cplusplus
extern "C" {
#endif

/** Basic data types */
typedef unsigned char		WFDCAPD_UINT8;
typedef unsigned short		WFDCAPD_UINT16;
typedef short				WFDCAPD_INT16;
typedef unsigned int		WFDCAPD_UINT32;
typedef int					WFDCAPD_INT32;
typedef unsigned long long	WFDCAPD_UINT64;

typedef int					WFDCAPD_BOOL;
#define	WFDCAPD_FALSE		0
#define WFDCAPD_TRUE		1

/** Maximum number of clients in a P2P based WFD group */
#define WFDCAPD_MAX_GROUP_CIDS	8

/** Status code */
typedef enum {
	/** Generic status code */
	WFDCAPD_SUCCESS = 0,
	WFDCAPD_ERROR,
	WFDCAPD_INVALID_PARAMS,
	WFDCAPD_NOT_ENOUGH_SPACE,
	WFDCAPD_MEMORY_ALLOC_FAIL,
	WFDCAPD_WFD_IE_NOT_FOUND,
	WFDCAPD_WFD_NO_SESS_INFO
} WFDCAPD_STATUS;

/** IP Address type in host order */
typedef WFDCAPD_UINT32 WFDCAPD_IP_ADDR;

#define	WFDCAPD_ETHER_ADDR_LEN	6
/** 48-bit Ethernet MAC address */
typedef struct WFDCAPD_ETHER_ADDR {
	WFDCAPD_UINT8 octet[WFDCAPD_ETHER_ADDR_LEN];
} WFDCAPD_ETHER_ADDR;

/** TDLS specific configuration */
typedef struct WFDCAPD_TDLS_CONFIG {
	WFDCAPD_ETHER_ADDR assoc_bssid;			/* Associated AP mac address. TDLS only */
	WFDCAPD_IP_ADDR	local_ip;				/* Local IPv4 address if connected to AP. TDLS only */
} WFDCAPD_TDLS_CONFIG;

/** WFD device types */
typedef enum {
	WFDCAPD_DEVICE_TYPE_SRC,			/* WFD source */
	WFDCAPD_DEVICE_TYPE_PRIM_SINK,		/* WFD primary sink */
	WFDCAPD_DEVICE_TYPE_SEC_SINK,		/* WFD second sink */
	WFDCAPD_DEVICE_TYPE_SRC_PRIM_SINK	/* WFD srouce and primary sink */
} WFDCAPD_DEVICE_TYPE;

/* WFD connection types */
typedef enum {
	WFDCAPD_CONNECTION_P2P,
	WFDCAPD_CONNECTION_TDLS
} WFDCAPD_CONNECTION_TYPE; 

/* Coupled sink status */
typedef enum {
	WFDCAPD_COUPLE_STATUS_NOT_AVL,		/* Not coupled/available for coupling */
	WFDCAPD_COUPLE_STATUS_COUPLED,		/* Coupled */
	WFDCAPD_COUPLE_STATUS_TEARDOWN		/* Teardown coupling */
} WFDCAPD_COUPLE_STATUS;

/** WFD device configuration */
typedef struct WFDCAPD_CAP_CONFIG {
	/** WFD device type */
	WFDCAPD_DEVICE_TYPE	dev_type;

	/** Is available for WFD session */
	WFDCAPD_BOOL sess_avl;

	/** RTSP port number */
	int				rtsp_tcp_port;			
	
	/** Maximum average througput in Mbps */
	int				max_tput;			

	/** Is coupled sink supported by source or sink */
	WFDCAPD_BOOL	support_cpl_sink;		
	
	/** Is WFD Servive Discovery supported */
	WFDCAPD_BOOL	support_wsd;		

	/** Preferred connection:  P2P or TDLS */
	WFDCAPD_CONNECTION_TYPE preferred_connection;
	
	/** Is content protection via HDCP2.0/2.1 is supported */
	WFDCAPD_BOOL	content_protected;		
	
	/** Time synchronization using 802.1AS supported or not */
	WFDCAPD_BOOL	support_time_sync;		

	/** Couple sink address, all 0 if not coupled */
	WFDCAPD_UINT8	cpl_sink_addr[6];
	
	/** Coupling status */
	WFDCAPD_COUPLE_STATUS cpl_status;

	/** TDLS configuration */
	WFDCAPD_BOOL	tdls_available;
	WFDCAPD_TDLS_CONFIG		tdls_cfg;

	/** Alternative mac address */
	WFDCAPD_ETHER_ADDR alt_mac;

} WFDCAPD_CAP_CONFIG;

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* _WFD_CAPD_H_ */
