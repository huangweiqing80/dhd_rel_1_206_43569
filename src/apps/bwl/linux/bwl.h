/*
 * Linux port of bwl command line utility
 *
 * Copyright (C) 2010, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bwl.h,v 1.17 2010-11-30 23:55:30 $
 */

#include <stdio.h>
#include <stdlib.h>

#ifndef BWL_H__
#define BWL_H__

#include <stdint.h>
#include <stdbool.h>
#define BWL_VERSION_STR "1.0"


//---------------------------------------------------------------------------
// BWL specifics Errors
//---------------------------------------------------------------------------
#define BWL_ERR_SUCCESS     ( 0)
#define BWL_ERR_USAGE       (-1)
#define BWL_ERR_IOCTL       (-2)
#define BWL_ERR_PARAM       (-3)
#define BWL_ERR_CMD         (-4)
#define BWL_ERR_ALLOC       (-5)
#define BWL_ERR_GENERIC   (-256)
//#define BWL_CHECK_ERR(x)    if((x)) {goto BWL_EXIT;}
#define BWL_CHECK_ERR(x)    do{ if((x)) {BWL_DisplayError((x), (char*)__FUNCTION__, __FILE__, __LINE__); goto BWL_EXIT;}} while(0);


#define BWL_INVALID_PIN     0xFFFFFFFF /* some big number */
#define BWL_MAX_CHANNEL     32
#define DOT11_MAX_SSID_LEN  32
#define SIZE_64_BYTES       64
#define ETHER_TYPE_BRCM     0x886c      /* Broadcom Corp. */
#define WSEC_PSK_LEN        64

#define BWL_DEFAULT_SCAN_DWELL_TIME  (-1)

//#define BWL_DEBUG
#ifdef BWL_DEBUG
#define PRINTF(x) printf x
#else
#define PRINTF(x)
#endif

/* Network Operating Mode */
typedef enum eNetOpMode
{
    eNetOpModeAdHoc =   0x000,  /* Ad Hoc Mode */
    eNetOpModeInfra =   0x001   /* Infrastructure Mode */
} NetOpMode_t;

typedef enum e802_11Modes
{
    e802_11_none  =   0x000,
    e802_11_a     =   0x001,
    e802_11_b     =   0x002,
    e802_11_g     =   0x004,
    e802_11_n     =   0x008
} e802_11Modes_t;

typedef enum eCryptoAlgo
{
    eCryptoAlgoOff,
    eCryptoAlgoWep1,
    eCryptoAlgoWep128,
    eCryptoAlgoTkip,
    eCryptoAlgoAesCcm,
    eCryptoAlgoAesOcbMsdu,
    eCryptoAlgoAesOcbMpdu,
    eCryptoAlgoNalg,
    eCryptoAlgoInvalid
} CryptoAlgo_t;


/* Bitmask of Ciphers */
typedef enum eWSec
{
    eWSecInvalid    = 0xff,
    eWSecNone       = 0x01,
    eWSecWep        = 0x02,
    eWSecTkip       = 0x04,
    eWSecAes        = 0x08,
    eWSecAll        = 0x10,
} WSec_t;

typedef enum eWpaAuth
{
    eWpaAuthDisabled    = 0x00,
    eWpaAuthNone        = 0x01,
    eWpaAuthWpaUnsp     = 0x02,
    eWpaAuthWpaPsk      = 0x04,
    eWpaAuthWpa2Unsp    = 0x08,
    eWpaAuthWpa2Psk     = 0x10,
    eWpaAuthInvalid     = 0xff
} WpaAuth_t;

typedef struct sWpaInfo
{
    WSec_t  Cipher;
    uint8_t Akm;
} WpaInfo_t;

typedef struct sWSecPmk
{
    uint16_t KeyLen;        /* octets in key material */
    uint16_t Flags;          /* key handling qualification */
    uint8_t  Key[WSEC_PSK_LEN];  /* PMK material */
} WSecPmk_t;

#define DPT_FNAME_LEN       48  /* Max length of friendly name */

/* structure for dpt friendly name */
typedef struct sDptFName
{
    uint8_t Len;                /* length of friendly name */
    uint8_t Name[DPT_FNAME_LEN];  /* friendly name */
} DptFName_t;

typedef enum eAuthType
{
    eAuthTypeOpen,
    eAuthTypeShare,
    eAuthTypeOpenShare,
    eAuthTypeInvalid
} AuthType_t;

typedef enum eWpaSup
{
    eWpaSupExternal = 0,    /* use external supplicant */
    eWpaSupInternal = 1     /* use internal supplicant */
} WpaSup_t;

typedef enum eBand
{
    eBandAuto,
    eBand5G,
    eBand2G,
    eBandAll,
    eBandInvalid
} Band_t;


typedef struct BWL_P_Handle *BWL_Handle;

typedef char SSID_t[DOT11_MAX_SSID_LEN + 1]; /* +1 for EOS */

typedef struct sCredential
{
    NetOpMode_t     eNetOpMode;     /* 0 == ad hoc, 1 == infrastructure */
    AuthType_t      eAuthType;      /* 0 == open, 1 == share, both */
    WpaAuth_t       eWpaAuth;       /* disable, none, wpa, wpapsk, wpa2, wpa2psk */
    WSec_t          eWSec;          /* wep, tkip, aes */
    WpaSup_t        eWpaSup;        /* 0 == external supplicant, 1 == internal supplicant */
    uint32_t        ulWepIndex;     /* wep key index, ie, primary key */
    uint32_t        ulKeyLen;       /* wep key, or pmk length */
    char            acKey[ SIZE_64_BYTES + 1 ]; /* wep key, pmk */
    char            acSSID[DOT11_MAX_SSID_LEN + 1 ]; /* +1 for EOS */
    struct ether_addr *peBSSID; /* BSSID of the AP */
} Credential_t;

typedef struct sScanInfo
{
    int32_t         lRSSI;
    uint32_t        ulChan;
    uint32_t        ulPhyNoise;
    uint32_t        ulAuthType;
    uint32_t        ul802_11Modes;
    
    struct ether_addr BSSID;

    Credential_t    tCredentials;
    bool            bLocked;
    bool            bWPS;
    int32_t         lRate;
} ScanInfo_t;

typedef struct sDptSta
{
    struct ether_addr mac;
    
    uint8_t     FName[48];
    uint32_t    ulRssi;
    uint32_t    ulTxFailures;
    uint32_t    ulTxPkts;
    uint32_t    ulRxUcastPkts;
    uint32_t    ulTxRate;
    uint32_t    ulRxRate;
    uint32_t    ulRxDecryptSucceeds;
    uint32_t    ulRxDecryptFailures;
} DptSta_t;

typedef struct sDptList
{
    uint32_t    ulNum;
    DptSta_t    Sta[4];
} DptList_t;


typedef struct sDptCredential
{
    WpaAuth_t   eWpaAuth;   /* disable, none, wpa, wpapsk, wpa2, wpa2psk */
    WSec_t      eWSec;      /* wep, tkip, aes */
    WSecPmk_t   Pmk;        /* PMK */
    DptFName_t  FName;      /* Friendly name */
} DptCredential_t;

typedef struct sScanParams
{
    int32_t     lActiveTime;    /* -1 use default, dwell time per channel for
                                 * active scanning
                                 */
    int32_t     lPassiveTime;   /* -1 use default, dwell time per channel
                                 * for passive scanning
                                 */
    int32_t     lHomeTime;      /* -1 use default, dwell time for the home channel
                                 * between channel scans
                                 */
    char        *pcSSID;        /* The name of an AP that we want to fetch 
                                 * scanned info from. This is usefull for 
                                 * fetching credentials from hidden AP's 
                                 */
}ScanParams_t;

/*
 * Structure for passing hardware and software
 * revision info up from the driver.
 */
typedef struct sRevInfo
{
    uint32_t     ulVendorId;    /* PCI vendor id */
    uint32_t     ulDeviceId;    /* device id of chip */
    uint32_t     ulRadioRev;    /* radio revision */
    uint32_t     ulChipRev;     /* chip revision */
    uint32_t     ulCoreRev;     /* core revision */
    uint32_t     ulBoardId;     /* board identifier (usu. PCI sub-device id) */
    uint32_t     ulBoardVendor; /* board vendor (usu. PCI sub-vendor id) */
    uint32_t     ulBoardRev;    /* board revision */
    uint32_t     ulDriverRev;   /* driver version */
    uint32_t     ulUcodeRev;    /* microcode version */
    uint32_t     ulBus;         /* bus type */
    uint32_t     ulChipNum;     /* chip number */
    uint32_t     ulPhyType;     /* phy type */
    uint32_t     ulPhyRev;      /* phy revision */
    uint32_t     ulAnaRev;      /* anacore rev */
    uint32_t     ulChipPkg;     /* chip package info */
} RevInfo_t;

void  BWL_DisplayError(int32_t lErr, const char *pcFunc, char *pcFile, int32_t lLine);
int32_t BWL_IsPresent(uint32_t *pulPresent, char *pcIfName, uint32_t ulLength);
int32_t BWL_Init(BWL_Handle *phBwl);
int32_t BWL_Uninit(BWL_Handle hBwl);
int32_t BWL_GetDriverError(BWL_Handle hBwl, int32_t *plDriverErrCode);
int32_t BWL_Up(BWL_Handle hBwl);
int32_t BWL_Down(BWL_Handle hBwl);
int32_t BWL_IsUp(BWL_Handle hBwl, uint32_t *pulUp);
int32_t BWL_Scan(BWL_Handle hBwl, ScanParams_t *pScanParams);
int32_t BWL_GetScanResults(BWL_Handle hBwl, ScanInfo_t *pData);
int32_t BWL_DisplayScanResults(BWL_Handle hBwl);
int32_t BWL_GetScannedApNum(BWL_Handle hBwl, uint32_t *pNumOfAP);
int32_t BWL_GetConnectedAp(BWL_Handle hBwl, char *pcSSID, uint32_t ulLength, int32_t *plRSSI);
int32_t BWL_GetConnectedInfo(BWL_Handle hBwl, ScanInfo_t *pScanInfo);
int32_t BWL_GetCounter(BWL_Handle hBwl, char *pName, uint32_t *pVal);
int32_t BWL_GetRevInfo(BWL_Handle hBwl, RevInfo_t *pRevInfo);
int32_t BWL_ScanAbort(BWL_Handle hBwl);


int32_t BWL_ConnectNoSec
(
    BWL_Handle    hBwl,        /* [in] BWL Handle */
    NetOpMode_t   eNetOpMode,  /* [in] infrastructure or adhoc */
    char          *pcSSID,     /* [in] SSID of the AP */
    struct ether_addr *peBSSID /* [in] BSSID of the AP */
);

int32_t BWL_ConnectWep
(
    BWL_Handle      hBwl,       /* [in] BWL Handle */
    NetOpMode_t     eNetOpMode, /* [in] infrastructure or adhoc */
    char            *pcSSID,    /* [in] SSID of the AP */
    char            *pcKey,     /* [in] key string */
    uint32_t        ulKeyIndex, /* [in] 0-3 key index */
    AuthType_t      eAuthType,  /* [in] open, shared, open & shared */
    struct ether_addr *peBSSID  /* [in] BSSID of the AP */
);

int32_t BWL_ConnectWpaTkip
(
    BWL_Handle      hBwl,       /* [in] BWL Handle */
    NetOpMode_t     eNetOpMode, /* [in] infrastructure or adhoc */
    char            *pcSSID,    /* [in] SSID of the AP */
    char            *pcKey,     /* [in] key string */
    struct ether_addr *peBSSID  /* [in] BSSID of the AP */
);

int32_t BWL_ConnectWpaAes
(
    BWL_Handle      hBwl,       /* [in] BWL Handle */
    NetOpMode_t     eNetOpMode, /* [in] infrastructure or adhoc */
    char            *pcSSID,    /* [in] SSID of the AP */
    char            *pcKey,     /* [in] key string */
    struct ether_addr *peBSSID  /* [in] BSSID of the AP */
);

int32_t BWL_ConnectWpa2Tkip
(
    BWL_Handle      hBwl,       /* [in] BWL Handle */
    NetOpMode_t     eNetOpMode, /* [in] infrastructure or adhoc */
    char            *pcSSID,    /* [in] SSID of the AP */
    char            *pcKey,     /* [in] key string */
    struct ether_addr *peBSSID  /* [in] BSSID of the AP */
);

int32_t BWL_ConnectWpa2Aes
(
    BWL_Handle      hBwl,       /* [in] BWL Handle */
    NetOpMode_t     eNetOpMode, /* [in] infrastructure or adhoc */
    char            *pcSSID,    /* [in] SSID of the AP */
    char            *pcKey,     /* [in] key string */
    struct ether_addr *peBSSID  /* [in] BSSID of the AP */
);

int32_t BWL_ConnectAp
(
    BWL_Handle      hBwl,   /* [in] BWL Handle */
    Credential_t    *pCred  /* [in] connection credential */
);
int32_t BWL_DisconnectAp(BWL_Handle hBwl);
int32_t BWL_SetCountry(BWL_Handle hBwl, char *pcCountry);
int32_t BWL_GetCountry(BWL_Handle hBwl, char *pcCountry);
int32_t BWL_SetSsid(BWL_Handle hBwl, char *pcSsid, struct ether_addr *peBSSID);
int32_t BWL_GetSsid
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    char        *pcSsid, /* [out] AP SSID */
    uint32_t    *pulLen  /* [out] SSID length */
);
int32_t BWL_GetCachedSsid
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    char        *pcSsid, /* [out] AP SSID */
    uint32_t    *pulLen  /* [out] SSID length */
);
int32_t BWL_GetBssid(BWL_Handle hBwl, struct ether_addr *pbssid);
int32_t BWL_SetBand(BWL_Handle hBwl, Band_t eBand);
int32_t BWL_GetBand(BWL_Handle hBwl, Band_t *peBand);
int32_t BWL_SetChannel(BWL_Handle hBwl, uint32_t ulChan);
int32_t BWL_GetChannel(BWL_Handle hBwl, uint32_t *pulChan);
int32_t BWL_GetChannelsByCountry
(
    BWL_Handle  hBwl,
    char        *pcCountry,
    uint32_t    ulBand,
    uint32_t    aulChannels[],
    uint32_t    *pulChannels
);


/* Supplicant Status for WPA */
typedef enum eSupStatus
{
    eSupStatusDisconnected  = 0,
    eSupStatuseConnecting,
    eSupStatusConnected,
    eSupStatusError,
} SupStatus_t;

/* Event API's */
typedef enum eEventMessage
{
    BWL_E_SET_SSID,         /* indicates status of set SSID */
    BWL_E_JOIN,             /* differentiates join IBSS from found (WLC_E_START) IBSS */
    BWL_E_START,            /* STA founded an IBSS or AP started a BSS */
    BWL_E_AUTH,             /* 802.11 AUTH request */
    BWL_E_AUTH_IND,         /* 802.11 AUTH indication */
    BWL_E_DEAUTH,           /* 802.11 DEAUTH request */
    BWL_E_DEAUTH_IND,       /* 802.11 DEAUTH indication */
    BWL_E_ASSOC,            /* 802.11 ASSOC request */
    BWL_E_ASSOC_IND,        /* 802.11 ASSOC indication */
    BWL_E_REASSOC,          /* 802.11 REASSOC request */
    BWL_E_REASSOC_IND,      /* 802.11 REASSOC indication */
    BWL_E_DISASSOC,         /* 802.11 DISASSOC request */
    BWL_E_DISASSOC_IND,     /* 802.11 DISASSOC indication */
    BWL_E_QUIET_START,      /* 802.11h Quiet period started */
    BWL_E_QUIET_END,        /* 802.11h Quiet period ended */
    BWL_E_BEACON_RX,        /* BEACONS received/lost indication */
    BWL_E_LINK,             /* generic link indication */
    BWL_E_MIC_ERROR,        /* TKIP MIC error occurred */
    BWL_E_NDIS_LINK,        /* NDIS style link indication */
    BWL_E_ROAM,             /* roam attempt occurred: indicate status & reason */
    BWL_E_TXFAIL,           /* change in dot11FailedCount (txfail) */
    BWL_E_PMKID_CACHE,      /* WPA2 pmkid cache indication */
    BWL_E_RETROGRADE_TSF,   /* current AP's TSF value went backward */
    BWL_E_PRUNE,            /* AP was pruned from join list for reason */
    BWL_E_AUTOAUTH,         /* report AutoAuth table entry match for join attempt */
    BWL_E_EAPOL_MSG,        /* Event encapsulating an EAPOL message */
    BWL_E_SCAN_COMPLETE,    /* Scan results are ready or scan was aborted */
    BWL_E_ADDTS_IND,        /* indicate to host addts fail/success */
    BWL_E_DELTS_IND,        /* indicate to host delts fail/success */
    BWL_E_BCNSENT_IND,      /* indicate to host of beacon transmit */
    BWL_E_BCNRX_MSG,        /* Send the received beacon up to the host */
    BWL_E_BCNLOST_MSG,      /* indicate to host loss of beacon */
    BWL_E_ROAM_PREP,        /* before attempting to roam */
    BWL_E_PFN_NET_FOUND,    /* PFN network found event */
    BWL_E_PFN_NET_LOST,     /* PFN network lost event */
    BWL_E_RESET_COMPLETE,
    BWL_E_JOIN_START,
    BWL_E_ROAM_START,
    BWL_E_ASSOC_START,
    BWL_E_IBSS_ASSOC,
    BWL_E_RADIO,
    BWL_E_PSM_WATCHDOG,    /* PSM microcode watchdog fired */
    BWL_E_PROBREQ_MSG,     /* probe request received */
    BWL_E_SCAN_CONFIRM_IND,
    BWL_E_PSK_SUP,         /* WPA Handshake fail */
    BWL_E_COUNTRY_CODE_CHANGED,
    BWL_E_EXCEEDED_MEDIUM_TIME, /* WMMAC excedded medium time */
    BWL_E_ICV_ERROR,       /* WEP ICV error occurred */
    BWL_E_UNICAST_DECODE_ERROR, /* Unsupported unicast encrypted frame */
    BWL_E_MULTICAST_DECODE_ERROR,  /* Unsupported multicast encrypted frame */
    BWL_E_TRACE,
    BWL_E_IF,               /* I/F change (for dongle host notification) */
    BWL_E_RSSI,             /* indicate RSSI change based on configured levels */
    BWL_E_PFN_SCAN_COMPLETE,/* PFN completed scan of network list */
    BWL_E_EXTLOG_MSG,
    BWL_E_ACTION_FRAME,
    BWL_E_PRE_ASSOC_IND,    /* assoc request received */
    BWL_E_PRE_REASSOC_IND,  /* re-assoc request received */
    BWL_E_CHANNEL_ADOPTED,  /* channel adopted */
    BWL_E_AP_STARTED,       /* AP started */
    BWL_E_DFS_AP_STOP,      /* AP stopped due to DFS */
    BWL_E_DFS_AP_RESUME,    /* AP resumed due to DFS */
    BWL_E_LAST,             /* highest val + 1 for range checking */
} EventMessage_t;



int32_t BWL_SetInfraMode(BWL_Handle hBwl, NetOpMode_t eNetOpMode);
int32_t BWL_GetInfraMode(BWL_Handle hBwl, NetOpMode_t *peNetOpMode);
int32_t BWL_SetAuthType(BWL_Handle hBwl, AuthType_t eAuthType);
int32_t BWL_GetAuthType(BWL_Handle hBwl, AuthType_t *peAuthType);
int32_t BWL_SetWpaSup(BWL_Handle hBwl, WpaSup_t eWpaSup);
int32_t BWL_GetWpaSup(BWL_Handle hBwl, WpaSup_t *peWpaSup);
int32_t BWL_SetWpaAuth(BWL_Handle hBwl, WpaAuth_t eWpaAuth);
int32_t BWL_GetWpaAuth(BWL_Handle hBwl, WpaAuth_t *peWpaAuth);
int32_t BWL_SetWSec(BWL_Handle hBwl, WSec_t eWSec);
int32_t BWL_GetWSec(BWL_Handle hBwl, WSec_t *peWSec);
int32_t BWL_SetWSecKey(BWL_Handle hBwl, char *pcKey);
int32_t BWL_GetWSecKey(BWL_Handle hBwl, char* pcKey, uint32_t ulLength);
int32_t BWL_SetWepIndex(BWL_Handle hBwl, uint32_t ulIndex);
int32_t BWL_GetWepIndex(BWL_Handle hBwl, uint32_t *pulIndex);
int32_t BWL_AddWepKey
(
    BWL_Handle      hBwl,
    uint32_t          ulIndex,
    char            *pcKey,
    CryptoAlgo_t    eAlgoOverride, /* used for 16 bytes key */
    uint32_t          ulIsPrimary
);

int32_t BWL_WpsConnectByPb(BWL_Handle hBwl, char *pcNetIf, char *pKey, uint32_t ulKeyLength);
int32_t BWL_WpsConnectByPin
(
    BWL_Handle  hBwl,
    char        *pcNetIf,
    char        *pcSsid,
    uint32_t      ulPin,
    char        *pKey,
    uint32_t    ulKeyLength
);


int32_t BWL_GetCredential(BWL_Handle hBwl, Credential_t *pCredential);
int32_t BWL_GetWepKey
(
    BWL_Handle  hBwl,           /* [in] BWL Handle */
    uint32_t      ulIndex,        /* [in] WEP index 0-3 */
    uint32_t      ulIsPrimary,    /* [in] WEP current used index */
    char        *pcKey,         /* [out] WEP key string */
    uint32_t      *pulLength      /* [out] WEP key length */
);

int32_t BWL_GetLinkStatus(BWL_Handle  hBwl, uint32_t *pulIsLinkUp);



int32_t BWL_GetRpcAgg
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t      *pulAgg  /* [out] Aggregation value */
);

int32_t BWL_SetRpcAgg
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t      ulAgg  /* [in] Aggregation value */
);

int32_t BWL_GetHtRestrict
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t      *pulVal  /* [out] Restrict value */
);

int32_t BWL_SetHtRestrict
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t      ulVal  /* [in] Restrict value */
);

int32_t BWL_GetSisoTx
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t      *pulVal  /* [out] SISO Value */
);

int32_t BWL_SetSisoTx
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t      ulVal  /* [in] SISO Value */
);

int32_t BWL_GetStaRetryTime
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t      *pulVal  /* [out] Value */
);

int32_t BWL_SetStaRetryTime
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t      ulVal  /* [in] Value */
);

int32_t BWL_GetMimoBwCap
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t      *pulVal  /* [out] Value */
);

int32_t BWL_SetMimoBwCap
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t      ulVal  /* [in] Value */
);

int32_t BWL_GetApBwCap
(
    BWL_Handle  hBwl,           /* [in] BWL Handle */
    uint32_t      *pulBandWidth   /* [out] 0 is 20MHz or Not Connect, 1 is 40MHz */
);

int32_t BWL_GetDptCredential
(
    BWL_Handle          hBwl,  /* [in] BWL Handle */
    DptCredential_t    *pCred  /* [out] used to store credential */
);

int32_t BWL_GetDptMode
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t      *pulVal  /* [out] Value */
);

int32_t BWL_SetDptMode
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t      ulVal  /* [in] Value */
);

int32_t BWL_GetRate
(
	BWL_Handle	 hBwl,      /* [in] BWL Handle */
	int32_t     *plRate     /* [out] Rate      */
);

int32_t BWL_SetRSSIEventLevels
(
    BWL_Handle      hBwl,          /* [in] BWL Handle */
    int32_t         *plLevel,      /* [in] value      */
    uint32_t        ulNumLevels    /* [in] value      */
);

int32_t BWL_GetRSSI
(
    BWL_Handle hBwl,    /* [in] BWL Handle */
	int32_t *plRSSI     /* [out] RSSI      */
);

int32_t BWL_GenerateDptKey
(
    BWL_Handle  hBwl,   /* [in] BWL Handle */
    WSecPmk_t   *dptkey /* [out] DPT Key */
);

int32_t BWL_SetDptSecurity
(
    BWL_Handle  hBwl   /* [in] BWL Handle */
);

int32_t BWL_GetDptList
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    DptList_t   *data  /* [out] DPT list */
);

int32_t BWL_SetEvent(BWL_Handle hBwl, EventMessage_t eEvent);
int32_t BWL_ClearEvent(BWL_Handle hBwl, EventMessage_t eEvent);
int32_t BWL_ParseEvent(BWL_Handle hBwl, void *pBuff, uint32_t ulBufLength, EventMessage_t *pEvent);
int32_t BWL_SetOBSSCoEx(BWL_Handle hBwl, uint32_t ulCoEx);
int32_t BWL_Get802_11Modes(BWL_Handle hBwl, uint32_t *pModes);
int32_t BWL_GetWpaSupStatus(BWL_Handle hBwl, SupStatus_t *pStatus);

#endif /* BWL_H__ */
