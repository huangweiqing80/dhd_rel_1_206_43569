/*
 * Linux port of bwl command line utility
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bwl.c,v 1.22 2010-12-16 18:55:10 $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <typedefs.h>
#include <epivers.h>
#include <proto/ethernet.h>
#include <proto/802.11.h>
#include <proto/802.1d.h>
#include <proto/802.11e.h>
#include <proto/wpa.h>
#include <proto/bcmip.h>
#include <wlioctl.h>
#include <bcmutils.h>
#include <bcmendian.h>
#include <bcmwifi_channels.h>
#include <bcmsrom_fmt.h>
#include <bcmsrom_tbl.h>
#include <bcmcdc.h>

#ifdef INCLUDE_WPS
/* wps includes */
#include <portability.h>
#include <wpserror.h>
#include <reg_prototlv.h>
#include <wps_enrapi.h>
#include <wps_enr.h>
#include <wps_enr_osl.h>
#include <wps_sta.h>
#endif
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h> /* ETH_P_ALL */


/* need this for using exec */
#include <unistd.h>
#include <sys/wait.h>
#include "wlu.h"
#define stricmp strcasecmp
#define strnicmp strncasecmp

/* IOCTL swapping mode for Big Endian host with Little Endian dongle.  Default to off */
#define htod32(i) i
#define htod16(i) i
#define dtoh32(i) i
#define dtoh16(i) i
#define htodchanspec(i) i
#define dtohchanspec(i) i
#define htodenum(i) i
#define dtohenum(i) i

#define WL_DUMP_BUF_LEN (127 * 1024)

#ifdef INCLUDE_WPS
/* WPS externs */
wps_ap_list_info_t *create_aplist(void);
void config_init(void);
int find_pbc_ap(char * bssid, char *ssid, uint8 *wsec);
int enroll_device(char *pin, char *ssid, uint8 wsec, char *bssid, char *key, uint32_t key_len);
int display_aplist(wps_ap_list_info_t *ap);
uint32_t wps_generatePin(char c_devPwd[8], int buf_len, IN bool b_display);
#endif
/* WLU externs */
extern int wl_check(void *bwl);
extern int wlu_set(void *wl, int cmd, void *cmdbuf, int len);
extern int wlu_get(void *wl, int cmd, void *cmdbuf, int len);
extern void dump_bss_info(wl_bss_info_t *bi);
extern void dump_networks(char *network_buf);
extern void wl_find(struct ifreq *ifr);
extern int wlu_iovar_set(void *wl, const char *iovar, void *param, int paramlen);
extern int wlu_iovar_get(void *wl, const char *iovar, void *param, int paramlen);
extern uint8 * wlu_parse_tlvs(uint8 *tlv_buf, int buflen, uint key);
extern bool wlu_is_wpa_ie(uint8 **wpaie, uint8 **tlvs, uint *tlvs_len);
extern bool bcm_is_wps_ie(uint8_t *ie, uint8_t **tlvs, uint32_t *tlvs_len);

struct ifreq    ifr;
static char s_bufdata[WLC_IOCTL_MAXLEN];

//---------------------------------------------------------------------------
// BWL specifics
//---------------------------------------------------------------------------
#include "bwl.h"

typedef struct BWL_P_Handle
{
    void    *wl;
} BWL_P_Handle;


typedef struct
{
    Band_t      eBwl;
    uint32_t    eWl;
    const char  *pName;
} BwlToWl_t;


static BwlToWl_t CryptoAlgoTable[] =
{
    { eCryptoAlgoOff,        CRYPTO_ALGO_OFF            , "eCryptoAlgoOff"          },
    { eCryptoAlgoWep1,       CRYPTO_ALGO_WEP1           , "eCryptoAlgoWep1"         },
    { eCryptoAlgoWep128,     CRYPTO_ALGO_WEP128         , "eCryptoAlgoWep128"       },
    { eCryptoAlgoTkip,       CRYPTO_ALGO_TKIP           , "eCryptoAlgoTkip"         },
    { eCryptoAlgoAesCcm,     CRYPTO_ALGO_AES_CCM        , "eCryptoAlgoAesCcm"       },
    { eCryptoAlgoAesOcbMsdu, CRYPTO_ALGO_AES_OCB_MSDU   , "eCryptoAlgoAesOcbMsdu"   },
    { eCryptoAlgoAesOcbMpdu, CRYPTO_ALGO_AES_OCB_MPDU   , "eCryptoAlgoAesOcbMpdu"   },
    { eCryptoAlgoNalg,       CRYPTO_ALGO_NALG           , "eCryptoAlgoNalg"         },
};


static BwlToWl_t WSecTable[] =
{
    { eWSecNone,    0               , "eWSecNone"   },
    { eWSecWep,     WEP_ENABLED     , "eWSecWep"    },
    { eWSecTkip,    TKIP_ENABLED    , "eWSecTkip"   },
    { eWSecAes,     AES_ENABLED     , "eWSecAes"    },
    { eWSecAll,     (WEP_ENABLED | TKIP_ENABLED | AES_ENABLED)     , "eWSecSw"     },
};


static BwlToWl_t AuthTypeTable[] =
{
    { eAuthTypeOpen,      WL_AUTH_OPEN_SYSTEM   , "eAuthTypeOpen"       },
    { eAuthTypeShare,     WL_AUTH_SHARED_KEY    , "eAuthTypeShare"      },
    { eAuthTypeOpenShare, WL_AUTH_OPEN_SHARED   , "eAuthTypeOpenShare"  },
};

static BwlToWl_t WpaAuthTable[] =
{
    { eWpaAuthDisabled, WPA_AUTH_DISABLED   , "eWpaAuthDisabled"},
    { eWpaAuthNone,     WPA_AUTH_NONE       , "eWpaAuthNone"    },
    { eWpaAuthWpaUnsp,  WPA_AUTH_UNSPECIFIED, "eWpaAuthWpaUnsp" },
    { eWpaAuthWpaPsk,   WPA_AUTH_PSK        , "eWpaAuthWpaPsk"  },
    { eWpaAuthWpa2Unsp, WPA2_AUTH_UNSPECIFIED,"eWpaAuthWpa2Unsp"},
    { eWpaAuthWpa2Psk,  WPA2_AUTH_PSK       , "eWpaAuthWpa2Psk" }
};


static BwlToWl_t BandTable[] =
{
    { eBandAuto,        WLC_BAND_AUTO   , "eBandAuto"   },
    { eBand5G,          WLC_BAND_5G     , "eBand5G"     },
    { eBand2G,          WLC_BAND_2G     , "eBand2G"     },
    { eBandAll,         WLC_BAND_ALL    , "eBandAll"    },
};


static BwlToWl_t NetOpModeTable[] =
{
    { eNetOpModeAdHoc,  0,  "eNetOpModeAdHoc"   },
    { eNetOpModeInfra,  1,  "eNetOpModeInfra"   },
};


static BwlToWl_t WpaSupTable[] =
{
    {eWpaSupExternal,   0,  "eWpaSupExternal" },
    {eWpaSupInternal,   1,  "eWpaSupInternal" },
};


static BwlToWl_t EventMessageTable [] =
{
    { BWL_E_SET_SSID,               WLC_E_SET_SSID,                 "WLC_E_SET_SSID"},
    { BWL_E_JOIN,                   WLC_E_JOIN,                     "WLC_E_JOIN"},
    { BWL_E_START,                  WLC_E_START,                    "WLC_E_START"},
    { BWL_E_AUTH,                   WLC_E_AUTH,                     "WLC_E_AUTH"},
    { BWL_E_AUTH_IND,               WLC_E_AUTH_IND,                 "WLC_E_AUTH_IND"},
    { BWL_E_DEAUTH,                 WLC_E_DEAUTH,                   "WLC_E_DEAUTH"},
    { BWL_E_DEAUTH_IND,             WLC_E_DEAUTH_IND,               "WLC_E_DEAUTH_IND"},
    { BWL_E_ASSOC,                  WLC_E_ASSOC,                    "WLC_E_ASSOC"},
    { BWL_E_ASSOC_IND,              WLC_E_ASSOC_IND,                "WLC_E_ASSOC_IND"},
    { BWL_E_REASSOC,                WLC_E_REASSOC,                  "WLC_E_REASSOC"},
    { BWL_E_REASSOC_IND,            WLC_E_REASSOC_IND,              "WLC_E_REASSOC_IND"},
    { BWL_E_DISASSOC,               WLC_E_DISASSOC,                 "WLC_E_DISASSOC"},
    { BWL_E_DISASSOC_IND,           WLC_E_DISASSOC_IND,             "WLC_E_DISASSOC_IND"},
    { BWL_E_QUIET_START,            WLC_E_QUIET_START,              "WLC_E_QUIET_START"},
    { BWL_E_QUIET_END,              WLC_E_QUIET_END,                "WLC_E_QUIET_END"},
    { BWL_E_BEACON_RX,              WLC_E_BEACON_RX,                "WLC_E_BEACON_RX"},
    { BWL_E_LINK,                   WLC_E_LINK,                     "WLC_E_LINK"},
    { BWL_E_MIC_ERROR,              WLC_E_MIC_ERROR,                "WLC_E_MIC_ERROR"},
    { BWL_E_NDIS_LINK,              WLC_E_NDIS_LINK,                "WLC_E_NDIS_LINK"},
    { BWL_E_ROAM,                   WLC_E_ROAM,                     "WLC_E_ROAM"},
    { BWL_E_TXFAIL,                 WLC_E_TXFAIL,                   "WLC_E_TXFAIL"},
    { BWL_E_PMKID_CACHE,            WLC_E_PMKID_CACHE,              "WLC_E_PMKID_CACHE"},
    { BWL_E_RETROGRADE_TSF,         WLC_E_RETROGRADE_TSF,           "WLC_E_RETROGRADE_TSF"},
    { BWL_E_PRUNE,                  WLC_E_PRUNE,                    "WLC_E_PRUNE"},
    { BWL_E_AUTOAUTH,               WLC_E_AUTOAUTH,                 "WLC_E_AUTOAUTH"},
    { BWL_E_EAPOL_MSG,              WLC_E_EAPOL_MSG,                "WLC_E_EAPOL_MSG"},
    { BWL_E_SCAN_COMPLETE,          WLC_E_SCAN_COMPLETE,            "WLC_E_EAPOL_MSG"},
    { BWL_E_ADDTS_IND,              WLC_E_ADDTS_IND,                "WLC_E_ADDTS_IND"},
    { BWL_E_DELTS_IND,              WLC_E_DELTS_IND,                "WLC_E_DELTS_IND"},
    { BWL_E_BCNSENT_IND,            WLC_E_BCNSENT_IND,              "WLC_E_BCNSENT_IND"},
    { BWL_E_BCNRX_MSG,              WLC_E_BCNRX_MSG,                "WLC_E_BCNRX_MSG"},
    { BWL_E_BCNLOST_MSG,            WLC_E_BCNLOST_MSG,              "WLC_E_BCNLOST_MSG"},
    { BWL_E_ROAM_PREP,              WLC_E_ROAM_PREP,                "WLC_E_ROAM_PREP"},
    { BWL_E_PFN_NET_FOUND,          WLC_E_PFN_NET_FOUND,            "WLC_E_PFN_NET_FOUND"},
    { BWL_E_PFN_NET_LOST,           WLC_E_PFN_NET_LOST,             "WLC_E_PFN_NET_LOST"},
    { BWL_E_RESET_COMPLETE,         WLC_E_RESET_COMPLETE,           "WLC_E_RESET_COMPLETE"},
    { BWL_E_JOIN_START,             WLC_E_JOIN_START,               "WLC_E_JOIN_START"},
    { BWL_E_ROAM_START,             WLC_E_ROAM_START,               "WLC_E_ROAM_START"},
    { BWL_E_ASSOC_START,            WLC_E_ASSOC_START,              "WLC_E_ASSOC_START"},
    { BWL_E_IBSS_ASSOC,             WLC_E_IBSS_ASSOC,               "WLC_E_IBSS_ASSOC"},
    { BWL_E_RADIO,                  WLC_E_RADIO,                    "WLC_E_RADIO"},
    { BWL_E_PSM_WATCHDOG,           WLC_E_PSM_WATCHDOG,             "WLC_E_PSM_WATCHDOG"},
//  { BWL_E_CCX_ASSOC_START,        WLC_E_CCX_ASSOC_START,          "WLC_E_CCX_ASSOC_START"},
//  { BWL_E_CCX_ASSOC_ABORT,        WLC_E_CCX_ASSOC_ABORT,          "WLC_E_CCX_ASSOC_ABORT"},
    { BWL_E_PROBREQ_MSG,            WLC_E_PROBREQ_MSG,              "WLC_E_PROBREQ_MSG"},
    { BWL_E_SCAN_CONFIRM_IND,       WLC_E_SCAN_CONFIRM_IND,         "WLC_E_SCAN_CONFIRM_IND"},
    { BWL_E_PSK_SUP,                WLC_E_PSK_SUP,                  "WLC_E_PSK_SUP"},
    { BWL_E_COUNTRY_CODE_CHANGED,   WLC_E_COUNTRY_CODE_CHANGED,     "WLC_E_COUNTRY_CODE_CHANGED"},
    { BWL_E_EXCEEDED_MEDIUM_TIME,   WLC_E_EXCEEDED_MEDIUM_TIME,     "WLC_E_EXCEEDED_MEDIUM_TIME"},
    { BWL_E_ICV_ERROR,              WLC_E_ICV_ERROR,                "WLC_E_ICV_ERROR"},
    { BWL_E_UNICAST_DECODE_ERROR,   WLC_E_UNICAST_DECODE_ERROR,     "WLC_E_UNICAST_DECODE_ERROR"},
    { BWL_E_MULTICAST_DECODE_ERROR, WLC_E_MULTICAST_DECODE_ERROR,   "WLC_E_MULTICAST_DECODE_ERROR"},
    { BWL_E_TRACE,                  WLC_E_TRACE,                    "WLC_E_TRACE"},
//  { BWL_E_HCI_EVENT,              WLC_E_BTA_HCI_EVENT,            "WLC_E_BTA_HCI_EVENT"},
    { BWL_E_IF,                     WLC_E_IF,                       "WLC_E_IF"},
    { BWL_E_RSSI,                   WLC_E_RSSI,                     "WLC_E_RSSI"},
    { BWL_E_PFN_SCAN_COMPLETE,      WLC_E_PFN_SCAN_COMPLETE,        "WLC_E_PFN_SCAN_COMPLETE"},
    { BWL_E_EXTLOG_MSG,             WLC_E_EXTLOG_MSG,               "WLC_E_EXTLOG_MSG"},
//  { BWL_E_ACTION_FRAME,           WLC_E_ACTION_FRAME,             "WLC_E_ACTION_FRAME"},
    { BWL_E_PRE_ASSOC_IND,          WLC_E_PRE_ASSOC_IND,            "WLC_E_PRE_ASSOC_IND"},
    { BWL_E_PRE_REASSOC_IND,        WLC_E_PRE_REASSOC_IND,          "WLC_E_PRE_REASSOC_IND"},
    { BWL_E_CHANNEL_ADOPTED,        WLC_E_CHANNEL_ADOPTED,          "WLC_E_CHANNEL_ADOPTED"},
    { BWL_E_AP_STARTED,             WLC_E_AP_STARTED,               "WLC_E_AP_STARTED"},
    { BWL_E_DFS_AP_STOP,            WLC_E_DFS_AP_STOP,              "WLC_E_DFS_AP_STOP"},
    { BWL_E_DFS_AP_RESUME,          WLC_E_DFS_AP_RESUME,            "WLC_E_DFS_AP_RESUME"},
    { BWL_E_LAST,                   WLC_E_LAST,                     "WLC_E_LAST"}};

#define MCS_INDEX_COUNT 32
static int32_t PhyDataRate_40MHz[MCS_INDEX_COUNT][2] =
{
    { 27,30 },    { 54,60 },    { 81,90 },    { 108,120 },    { 162,180 },    { 216,240 },    { 243,270 },    { 270,300 },
    { 54,60 },    { 108,120 },  { 162,180 },  { 216,240 },    { 324,360 },    { 432,480 },    { 486,540 },    { 540,600 }, /*15 */
    { 81,90 },    { 162,180 },  { 243,270 },  { 324,360 },    { 486,540 },    { 648,720 },    { 728,810 },    { 810,900 },
    { 108,120 },  { 216,240 },  { 324,360 },  { 432,480 },    { 648,720 },    { 864,960 },    { 972,1080 },   { 1080,1200 },
};

static int32_t PhyDataRate_20MHz[MCS_INDEX_COUNT][2] =
{
    { 13,14},    { 26,29},    { 39,43},    { 52,58},    { 78,87},    { 104,116},    { 117,130},    { 130,144},
    { 26,29},    { 52,58},    { 78,87},    { 104,116},  { 156,173},  { 208,231},    { 234,260},    { 260,289}, /* 15 */
    { 39,43},    { 78,87},    { 117,130},  { 156,173},  { 234,260},  { 312,347},    { 351,390},    { 390,433},
    { 52,58},    { 104,116},  { 156,173},  { 208,231},  { 312,347},  { 416,462},    { 468,520},    { 520,578},
};

void wl_rsn_ie_dump(bcm_tlv_t *ie, WpaInfo_t *info);

int32_t
BWL_SetOBSSCoEx(BWL_Handle hBwl, uint32_t ulCoEx)
{ 
    int32_t      err = 0;
    void         *wl = hBwl->wl; 

    err = wlu_iovar_set( wl, "obss_coex", &ulCoEx, sizeof( ulCoEx ) );
    BWL_CHECK_ERR( err );

    BWL_EXIT:
    return( err );
}


#define PRVAL(name) pbuf += sprintf(pbuf, "%s %d ", #name, dtoh32(cnt.name))
#define PRNL()      pbuf += sprintf(pbuf, "\n")

static int
bwl_get_counter(void *wl, char *cnt_name, uint32 *cnt_val)
{
	char *statsbuf;
	wl_cnt_t cnt;
	int err;
	uint i;
	char buf[WLC_IOCTL_MAXLEN];
	char *pbuf = buf;

	if ((err = wlu_iovar_get (wl, "counters", buf, WLC_IOCTL_MEDLEN)))
		return (err);

	statsbuf = (char *)buf;
	memcpy(&cnt, statsbuf, sizeof(cnt));
	cnt.version = dtoh16(cnt.version);
	cnt.length = dtoh16(cnt.length);

	// Dump all counters
	if (cnt.version > WL_CNT_T_VERSION) {
		printf("\tIncorrect version of counters struct: expected %d; got %d\n",
		       WL_CNT_T_VERSION, cnt.version);
		return -1;
	}
	else if (cnt.version != WL_CNT_T_VERSION) {
		printf("\tIncorrect version of counters struct: expected %d; got %d\n",
		       WL_CNT_T_VERSION, cnt.version);
		printf("\tDisplayed values may be incorrect\n");
	}

	/* summary stat counter line */
	PRVAL(txframe); PRVAL(txbyte); PRVAL(txretrans); PRVAL(txerror);
	PRVAL(rxframe); PRVAL(rxbyte); PRVAL(rxerror); PRNL();

	PRVAL(txprshort); PRVAL(txdmawar); PRVAL(txnobuf); PRVAL(txnoassoc);
	PRVAL(txchit); PRVAL(txcmiss); PRNL();

	PRVAL(reset); PRVAL(txserr); PRVAL(txphyerr); PRVAL(txphycrs);
	PRVAL(txfail); PRVAL(tbtt); PRNL();

	pbuf += sprintf(pbuf, "d11_txfrag %d d11_txmulti %d d11_txretry %d d11_txretrie %d\n",
		dtoh32(cnt.txfrag), dtoh32(cnt.txmulti), dtoh32(cnt.txretry), dtoh32(cnt.txretrie));

	pbuf += sprintf(pbuf, "d11_txrts %d d11_txnocts %d d11_txnoack %d d11_txfrmsnt %d\n",
		dtoh32(cnt.txrts), dtoh32(cnt.txnocts), dtoh32(cnt.txnoack), dtoh32(cnt.txfrmsnt));

	PRVAL(rxcrc); PRVAL(rxnobuf); PRVAL(rxnondata); PRVAL(rxbadds);
	PRVAL(rxbadcm); PRVAL(rxdup); PRVAL(rxfragerr); PRNL();

	PRVAL(rxrunt); PRVAL(rxgiant); PRVAL(rxnoscb); PRVAL(rxbadproto);
	PRVAL(rxbadsrcmac); PRNL();

	pbuf += sprintf(pbuf, "d11_rxfrag %d d11_rxmulti %d d11_rxundec %d\n",
		dtoh32(cnt.rxfrag), dtoh32(cnt.rxmulti), dtoh32(cnt.rxundec));

	PRVAL(rxctl); PRVAL(rxbadda); PRVAL(rxfilter); PRNL();

	pbuf += sprintf(pbuf, "rxuflo: ");
	for (i = 0; i < NFIFO; i++)
		pbuf += sprintf(pbuf, "%d ", dtoh32(cnt.rxuflo[i]));
	pbuf += sprintf(pbuf, "\n");
	PRVAL(txallfrm); PRVAL(txrtsfrm); PRVAL(txctsfrm); PRVAL(txackfrm); PRNL();
	PRVAL(txdnlfrm); PRVAL(txbcnfrm); PRVAL(txtplunfl); PRVAL(txphyerr); PRNL();
	pbuf += sprintf(pbuf, "txfunfl: ");
	for (i = 0; i < NFIFO; i++)
		pbuf += sprintf(pbuf, "%d ", dtoh32(cnt.txfunfl[i]));
	pbuf += sprintf(pbuf, "\n");

	/* WPA2 counters */
	PRNL();
	PRVAL(tkipmicfaill); PRVAL(tkipicverr); PRVAL(tkipcntrmsr); PRNL();
	PRVAL(tkipreplay); PRVAL(ccmpfmterr); PRVAL(ccmpreplay); PRNL();
	PRVAL(ccmpundec); PRVAL(fourwayfail); PRVAL(wepundec); PRNL();
	PRVAL(wepicverr); PRVAL(decsuccess); PRVAL(rxundec); PRNL();

	PRNL();
	PRVAL(rxfrmtoolong); PRVAL(rxfrmtooshrt);
	PRVAL(rxinvmachdr); PRVAL(rxbadfcs); PRNL();
	PRVAL(rxbadplcp); PRVAL(rxcrsglitch);
	PRVAL(rxstrt); PRVAL(rxdfrmucastmbss); PRNL();
	PRVAL(rxmfrmucastmbss); PRVAL(rxcfrmucast);
	PRVAL(rxrtsucast); PRVAL(rxctsucast); PRNL();
	PRVAL(rxackucast); PRVAL(rxdfrmocast);
	PRVAL(rxmfrmocast); PRVAL(rxcfrmocast); PRNL();
	PRVAL(rxrtsocast); PRVAL(rxctsocast);
	PRVAL(rxdfrmmcast); PRVAL(rxmfrmmcast); PRNL();
	PRVAL(rxcfrmmcast); PRVAL(rxbeaconmbss);
	PRVAL(rxdfrmucastobss); PRVAL(rxbeaconobss); PRNL();
	PRVAL(rxrsptmout); PRVAL(bcntxcancl);
	PRVAL(rxf0ovfl); PRVAL(rxf1ovfl); PRNL();
	PRVAL(rxf2ovfl); PRVAL(txsfovfl); PRVAL(pmqovfl); PRNL();
	PRVAL(rxcgprqfrm); PRVAL(rxcgprsqovfl);
	PRVAL(txcgprsfail); PRVAL(txcgprssuc); PRNL();
	PRVAL(prs_timeout); PRVAL(rxnack); PRVAL(frmscons);
	PRVAL(txnack); PRVAL(txphyerror); PRNL();
	PRVAL(txchanrej); PRNL();

	if (cnt.version >= 4) {
		/* per-rate receive counters */
		PRVAL(rx1mbps); PRVAL(rx2mbps); PRVAL(rx5mbps5); PRNL();
		PRVAL(rx6mbps); PRVAL(rx9mbps); PRVAL(rx11mbps); PRNL();
		PRVAL(rx12mbps); PRVAL(rx18mbps); PRVAL(rx24mbps); PRNL();
		PRVAL(rx36mbps); PRVAL(rx48mbps); PRVAL(rx54mbps); PRNL();
	}

	if (cnt.version >= 5) {
		PRVAL(pktengrxducast); PRVAL(pktengrxdmcast); PRNL();
	}

	if (cnt.version >= 6) {
		PRVAL(txmpdu_sgi); PRVAL(rxmpdu_sgi); PRVAL(txmpdu_stbc);
		PRVAL(rxmpdu_stbc); PRNL();
	}

	//Get specified counter value
	if (cnt_name != NULL ) 
	{
		if ( (pbuf = strstr (buf, cnt_name))!= NULL ) 
		{
			pbuf += strlen(cnt_name)+1;
			pbuf = strtok (pbuf, " ");
			*cnt_val = atoi (pbuf) ;
			return 0;
		}
		else
		{
			printf("Could not find counter %s\n", cnt_name);
			return BWL_ERR_PARAM ;
		}
	}
	else
	{
		pbuf += sprintf(pbuf, "\n");
		fputs(buf, stdout);
	}
	return (0);
}

static int
bwl_get_scan(void *wl, int opc, char *scan_buf, uint buf_len)
{
	wl_scan_results_t *list = (wl_scan_results_t*)scan_buf;
	int ret;

	list->buflen = htod32(buf_len);
	ret = wlu_get(wl, opc, scan_buf, buf_len);
	if (ret < 0)
		return ret;
	ret = 0;

	list->buflen = dtoh32(list->buflen);
	list->version = dtoh32(list->version);
	list->count = dtoh32(list->count);
	if (list->buflen == 0) {
		list->version = 0;
		list->count = 0;
	} else if (list->version != WL_BSS_INFO_VERSION &&
	           list->version != LEGACY2_WL_BSS_INFO_VERSION &&
	           list->version != LEGACY_WL_BSS_INFO_VERSION) {
		fprintf(stderr, "Sorry, your driver has bss_info_version %d "
			"but this program supports only version %d.\n",
			list->version, WL_BSS_INFO_VERSION);
		list->buflen = 0;
		list->count = 0;
	}

	return ret;
}

int
bwl_parse_country_spec(const char *spec, char *ccode, int *regrev)
{
	char *revstr;
	char *endptr = NULL;
	int ccode_len;
	int rev = -1;

	revstr = strchr(spec, '/');

	if (revstr) {
		rev = strtol(revstr + 1, &endptr, 10);
		if (*endptr != '\0') {
			/* not all the value string was parsed by strtol */
			fprintf(stderr,
				"Could not parse \"%s\" as a regulatory revision "
				"in the country string \"%s\"\n",
				revstr + 1, spec);
			return BWL_ERR_USAGE;
		}
	}

	if (revstr)
		ccode_len = (int)(uintptr)(revstr - spec);
	else
		ccode_len = (int)strlen(spec);

	if (ccode_len > 3) {
		fprintf(stderr,
			"Could not parse a 2-3 char country code "
			"in the country string \"%s\"\n",
			spec);
		return BWL_ERR_USAGE;
	}

	memcpy(ccode, spec, ccode_len);
	ccode[ccode_len] = '\0';
	*regrev = rev;

	return 0;
}


/*******************************************************************************
*
*   Name: BWL_DisplayError()
*
*   Purpose:
*       Prints out the function that cause the error.
*
*   Returns:
*       None
*
*   See Also:
*
*******************************************************************************/
void  BWL_DisplayError
(
    int32_t         lErr,     /* [in] error type */
    const char      *pcFunc,  /* [in] the functin that cause the error */
    char            *pcFile,  /* [in] the file that the function resides */
    int32_t         lLine     /* [in] the line number where the error occur */
)
{
    char *pcErr;

    switch( lErr )
    {
        case BWL_ERR_USAGE: pcErr = "BWL_ERR_USAGE"; break;
        case BWL_ERR_IOCTL: pcErr = "BWL_ERR_IOCTL"; break;
        case BWL_ERR_PARAM: pcErr = "BWL_ERR_PARAM"; break;
        case BWL_ERR_CMD:   pcErr = "BWL_ERR_CMD";   break;
        case BWL_ERR_ALLOC: pcErr = "BWL_ERR_ALLOC"; break;
        default: pcErr = "UNKNOWN ERROR"; break;
    }
    fprintf( stderr, "err=%s in '%s()' [%s @ %d]\n", pcErr, pcFunc, pcFile, lLine );
}



/*******************************************************************************
*
*   Name: BWL_IsPresent()
*
*   Purpose:
*       Checks to see if the device is connected to the system (plugged in) before
*       we initialize the BWL API
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_IsPresent
(
    uint32_t    *pulPresent,
    char        *pcIfName,
    uint32_t    ulLength
)
{
    int32_t         err = 0;
    struct ifreq    ifr;

    memset(&ifr, 0, sizeof(struct ifreq));

    wl_find(&ifr);

    err = wl_check((void*)&ifr);
    if (err != 0)
    {
        goto BWL_EXIT;
    }

    strncpy(pcIfName, ifr.ifr_name, ulLength);
    *pulPresent = 1;

BWL_EXIT:
    return( err );
}



/*******************************************************************************
*
*   Name: BWL_Init()
*
*   Purpose:
*       Finds the wireless interface and initialize the BWL handle.  The
*       handle is used throughout the all BWL functions.  This function
*       must be called prior to accessing any other BWL function.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_Uninit()
*
*******************************************************************************/
int32_t BWL_Init
(
    BWL_Handle  *phBwl  /* [out] the driver handle to be filled in */
)
{
    int32_t     err = 0;
    BWL_Handle  hBwl;

    memset( &ifr, 0, sizeof( struct ifreq ) );

    /* use default interface */
    wl_find( &ifr );
    err = wl_check( (void *)&ifr );
    BWL_CHECK_ERR( err );

    hBwl = (BWL_Handle) malloc( sizeof( BWL_P_Handle ) );
    if( hBwl == 0 )
    {
        BWL_CHECK_ERR( err = BWL_ERR_ALLOC );
    }
    memset( hBwl, 0, sizeof( BWL_P_Handle ) );

    hBwl->wl = (void*)&ifr;

    *phBwl = hBwl;

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_Uninit()
*
*   Purpose:
*       Frees the resources used by by BWL_Init().  Call this function to clean
*       up.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_Init()
*
*******************************************************************************/
int32_t BWL_Uninit
(
    BWL_Handle  hBwl    /* [in] BWL Handle */
)
{
    if( hBwl )
        free( hBwl );

    return( BWL_ERR_SUCCESS );
}


/*******************************************************************************
*
*   Name: BWL_GetDriverError()
*
*   Purpose:
*       Returns the driver's error.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_GetDriverError
(
    BWL_Handle  hBwl, /* [in] BWL Handle */
    int32_t     *plDriverErrCode /* [out] the driver's error code */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    err = wlu_iovar_get( wl, "bcmerror", plDriverErrCode, sizeof( int32_t ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_Up()
*
*   Purpose:
*       Brings the wireless device up before association.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_Up
(
    BWL_Handle  hBwl  /* [in] BWL Handle */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    /* bring the dongle out of reset */
    err = wlu_set( wl, WLC_UP, NULL, 0 );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}



/*******************************************************************************
*
*   Name: BWL_Down()
*
*   Purpose:
*       Brings the wireless device down.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_Down
(
    BWL_Handle  hBwl /* [in] BWL Handle */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    /* bring the dongle out of reset */
    err = wlu_set( wl, WLC_DOWN, NULL, 0 );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}

/*******************************************************************************
*
*   Name: BWL_IsUp()
*
*   Purpose:
*       Checks to see if the device is up.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_IsUp
(
    BWL_Handle  hBwl,   /* [in] BWL Handle */
    uint32_t    *pulUp  /* [out] 1 is up, 0 is down */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulUp = 0;

    err = wlu_get( wl, WLC_GET_UP, &ulUp, sizeof( ulUp ) );
    BWL_CHECK_ERR( err );

    *pulUp = htod32( ulUp );

BWL_EXIT:
    return( err );
}

/*******************************************************************************
*
*   Name: BWL_Scan()
*
*   Purpose:
*       Scans to find the APs.  The scan might take a few seconds to complete.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetScanResults()
*
*******************************************************************************/
int32_t BWL_Scan
(
    BWL_Handle      hBwl,   /* [in] BWL Handle */
	ScanParams_t    *pScanParams
)
{
    int32_t             err = 0;
    void                *wl = hBwl->wl;
    int32_t             params_size;
    wl_scan_params_t    *params;

    params_size = WL_SCAN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof( uint16 );
    params      = (wl_scan_params_t*) malloc( params_size );
    if( !params )
    {
        BWL_CHECK_ERR( err = BWL_ERR_ALLOC );
    }
    memset( params, 0, params_size );

    /* Do a single AP scan */
    if(pScanParams->pcSSID != NULL)
    {
        params->ssid.SSID_len = strlen(pScanParams->pcSSID);
        strncpy((char*)params->ssid.SSID, pScanParams->pcSSID, sizeof(params->ssid.SSID)/sizeof(params->ssid.SSID[0]));
    }

    memcpy( &params->bssid, &ether_bcast, ETHER_ADDR_LEN );
    params->bss_type     = DOT11_BSSTYPE_ANY;
    params->scan_type    = 0;
    params->nprobes      = -1;
    params->active_time  = dtoh32(pScanParams->lActiveTime);
    params->passive_time = dtoh32(pScanParams->lPassiveTime);
    params->home_time    = dtoh32(pScanParams->lHomeTime);
    params->channel_num  = 0;

    params_size = WL_SCAN_PARAMS_FIXED_SIZE +
        dtoh32( params->channel_num ) * sizeof( uint16 );

    err = wlu_set( wl, WLC_SCAN, params, params_size );
    BWL_CHECK_ERR( err );


BWL_EXIT:
    if( params )
        free( params );
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_ScanAbort()
*
*   Purpose:
*       Abort a scan in progress.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_ScanAbort()
*
*******************************************************************************/
int32_t BWL_ScanAbort
(
    BWL_Handle  hBwl       /* [in] BWL Handle */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    err = wlu_iovar_set( wl, "scanabort", NULL, 0 );
    BWL_CHECK_ERR( err );


BWL_EXIT:
    return( err );
}


static int BWL_ParseBssInfo(wl_bss_info_t *bi, ScanInfo_t *pScanInfo)
{
    int j;
    int mcs_idx = 0;
    if ( (bi == NULL) || (pScanInfo == NULL) )
    {
        return BWL_ERR_PARAM;
    }

    bi->chanspec                        = dtohchanspec(bi->chanspec);
    memset(&pScanInfo->tCredentials.acSSID, 0, sizeof(pScanInfo->tCredentials.acSSID));
    strncpy(pScanInfo->tCredentials.acSSID, (char*)bi->SSID, bi->SSID_len);
    pScanInfo->lRSSI                    = (int16)(dtoh16(bi->RSSI));
    pScanInfo->ulChan                   = CHSPEC_CHANNEL( bi->chanspec);
    pScanInfo->ulPhyNoise               = bi->phy_noise;
    pScanInfo->tCredentials.eNetOpMode  = !(dtoh16(bi->capability) & DOT11_CAP_IBSS);

    pScanInfo->BSSID       = bi->BSSID;
    pScanInfo->ul802_11Modes  = e802_11_none;
    pScanInfo->ul802_11Modes |= CHSPEC_IS2G(bi->chanspec)? e802_11_b : e802_11_none;
    pScanInfo->ul802_11Modes |= (bi->n_cap)              ? e802_11_n : e802_11_none;

    for (j = 0; j < MCS_INDEX_COUNT; j++)
    {
        if (isset(bi->basic_mcs, j))
        {
            mcs_idx = j;
        }
    }

    if (CHSPEC_IS5G(bi->chanspec))
    {
        pScanInfo->ul802_11Modes |= e802_11_a;
    }
    else
    {
        for (j = 0; j < dtoh32(bi->rateset.count); j++)
        {
            uint r = bi->rateset.rates[j] & 0x7f;
            if (r == 0)
                break;

            if (r > pScanInfo->lRate)
            {
                pScanInfo->lRate = r;
            }
            if (r/2 == 54)
            {
                pScanInfo->ul802_11Modes |= e802_11_g;
                break;
            }
        }
    }
    
    if (bi->n_cap)
    {
        if (CHSPEC_IS40(bi->chanspec))
        {
            pScanInfo->lRate = PhyDataRate_40MHz[mcs_idx][((dtoh32(bi->nbss_cap) & HT_CAP_SHORT_GI_40) == HT_CAP_SHORT_GI_40)];
        }
        else if (CHSPEC_IS20(bi->chanspec))
        {
            pScanInfo->lRate = PhyDataRate_20MHz[mcs_idx][((dtoh32(bi->nbss_cap) & HT_CAP_SHORT_GI_20) == HT_CAP_SHORT_GI_20)];
        }
    }


    /* Parse credentials */
    if (dtoh32(bi->ie_length))
    {
        uint8_t     *cp = (uint8 *)(((uint8 *)bi) + dtoh16(bi->ie_offset));
        uint8_t     *parse = cp;
        uint32_t    parse_len = dtoh32(bi->ie_length);
        uint8_t     *wpaie;
        uint8_t     *rsnie;
        WpaInfo_t  wpa_info, rsn_info;

        memset(&wpa_info, 0, sizeof(WpaInfo_t));
        memset(&rsn_info, 0, sizeof(WpaInfo_t));

        while ((wpaie = wlu_parse_tlvs(parse, parse_len, DOT11_MNG_WPA_ID)))
        {
            if (wlu_is_wpa_ie(&wpaie, &parse, &parse_len))
                break;
        }


        /* Read the WPA information */
        if (wpaie)
        {
            wl_rsn_ie_dump((bcm_tlv_t*)wpaie, &wpa_info);
        }

        rsnie = wlu_parse_tlvs(cp, dtoh32(bi->ie_length), DOT11_MNG_RSN_ID);
        if (rsnie)
        {
            wl_rsn_ie_dump((bcm_tlv_t*)rsnie, &rsn_info);
        }


        /* Now figure out the supported cipher & authentication modes */
        pScanInfo->tCredentials.eWpaAuth = eWpaAuthDisabled; /* clear to start with */

        if (rsn_info.Akm == RSN_AKM_PSK)
        {
            pScanInfo->tCredentials.eWpaAuth |= eWpaAuthWpa2Psk;
        }
        if (rsn_info.Akm == RSN_AKM_UNSPECIFIED)
        {
            pScanInfo->tCredentials.eWpaAuth |= eWpaAuthWpa2Unsp;
        }
        if (wpa_info.Akm == RSN_AKM_PSK)
        {
            pScanInfo->tCredentials.eWpaAuth |= eWpaAuthWpaPsk;
        }
        if (wpa_info.Akm == RSN_AKM_UNSPECIFIED)
        {
            pScanInfo->tCredentials.eWpaAuth |= eWpaAuthWpaUnsp;
        }
        if( (rsn_info.Akm == RSN_AKM_NONE) || 
            (wpa_info.Akm == RSN_AKM_NONE) )
        {
            pScanInfo->tCredentials.eWpaAuth |= eWpaAuthNone;
        }


        /* Supported Encryption Method */
        pScanInfo->tCredentials.eWSec |= rsn_info.Cipher;
        pScanInfo->tCredentials.eWSec |= wpa_info.Cipher;

        /* Search for WPS */
        parse     = cp;
        parse_len = dtoh32(bi->ie_length);
        while ((wpaie = wlu_parse_tlvs(parse, parse_len, DOT11_MNG_WPA_ID)))
        {
            pScanInfo->bWPS = bcm_is_wps_ie(wpaie, &parse, &parse_len);
            if (pScanInfo->bWPS)
            {
                break;
            }
        }
    }

    pScanInfo->bLocked = (bi->capability & DOT11_CAP_PRIVACY);
    return 0;
}


/*******************************************************************************
*
*   Name: BWL_GetScanResults()
*
*   Purpose:
*       Gets the scan results.  Call this function after a few seconds after
*       calling BWL_Scan().
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_Scan()
*
*******************************************************************************/
int32_t BWL_GetScanResults
(
    BWL_Handle      hBwl,   /* [in] BWL Handle */
    ScanInfo_t      *pData  /* [out] the scan data */
)
{
    int32_t   err = 0;
    void    *wl = hBwl->wl;
    char    *dump_buf = NULL;

    dump_buf = malloc( WL_DUMP_BUF_LEN );
    if( dump_buf == NULL )
    {
        BWL_CHECK_ERR( err = BWL_ERR_ALLOC );
    }

    memset(dump_buf, 0, WL_DUMP_BUF_LEN);
    err = bwl_get_scan( wl, WLC_SCAN_RESULTS, dump_buf, WL_DUMP_BUF_LEN );
    BWL_CHECK_ERR( err );

    if( !err )
    {
        wl_scan_results_t   *list = (wl_scan_results_t*)dump_buf;
        wl_bss_info_t       *bi;
        uint32_t              i;

        if( list->count == 0 )
        {
            goto BWL_EXIT;
        }
        else if( list->version != WL_BSS_INFO_VERSION &&
                 list->version != LEGACY_WL_BSS_INFO_VERSION )
        {
            fprintf( stderr, "Sorry, your driver has bss_info_version %d "
                             "but this program supports only version %d.\n",
                             list->version, WL_BSS_INFO_VERSION );
            goto BWL_EXIT;
        }

        bi = list->bss_info;
        for( i = 0; i < list->count; i++,
             bi = (wl_bss_info_t*)((int8*)bi + dtoh32( bi->length )) )
        {
            err = BWL_ParseBssInfo(bi, &pData[i]);
            BWL_CHECK_ERR( err );
        }
    }

BWL_EXIT:
    if( dump_buf )
        free( dump_buf );

    return( err );
}


/*******************************************************************************
*
*   Name: BWL_DisplayScanResults()
*
*   Purpose:
*       Displays the scan results.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetScanResults()
*
*******************************************************************************/
int32_t BWL_DisplayScanResults
(
    BWL_Handle      hBwl   /* [in] BWL Handle */
)
{
    int32_t       err = 0;
    void        *wl = hBwl->wl;
    char        *dump_buf;

    dump_buf = malloc( WL_DUMP_BUF_LEN );
    if( dump_buf == NULL )
    {
        BWL_CHECK_ERR( err = BWL_ERR_ALLOC );
    }

    err = bwl_get_scan( wl, WLC_SCAN_RESULTS, dump_buf, WL_DUMP_BUF_LEN );
    BWL_CHECK_ERR( err );

    dump_networks( dump_buf );


BWL_EXIT:
    if( dump_buf )
        free( dump_buf );

    return( err );
}



/*******************************************************************************
*
*   Name: BWL_GetScannedApNum()
*
*   Purpose:
*       Get the number of AP in a scan.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetScanResults()
*
*******************************************************************************/
int32_t BWL_GetScannedApNum
(
    BWL_Handle      hBwl,       /* [in] BWL Handle */
    uint32_t          *ulNumOfAp  /* [out] number of AP */
)
{
    int32_t       err = 0;
    void        *wl = hBwl->wl;
    char        *dump_buf;

    *ulNumOfAp = 0;
    dump_buf = malloc( WL_DUMP_BUF_LEN );
    if( dump_buf == NULL )
    {
        BWL_CHECK_ERR( err = BWL_ERR_ALLOC );
    }

    err = bwl_get_scan( wl, WLC_SCAN_RESULTS, dump_buf, WL_DUMP_BUF_LEN );
    BWL_CHECK_ERR( err );

    if( !err )
    {
        wl_scan_results_t *list = (wl_scan_results_t*)dump_buf;
        *ulNumOfAp = list->count;
    }


BWL_EXIT:
    if( dump_buf )
        free( dump_buf );

    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetConnectedAp()
*
*   Purpose:
*       Get information for the AP currently connected.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*******************************************************************************/
int32_t BWL_GetConnectedAp
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    char        *pcSSID,    /* [in] the pointer to store SSID strings */
    uint32_t    ulLength,   /* [in] the length of pcSSID */
    int32_t     *plRSSI     /* [in] the pointer to store RSSI value */
)
{
    int32_t             err = 0;
    void                *wl = hBwl->wl;
    struct ether_addr   bssid;
    wl_bss_info_t       *bi;
    char                *pbuf;

    BWL_CHECK_ERR( (pcSSID == NULL) || (plRSSI == NULL) );
    memset( &bssid, 0, sizeof( bssid ) );
    *pcSSID = '\0';
    err = wlu_get( wl, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN );

    if( err == 0 )
    {
        /* The adapter is associated. */
        pbuf = malloc( WLC_IOCTL_MAXLEN );

        *((uint32_t*)pbuf) = htod32( WLC_IOCTL_MAXLEN );
        err = wlu_get( wl, WLC_GET_BSS_INFO, pbuf, WLC_IOCTL_MAXLEN );
        BWL_CHECK_ERR( err );

        bi = (wl_bss_info_t*)(pbuf + 4);
        if( dtoh32( bi->version ) == WL_BSS_INFO_VERSION ||
            dtoh32( bi->version ) == LEGACY_WL_BSS_INFO_VERSION )
        {
#ifdef BWL_DEBUG
            dump_bss_info(bi);
#endif
            strncpy(pcSSID, (char*)bi->SSID, ulLength);
            *plRSSI = dtoh16( bi->RSSI );
        }
        else
        {
            fprintf( stderr, "Sorry, your driver has bss_info_version %d "
                        "but this program supports only version %d.\n",
                        bi->version, WL_BSS_INFO_VERSION );
        }
        free( pbuf );
    }
    else
    {
        int32_t errcode = 0, err2 = 0;

        err2 = BWL_GetDriverError(hBwl, &errcode);
        if ( (err2 == 0) && (errcode == BCME_NOTASSOCIATED) )
        {
            err = 0;
        }

    }
BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_IsConnectedAp()
*
*   Purpose:
*       Checking to see if the stat is connnected to the AP.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetCountry()
*
*******************************************************************************/
int32_t BWL_IsConnectedAp
(
    BWL_Handle  hBwl, 
    uint32_t    *pulConnect
)
{
    int32_t              err = 0;
    void                *wl = hBwl->wl;
    struct ether_addr   bssid;

    memset( &bssid, 0, sizeof( bssid ) );
    err = wlu_get( wl, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN );

    /*-----------------------------------------------------------------------
     * Check to see if the return ether address is all zeros.
     * If it is all zeros, then the client is not connected to an AP.
     *-----------------------------------------------------------------------*/
    if( ETHER_ISNULLADDR(bssid.octet) )
    {
        /* not connected */
        *pulConnect = 0;
    }
    else
    {
        *pulConnect = 1;
    }

    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetCountry()
*
*   Purpose:
*       Set the country code using ISO 3166 format.
*       follows ISO 3166 format
*       eg: KR/3, KP (Korea)
*           US (United States)
*           JP (Japan)
*           CN (China)
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetCountry()
*
*******************************************************************************/
int32_t BWL_SetCountry
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    char        *pcCountry  /* [in] Country string */
)
{
    int32_t         err = 0;
    void            *wl = hBwl->wl;
    wl_country_t    cspec;


    /* always start out clean */
    memset( &cspec, 0, sizeof( cspec ) );
    cspec.rev = -1;

    /* parse a country spec, e.g. "US/1", or a country code.
     * cspec.rev will be -1 if not specified.
     */
    err = bwl_parse_country_spec( pcCountry, cspec.country_abbrev, &cspec.rev );

    if( err )
    {
        fprintf( stderr,
                "Argument \"%s\" could not be parsed as a country name, "
                "country code, or country code and regulatory revision.\n",
                pcCountry );
        BWL_CHECK_ERR( err = BWL_ERR_USAGE );
    }

    /* if the arg was a country spec, then fill out ccode and rev,
     * and leave country_abbrev defaulted to the ccode
     */
    if( cspec.rev != -1 )
    {
        memcpy( cspec.ccode, cspec.country_abbrev, WLC_CNTRY_BUF_SZ );
    }

    /* first try the country iovar */
    if (cspec.rev == -1 && cspec.ccode[0] == '\0')
        err = wlu_iovar_set( wl, "country", &cspec, WLC_CNTRY_BUF_SZ );
    else
        err = wlu_iovar_set( wl, "country", &cspec, sizeof( cspec ) );

    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetCountry()
*
*   Purpose:
*       Get the country code in ISO 3166 format.
*       follows ISO 3166 format
*       eg: KR/3, KP (Korea)
*           US (United States)
*           JP (Japan)
*           CN (China)
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetCountry()
*
*******************************************************************************/
int32_t BWL_GetCountry
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    char        *pcCountry  /* [out] Country string */
)
{
    int32_t         err = 0;
    void            *wl = hBwl->wl;
    wl_country_t    cspec;

    /* always start out clean */
    memset( &cspec, 0, sizeof( cspec ) );
    cspec.rev = -1;

    /* first try the country iovar */
    err = wlu_iovar_get( wl, "country", &cspec, sizeof( cspec ) );
    BWL_CHECK_ERR( err );

    memcpy( pcCountry, cspec.country_abbrev, WLC_CNTRY_BUF_SZ );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetSsid()
*
*   Purpose:
*       Set the SSID of the AP that the client want to associate.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetSsid()
*
*******************************************************************************/
int32_t BWL_SetSsid
(
    BWL_Handle          hBwl,    /* [in] BWL Handle */
    char                *pcSsid, /* [in] AP SSID */
    struct ether_addr   *peBSSID /* [in] BSSID of the AP */
)
{
    int32_t             err = 0;
    void                *wl = hBwl->wl;
    wl_join_params_t    join;

    if( pcSsid == NULL )
    {
        fprintf( stderr, "SSID arg NULL ponter\n" );
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }
 
    if( strlen( pcSsid ) > DOT11_MAX_SSID_LEN )
    {
        fprintf( stderr, "SSID arg \"%s\" must be 32 chars or less\n", pcSsid );
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }
    memset( &join, 0, sizeof(wl_join_params_t) );
    join.ssid.SSID_len = strlen( pcSsid );
    join.ssid.SSID_len = htod32( join.ssid.SSID_len );
    memcpy( join.ssid.SSID, pcSsid, join.ssid.SSID_len );
 
    if( NULL == peBSSID )
    {
        PRINTF(("peBSSID NULL\n"));
        err = wlu_set( wl, WLC_SET_SSID, &join.ssid, sizeof( wlc_ssid_t ) );
    }
    else
    {
        PRINTF(("peBSSID Non NULL\n"));
        memcpy( &join.params.bssid, peBSSID, sizeof(struct ether_addr) );
        err = wlu_set( wl, WLC_SET_SSID, &join, sizeof( wl_join_params_t ) );
    }
 
BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetSsid()
*
*   Purpose:
*       Get the SSID of the associated AP.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetSsid()
*       BWL_GetCacheSsid()
*
*******************************************************************************/
int32_t BWL_GetSsid
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    char        *pcSsid, /* [out] AP SSID */
    uint32_t    *pulLen  /* [out] SSID length */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    wlc_ssid_t  ssid;

    memset(&ssid,0,sizeof(wlc_ssid_t));

    if( pcSsid == NULL )
    {
        fprintf( stderr, "SSID arg NULL ponter\n" );
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    err = wlu_get( wl, WLC_GET_SSID, &ssid, sizeof( ssid ) );
    *pulLen = dtoh32( ssid.SSID_len );
    memcpy( pcSsid, ssid.SSID, *pulLen );

BWL_EXIT:
    return( err );
}



/*******************************************************************************
*
*   Name: BWL_GetCachedSsid()
*
*   Purpose:
*       Get the BSSID of the previous stored SSID.  The return the SSID
*       regardless of associatively.  This is different than the BWL_GetSsid().
*       The BWL_GetSsid() returns the currently associated SSID.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetSsid()
*       BWL_GetSsid()
*
*******************************************************************************/
int32_t BWL_GetCachedSsid
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    char        *pcSsid, /* [out] AP SSID */
    uint32_t    *pulLen  /* [out] SSID length */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    wlc_ssid_t  ssid;

    if( pcSsid == NULL )
    {
        fprintf( stderr, "SSID arg NULL ponter\n" );
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    err = wlu_iovar_get( wl, "ssid", &ssid, sizeof( ssid ) );
    BWL_CHECK_ERR( err );

    *pulLen = dtoh32( ssid.SSID_len );
    memcpy( pcSsid, ssid.SSID, *pulLen );

BWL_EXIT:
    return( err );
}/* BWL_GetCachedSsid */


/*******************************************************************************
*
*   Name: BWL_GetBssid()
*
*   Purpose:
*       Get the BSSID of the associated AP.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetSsid()
*
*******************************************************************************/
int32_t BWL_GetBssid
(
    BWL_Handle          hBwl,    /* [in] BWL Handle */
    struct ether_addr   *pbssid  /* [out] AP BSSID */
)

{
    int32_t             err = 0;
    void                *wl = hBwl->wl;

    memset( pbssid, 0, sizeof( struct ether_addr ) );
    err = wlu_get( wl, WLC_GET_BSSID, pbssid, ETHER_ADDR_LEN );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetBand()
*
*   Purpose:
*       Set the Band to use.
*       Supported Bands: Auto, 5G, 2G, All bands.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetBand()
*
*******************************************************************************/
int32_t BWL_SetBand
(
    BWL_Handle  hBwl,   /* [in] BWL Handle */
    Band_t      eBand   /* [in] Auto, 5G, 2G, All bands */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulBand = 0;
    uint32_t    ii;

    for (ii = 0; ii < sizeof(BandTable)/sizeof(BandTable[0]); ii++)
    {
        if (BandTable[ii].eBwl == eBand)
        {
            ulBand = htod32(BandTable[ii].eWl);
            break;
        }
    }

    err = wlu_set( wl, WLC_SET_BAND, &ulBand, sizeof( ulBand ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetBand()
*
*   Purpose:
*       Get the Band associated band.
*       Supported Bands: Auto, 5G, 2G, All bands.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetBand()
*
*******************************************************************************/
int32_t BWL_GetBand
(
    BWL_Handle  hBwl,   /* [in] BWL Handle */
    Band_t      *peBand /* [out] Auto, 5G, 2G, All bands */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulBand;
    uint32_t    ii;

    err = wlu_get( wl, WLC_GET_BAND, &ulBand, sizeof( ulBand ) );
    BWL_CHECK_ERR( err );

    ulBand = htod32(ulBand);
    for (ii = 0; ii < sizeof(BandTable)/sizeof(BandTable[0]); ii++)
    {
        if (BandTable[ii].eWl == ulBand)
        {
            *peBand = BandTable[ii].eBwl;
            break;
        }
    }


BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetChannel()
*
*   Purpose:
*       Set the channel use..
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetChannel()
*
*******************************************************************************/
int32_t BWL_SetChannel
(
    BWL_Handle  hBwl,   /* [in] BWL Handle */
    uint32_t    ulChan  /* [in] Channel */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    ulChan = htod32( ulChan );
    err = wlu_set( wl, WLC_SET_CHANNEL, &ulChan, sizeof( ulChan ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetChannel()
*
*   Purpose:
*       Set the channel use..
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetChannel()
*
*******************************************************************************/
int32_t BWL_GetChannel
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    uint32_t    *pulChan    /* [in] Channel */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulChan;

    err = wlu_iovar_get( wl, "chanspec", &ulChan, sizeof( ulChan ) );
    BWL_CHECK_ERR( err );

    *pulChan = CHSPEC_CHANNEL( ulChan );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetChannelsByCountry()
*
*   Purpose:
*       Get all the supported channels by the country
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetChannel()
*
*******************************************************************************/
int32_t BWL_GetChannelsByCountry
(
    BWL_Handle  hBwl,           /* [in] BWL Handle */
    char        *pcCountry,     /* [in] country code in ISO 3166 format */
    Band_t      eBand,          /* [in] which band */
    uint32_t    aulChannels[],  /* [out] all channels */
    uint32_t    *pulChannels    /* [out] number of channels */
)
{
    int32_t                     err = 0;
    void                        *wl = hBwl->wl;
    wl_channels_in_country_t    *cic;
    uint32_t                    ii, len;
    uint32_t                    ulChannels;
    uint32_t                    i;

    cic = (wl_channels_in_country_t *)s_bufdata;
    cic->buflen = WLC_IOCTL_MAXLEN;
    cic->count = 0;

    /* country abbrev must follow */
    if( pcCountry == NULL )
    {
        fprintf( stderr, "missing country abbrev\n" );
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    len = strlen( pcCountry );
    if ((len > 3) || (len < 2))
    {
        fprintf( stderr, "invalid country abbrev: %s\n", pcCountry );
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    strcpy( cic->country_abbrev, pcCountry );

    for (i = 0; i < sizeof(BandTable)/sizeof(BandTable[0]); i++)
    {
        if (BandTable[i].eBwl == eBand)
        {
            cic->band = htod32(BandTable[i].eWl);
            break;
        }
    }
    cic->buflen = htod32( cic->buflen );
    cic->band   = htod32( cic->band );
    cic->count  = htod32( cic->count );
    err = wlu_get( wl, WLC_GET_CHANNELS_IN_COUNTRY, s_bufdata, WLC_IOCTL_MAXLEN );
    BWL_CHECK_ERR( err );

    ulChannels = dtoh32(cic->count);
    if( ulChannels > BWL_MAX_CHANNEL )
    {
        ulChannels = BWL_MAX_CHANNEL;
    }

    for( ii = 0; ii < ulChannels ; ii++)
    {
        aulChannels[ ii ] = dtoh32( cic->channel[ ii ] );
    }
    *pulChannels = ulChannels;


BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetInfraMode()
*
*   Purpose:
*       Set the network operating mode.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetInfraMode()
*
*******************************************************************************/
int32_t BWL_SetInfraMode
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    NetOpMode_t eNetOpMode  /* [in] ad-hoc or infrasture */
)
{
    int32_t       err = 0;
    void          *wl = hBwl->wl;
    uint32_t      ulMode = 0;
    uint32_t      i;

    for (i = 0; i < sizeof(NetOpModeTable)/sizeof(NetOpModeTable[0]); i++)
    {
        if (NetOpModeTable[i].eBwl == eNetOpMode)
        {
            ulMode = htod32(NetOpModeTable[i].eWl);
            break;
        }
    }

    err = wlu_set( wl, WLC_SET_INFRA, &ulMode, sizeof( ulMode ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetInfraMode()
*
*   Purpose:
*       Set the network operating mode.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetInfraMode()
*
*******************************************************************************/
int32_t BWL_GetInfraMode
(
    BWL_Handle  hBwl,           /* [in] BWL Handle */
    NetOpMode_t *peNetOpMode    /* [out] ad-hoc or infrasture */
)
{
    int32_t       err = 0;
    void          *wl = hBwl->wl;
    uint32_t      ulMode;
    uint32_t      i;

    err = wlu_get( wl, WLC_GET_INFRA, &ulMode, sizeof( ulMode ) );
    BWL_CHECK_ERR( err );


    ulMode = htod32(ulMode);
    for (i = 0; i < sizeof(NetOpModeTable)/sizeof(NetOpModeTable[0]); i++)
    {
        if (NetOpModeTable[i].eWl == ulMode)
        {
            *peNetOpMode = NetOpModeTable[i].eBwl;
            break;
        }
    }

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetAuthType()
*
*   Purpose:
*       Set the authentication type: open, shared, or open & shared.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetAuthType()
*
*******************************************************************************/
int32_t BWL_SetAuthType
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    AuthType_t  eAuthType   /* [in] authentication type */
)
{
    int32_t       err = 0;
    void          *wl = hBwl->wl;
    uint32_t      ulAuthType;
    uint32_t      i;

    for (i = 0; i < sizeof(AuthTypeTable)/sizeof(AuthTypeTable[0]); i++)
    {
        if (AuthTypeTable[i].eBwl == eAuthType)
        {
            ulAuthType = htod32(AuthTypeTable[i].eWl);
            break;
        }
    }

    err = wlu_iovar_set( wl, "auth", &ulAuthType, sizeof( ulAuthType ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetAuthType()
*
*   Purpose:
*       Set the authentication type: open, shared, or open & shared.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetAuthType()
*
*******************************************************************************/
int32_t BWL_GetAuthType
(
    BWL_Handle  hBwl,           /* [in] BWL Handle */
    AuthType_t  *peAuthType     /* [out] authentication type */
)
{
    int32_t       err = 0;
    void          *wl = hBwl->wl;
    uint32_t      ulAuthType;
    uint32_t      i;


    err = wlu_iovar_get( wl, "auth", &ulAuthType, sizeof( ulAuthType ) );
    BWL_CHECK_ERR( err );

    ulAuthType = htod32( ulAuthType );
    for (i = 0; i < sizeof(AuthTypeTable)/sizeof(AuthTypeTable[0]); i++)
    {
        if (AuthTypeTable[i].eWl == ulAuthType)
        {
            *peAuthType = AuthTypeTable[i].eBwl;
            break;
        }
    }
BWL_EXIT:
    return( err );
}

int32_t BWL_GetWpaSupStatus(BWL_Handle hBwl, SupStatus_t *pStatus)
{
    int32_t       err = 0;
    void          *wl = hBwl->wl;
    uint32_t      ulSupWpaStatus = 0;

    err = wlu_iovar_get( wl, "sup_auth_status", &ulSupWpaStatus, sizeof( ulSupWpaStatus) );
    BWL_CHECK_ERR( err );

    switch (htod32(ulSupWpaStatus))
    {
    case WLC_SUP_DISCONNECTED:
        *pStatus = eSupStatusDisconnected;
        break;

    case WLC_SUP_CONNECTING:
    case WLC_SUP_IDREQUIRED:
    case WLC_SUP_AUTHENTICATING:
    case WLC_SUP_AUTHENTICATED:
    case WLC_SUP_KEYXCHANGE:
        *pStatus = eSupStatuseConnecting;
        break;

    case WLC_SUP_KEYED:
        *pStatus = eSupStatusConnected;
        break;

    default:
        *pStatus = eSupStatusError;
        break;
    }
    BWL_EXIT:
        return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetWpaSup()
*
*   Purpose:
*       Set WPA supplication: internal or external.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetWpaSup()
*
*******************************************************************************/
int32_t BWL_SetWpaSup
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    WpaSup_t    eWpaSup     /* [in] driver supplicant */
)
{
    int32_t       err = 0;
    void          *wl = hBwl->wl;
    uint32_t      ulWpaSup;
    uint32_t      i;

    for (i = 0; i < sizeof(WpaSupTable)/sizeof(WpaSupTable[0]); i++)
    {
        if (WpaSupTable[i].eBwl == eWpaSup)
        {
            ulWpaSup = htod32(WpaSupTable[i].eWl);
            break;
        }
    }

    err = wlu_iovar_set( wl, "sup_wpa", &ulWpaSup, sizeof( ulWpaSup ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetWpaSup()
*
*   Purpose:
*       Get WPA supplication: internal or external.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetWpaSup()
*
*******************************************************************************/
int32_t BWL_GetWpaSup
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    WpaSup_t    *peWpaSup   /* [out] driver supplicant */
)
{
    int32_t       err = 0;
    void          *wl = hBwl->wl;
    uint32_t      ulWpaSup;
    uint32_t      i;

    err = wlu_iovar_get( wl, "sup_wpa", &ulWpaSup, sizeof( ulWpaSup) );
    BWL_CHECK_ERR( err );

    ulWpaSup = htod32(ulWpaSup);
    for (i = 0; i < sizeof(WpaSupTable)/sizeof(WpaSupTable[0]); i++)
    {
        if (WpaSupTable[i].eWl == ulWpaSup)
        {
            *peWpaSup = WpaSupTable[i].eBwl;
            break;
        }
    }

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetWpaAuth()
*
*   Purpose:
*       Get WPA authentication: none, wpa psk, wpa2 psk.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetWpaAuth()
*
*******************************************************************************/
int32_t BWL_SetWpaAuth
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    WpaAuth_t   eWpaAuth /* [in] wpa authentication: none, wpa psk, wpa2 psk */
)
{
    int32_t       err = 0;
    void          *wl = hBwl->wl;
    uint32_t      ulWpaAuth;
    uint32_t      i;

    for (i = 0; i < sizeof(WpaAuthTable)/sizeof(WpaAuthTable[0]); i++)
    {
        if (WpaAuthTable[i].eBwl == eWpaAuth)
        {
            ulWpaAuth = htod32(WpaAuthTable[i].eWl);
            break;
        }
    }

    err = wlu_iovar_set( wl, "wpa_auth", &ulWpaAuth, sizeof( ulWpaAuth ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetWpaAuth()
*
*   Purpose:
*       Set WPA authentication: none, wpa psk, wpa2 psk.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetWpaAuth()
*
*******************************************************************************/
int32_t BWL_GetWpaAuth
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    WpaAuth_t   *peWpaAuth  /* [out] wpa authentication  */
)
{
    int32_t       err = 0;
    void          *wl = hBwl->wl;
    uint32_t      ulWpaAuth;
    uint32_t      i;

    err = wlu_iovar_get( wl, "wpa_auth", &ulWpaAuth, sizeof( ulWpaAuth ) );
    BWL_CHECK_ERR( err );

    ulWpaAuth = htod32( ulWpaAuth );
    for (i = 0; i < sizeof(WpaAuthTable)/sizeof(WpaAuthTable[0]); i++)
    {
        if (WpaAuthTable[i].eWl == ulWpaAuth)
        {
            *peWpaAuth = WpaAuthTable[i].eBwl;
            break;
        }
    }

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetWSec()
*
*   Purpose:
*       Set wireless security: none, wep, tkip, aes.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetWSec()
*
*******************************************************************************/
int32_t BWL_SetWSec
(
    BWL_Handle  hBwl,   /* [in] BWL Handle */
    WSec_t      eWSec   /* [in] wireless security: none, wep, tkip, aes */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulWSec = 0;
    uint32_t    i;

    for (i = 0; i < sizeof(WSecTable)/sizeof(WSecTable[0]); i++)
    {
        if (WSecTable[i].eBwl == eWSec)
        {
            ulWSec = htod32(WSecTable[i].eWl);
            break;
        }
    }

    err = wlu_set( wl, WLC_SET_WSEC, &ulWSec, sizeof( ulWSec ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetWSec()
*
*   Purpose:
*       Get wireless security: none, wep, tkip, aes.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetWSec()
*
*******************************************************************************/
int32_t BWL_GetWSec
(
    BWL_Handle  hBwl,   /* [in] BWL Handle */
    WSec_t      *peWSec /* [out] wireless security: none, wep, tkip, aes */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulWSec;
    uint32_t    i;

    err = wlu_get( wl, WLC_GET_WSEC, &ulWSec, sizeof( ulWSec ) );
    BWL_CHECK_ERR( err );

    ulWSec = htod32( ulWSec );
    for (i = 0; i < sizeof(WSecTable)/sizeof(WSecTable[0]); i++)
    {
        if (WSecTable[i].eWl == ulWSec)
        {
            *peWSec = WSecTable[i].eBwl;
            break;
        }
    }

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetWSecKey()
*
*   Purpose:
*       Set security passphrase/key for tkip or aes.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*******************************************************************************/
int32_t BWL_SetWSecKey
(
    BWL_Handle  hBwl,   /* [in] BWL Handle */
    char        *pcKey  /* [out] security passphrass/key */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    wsec_pmk_t  psk;
    size_t      key_len;


    key_len = strlen( pcKey );
    if( (key_len < WSEC_MIN_PSK_LEN) || (key_len > WSEC_MAX_PSK_LEN) )
    {
        fprintf( stderr, "passphrase must be between %d and %d characters long\n",
                 WSEC_MIN_PSK_LEN, WSEC_MAX_PSK_LEN );
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    psk.key_len = htod16( (ushort) key_len );
    psk.flags  = htod16( WSEC_PASSPHRASE );

    memcpy( psk.key, pcKey, key_len );

    err = wlu_set( wl, WLC_SET_WSEC_PMK, &psk, sizeof( psk ) );
    BWL_CHECK_ERR( err );


BWL_EXIT:
    return( err );
}



/*******************************************************************************
*
*   Name: BWL_SetWepIndex()
*
*   Purpose:
*       Set WEP key index.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetWepIndex()
*       BWL_AddWepKey()
*
*******************************************************************************/
int32_t BWL_SetWepIndex
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    uint32_t    ulIndex     /* [in] WEP index */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    ulIndex = htod32( ulIndex );
    err = wlu_set( wl, WLC_SET_KEY_PRIMARY, &ulIndex, sizeof( ulIndex ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetWepIndex()
*
*   Purpose:
*       Get WEP key index.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetWepIndex()
*       BWL_AddWepKey()
*
*******************************************************************************/
int32_t BWL_GetWepIndex
(
    BWL_Handle  hBwl,       /* [in] BWL Handle */
    uint32_t    *pulIndex   /* [out] WEP index */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulIndex = 0;

    err = wlu_get( wl, WLC_GET_KEY_PRIMARY, &ulIndex, sizeof( uint32_t ) );
    BWL_CHECK_ERR( err );

    *pulIndex = htod32( ulIndex );

BWL_EXIT:
    return( err );
}



/*******************************************************************************
*
*   Name: BWL_AddWepKey()
*
*   Purpose:
*       Add a WEP key based on the for a key index.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetWepIndex()
*       BWL_GetWepIndex()
*
*******************************************************************************/
int32_t BWL_AddWepKey
(
    BWL_Handle      hBwl,           /* [in] BWL Handle */
    uint32_t          ulIndex,        /* [in] key index [0:3] */
    char            *pcKey,         /* [in] key string */
    CryptoAlgo_t    eAlgoOverride,  /* [in] used for 16 bytes key */
    uint32_t          ulIsPrimary     /* [in] type of key */
)
{
    int32_t         err = 0;
    void            *wl = hBwl->wl;
    wl_wsec_key_t   key;
    uint32_t        ulLen;
    uint32_t        ulAlgo;
    unsigned char   *data = &key.data[0];
    char            hex[] = "XX";

    memset( &key, 0, sizeof( key ) );
    ulLen = strlen( pcKey );


    switch( ulLen )
    {
    case 5:
    case 13:
    case 16:
        memcpy(data, pcKey, ulLen + 1);
        break;
    case 12:
    case 28:
    case 34:
    case 66:
        /* strip leading 0x */
        if (!strnicmp(pcKey, "0x", 2))
            pcKey += 2;
        else
            return -1;
        /* fall through */
    case 10:
    case 26:
    case 32:
    case 64:
        ulLen = ulLen / 2;
        while (*pcKey) {
            strncpy(hex, pcKey, 2);
            *data++ = (char) strtoul(hex, NULL, 16);
            pcKey += 2;
        }
        break;
    default:
        return BWL_ERR_PARAM;
    }

    switch (ulLen)
    {
    case 5:
        ulAlgo = CRYPTO_ALGO_WEP1;
        break;

    case 13:
        ulAlgo = CRYPTO_ALGO_WEP128;
        break;

    case 16:
    {
        unsigned int i;
        for (i = 0; i < sizeof(CryptoAlgoTable)/sizeof(CryptoAlgoTable[0]); i++)
        {
            if (CryptoAlgoTable[i].eBwl == eAlgoOverride)
            {
                ulAlgo = CryptoAlgoTable[i].eWl;
                break;
            }
        }
        /* sanity check to make sure the override algo is valid */
        if( (ulAlgo != CRYPTO_ALGO_AES_CCM)  &&
            (ulAlgo != CRYPTO_ALGO_AES_OCB_MPDU) )
        {
            BWL_CHECK_ERR( err = BWL_ERR_PARAM );
        }
        break;
    }
    case 32:
        ulAlgo = CRYPTO_ALGO_TKIP;
        break;

    default:
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
        break;
    }


    if( ulIsPrimary )
        key.flags = WL_PRIMARY_KEY;

    key.index  = htod32( ulIndex );
    key.len    = htod32( ulLen );
    key.algo   = htod32( ulAlgo );
    key.flags  = htod32( key.flags );

    err = wlu_set( wl, WLC_SET_KEY, &key, sizeof( key ) );
    BWL_CHECK_ERR( err );


BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_ConnectNoSec()
*
*   Purpose:
*       Associate without encryption.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_ConnectAp()
*       BWL_DisconnectAp()
*       BWL_ConnectWep()
*       BWL_ConnectWpaAes()
*       BWL_ConnectWpaTkip()
*       BWL_ConnectWpa2Aes()
*       BWL_ConnectWpa2Tkip()
*
*******************************************************************************/
int32_t BWL_ConnectNoSec
(
    BWL_Handle    hBwl,       /* [in] BWL Handle */
    NetOpMode_t   eNetOpMode, /* [in] infrastructure or adhoc */
    char          *pcSSID,     /* [in] SSID of the AP */
    struct ether_addr *peBSSID /* [in] BSSID of the AP */
)
{
    int32_t             err = 0;
    Credential_t        Credential;

    /* good pratice, always clear the structure first */
    memset( &Credential, 0, sizeof( Credential ) );

    Credential.eNetOpMode = eNetOpMode;
    Credential.eAuthType  = eAuthTypeOpen;
    Credential.eWpaAuth   = eWpaAuthDisabled;
    Credential.eWSec      = eWSecNone;
    Credential.eWpaSup    = eWpaSupInternal;
    Credential.ulWepIndex = 0; /* doesn't need for NO WEP */
    Credential.peBSSID = peBSSID;

    /* clear the key, doesn't need it */
    memset( Credential.acKey, 0, sizeof( Credential.acKey ) );

    memcpy( Credential.acSSID, pcSSID, strlen( pcSSID ) );

    err = BWL_ConnectAp( hBwl, &Credential);

    return( err );
}


/*******************************************************************************
*
*   Name: BWL_ConnectWep()
*
*   Purpose:
*       Associate using WEP key.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_ConnectAp()
*       BWL_DisconnectAp()
*       BWL_ConnectNoSec()
*       BWL_ConnectWpaAes()
*       BWL_ConnectWpaTkip()
*       BWL_ConnectWpa2Aes()
*       BWL_ConnectWpa2Tkip()
*
*******************************************************************************/
int32_t BWL_ConnectWep
(
    BWL_Handle          hBwl,       /* [in] BWL Handle */
    NetOpMode_t         eNetOpMode, /* [in] infrastructure or adhoc */
    char                *pcSSID,    /* [in] SSID of the AP */
    char                *pcKey,     /* [in] key string */
    uint32_t            ulKeyIndex, /* [in] 0-3 key index */
    AuthType_t          eAuthType,  /* [in] open, shared, open & shared */
    struct ether_addr   *peBSSID    /* [in] BSSID of the AP */
)
{
    int32_t             err = 0;
    Credential_t        Credential;

    /* good pratice, always clear the structure first */
    memset( &Credential, 0, sizeof( Credential ) );

    Credential.eNetOpMode = eNetOpMode;
    Credential.eAuthType  = eAuthType;
    Credential.eWpaAuth   = eWpaAuthDisabled;
    Credential.eWSec      = eWSecWep;
    Credential.eWpaSup    = eWpaSupInternal;
    Credential.ulWepIndex = ulKeyIndex;
    Credential.peBSSID    = peBSSID;

    memcpy( Credential.acKey, pcKey, strlen( pcKey ) );
    memcpy( Credential.acSSID, pcSSID, strlen( pcSSID ) );

    err = BWL_ConnectAp( hBwl, &Credential );

    return( err );
}


/*******************************************************************************
*
*   Name: BWL_ConnectWpaTkip()
*
*   Purpose:
*       Associate using TKIP key.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_ConnectAp()
*       BWL_DisconnectAp()
*       BWL_ConnectNoSec()
*       BWL_ConnectWep()
*       BWL_ConnectWpaAes()
*       BWL_ConnectWpa2Aes()
*       BWL_ConnectWpa2Tkip()
*
*******************************************************************************/
int32_t BWL_ConnectWpaTkip
(
    BWL_Handle          hBwl,       /* [in] BWL Handle */
    NetOpMode_t         eNetOpMode, /* [in] infrastructure or adhoc */
    char                *pcSSID,    /* [in] SSID of the AP */
    char                *pcKey,     /* [in] key string */
    struct ether_addr   *peBSSID    /* [in] BSSID of the AP */
)
{
    int32_t               err = 0;
    Credential_t        Credential;

    /* good pratice, always clear the structure first */
    memset( &Credential, 0, sizeof( Credential ) );

    Credential.eNetOpMode = eNetOpMode;
    Credential.eAuthType  = eAuthTypeOpen;
    Credential.eWpaAuth   = eWpaAuthWpaPsk;
    Credential.eWSec      = eWSecTkip;
    Credential.eWpaSup    = eWpaSupInternal;
    Credential.peBSSID    = peBSSID;

    memcpy( Credential.acKey, pcKey, strlen( pcKey ) );
    memcpy( Credential.acSSID, pcSSID, strlen( pcSSID ) );

    err = BWL_ConnectAp( hBwl, &Credential );

    return( err );
}


/*******************************************************************************
*
*   Name: BWL_ConnectWpaAes()
*
*   Purpose:
*       Associate using AES key.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_ConnectAp()
*       BWL_DisconnectAp()
*       BWL_ConnectNoSec()
*       BWL_ConnectWep()
*       BWL_ConnectWpaTkip()
*       BWL_ConnectWpa2Aes()
*       BWL_ConnectWpa2Tkip()
*
*******************************************************************************/
int32_t BWL_ConnectWpaAes
(
    BWL_Handle          hBwl,       /* [in] BWL Handle */
    NetOpMode_t         eNetOpMode, /* [in] infrastructure or adhoc */
    char                *pcSSID,    /* [in] SSID of the AP */
    char                *pcKey,     /* [in] key string */
    struct ether_addr   *peBSSID    /* [in] BSSID of the AP */
)
{
    int32_t             err = 0;
    Credential_t        Credential;

    /* good pratice, always clear the structure first */
    memset( &Credential, 0, sizeof( Credential ) );

    Credential.eNetOpMode = eNetOpMode;
    Credential.eAuthType  = eAuthTypeOpen;
    Credential.eWpaAuth   = eWpaAuthWpaPsk;
    Credential.eWSec      = eWSecAes;
    Credential.eWpaSup    = eWpaSupInternal;
    Credential.peBSSID    = peBSSID;

    memcpy( Credential.acKey, pcKey, strlen( pcKey ) );
    memcpy( Credential.acSSID, pcSSID, strlen( pcSSID ) );

    err = BWL_ConnectAp( hBwl, &Credential );

    return( err );
}



/*******************************************************************************
*
*   Name: BWL_ConnectWpa2Tkip()
*
*   Purpose:
*       Associate using WPA2 TKIP key.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_ConnectAp()
*       BWL_DisconnectAp()
*       BWL_ConnectNoSec()
*       BWL_ConnectWep()
*       BWL_ConnectWpaAes()
*       BWL_ConnectWpaTkip()
*       BWL_ConnectWpa2Aes()
*
*******************************************************************************/
int32_t BWL_ConnectWpa2Tkip
(
    BWL_Handle          hBwl,       /* [in] BWL Handle */
    NetOpMode_t         eNetOpMode, /* [in] infrastructure or adhoc */
    char                *pcSSID,    /* [in] SSID of the AP */
    char                *pcKey,     /* [in] key string */
	struct ether_addr   *peBSSID    /* [in] BSSID of the AP */
)
{
    int32_t             err = 0;
    Credential_t        Credential;

    /* good pratice, always clear the structure first */
    memset( &Credential, 0, sizeof( Credential ) );

    Credential.eNetOpMode = eNetOpMode;
    Credential.eAuthType  = eAuthTypeOpen;
    Credential.eWpaAuth   = eWpaAuthWpa2Psk;
    Credential.eWSec      = eWSecTkip;
    Credential.eWpaSup    = eWpaSupInternal;
    Credential.peBSSID    = peBSSID;

    memcpy( Credential.acKey, pcKey, strlen( pcKey ) );
    memcpy( Credential.acSSID, pcSSID, strlen( pcSSID ) );

    err = BWL_ConnectAp( hBwl, &Credential );

    return( err );
}


/*******************************************************************************
*
*   Name: BWL_ConnectWpa2Aes()
*
*   Purpose:
*       Associate using WPA2 AES key.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_ConnectAp()
*       BWL_DisconnectAp()
*       BWL_ConnectNoSec()
*       BWL_ConnectWep()
*       BWL_ConnectWpaAes()
*       BWL_ConnectWpaTkip()
*       BWL_ConnectWpa2Tkip()
*
*******************************************************************************/
int32_t BWL_ConnectWpa2Aes
(
    BWL_Handle          hBwl,       /* [in] BWL Handle */
    NetOpMode_t         eNetOpMode, /* [in] infrastructure or adhoc */
    char                *pcSSID,    /* [in] SSID of the AP */
    char                *pcKey,     /* [in] key string */
    struct ether_addr   *peBSSID    /* [in] BSSID of the AP */
)
{
    int32_t              err = 0;
    Credential_t        Credential;

    /* good pratice, always clear the structure first */
    memset( &Credential, 0, sizeof( Credential ) );

    Credential.eNetOpMode = eNetOpMode;
    Credential.eAuthType  = eAuthTypeOpen;
    Credential.eWpaAuth   = eWpaAuthWpa2Psk;
    Credential.eWSec      = eWSecAes;
    Credential.eWpaSup    = eWpaSupInternal;
    Credential.peBSSID    = peBSSID;

    memcpy( Credential.acKey, pcKey, strlen( pcKey ) );
    memcpy( Credential.acSSID, pcSSID, strlen( pcSSID ) );


    err = BWL_ConnectAp( hBwl, &Credential );

    return( err );
}


/*******************************************************************************
*
*   Name: BWL_ConnectAp()
*
*   Purpose:
*       Associate to an AP using a set of credentials.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_DisconnectAp()
*       BWL_ConnectNoSec()
*       BWL_ConnectWep()
*       BWL_ConnectWpaAes()
*       BWL_ConnectWpaTkip()
*       BWL_ConnectWpa2Aes()
*       BWL_ConnectWpa2Tkip()
*
*******************************************************************************/
int32_t BWL_ConnectAp
(
    BWL_Handle      hBwl,   /* [in] BWL Handle */
    Credential_t    *pCred  /* [in] connection credential */
)
{
    int32_t   err = 0;
 
    err = BWL_SetInfraMode( hBwl, pCred->eNetOpMode );
    BWL_CHECK_ERR( err );
 
    err = BWL_SetAuthType( hBwl, pCred->eAuthType );
    BWL_CHECK_ERR( err );
 
    err = BWL_SetWpaAuth( hBwl, pCred->eWpaAuth );
    BWL_CHECK_ERR( err );
 
    err = BWL_SetWSec( hBwl, pCred->eWSec );
    BWL_CHECK_ERR( err );
 
    err = BWL_SetWpaSup( hBwl, pCred->eWpaSup );
    BWL_CHECK_ERR( err );
 
    err = BWL_SetSsid( hBwl, pCred->acSSID, pCred->peBSSID );
    BWL_CHECK_ERR( err );
 
    if( pCred->eWSec == eWSecNone )
    {
        /* Do nothing */
        goto BWL_EXIT;
    }
    else if( pCred->eWSec == eWSecWep )
    {
        /* set the key and key index for wep */
        err = BWL_AddWepKey( hBwl,
                             pCred->ulWepIndex,
                             pCred->acKey,
                             eCryptoAlgoOff, /* dont' use overide */
                             1 );    /* primary key */
        BWL_CHECK_ERR( err );

        err = BWL_SetWepIndex( hBwl, pCred->ulWepIndex );
        BWL_CHECK_ERR( err );
    }
    else
    {
        /* set the key for tkip or aes */
        err = BWL_SetWSecKey( hBwl, pCred->acKey );
        BWL_CHECK_ERR( err );
    }
 
BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_DisconnectAp()
*
*   Purpose:
*       Disassociate from an AP.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_ConnectAp()
*       BWL_ConnectNoSec()
*       BWL_ConnectWep()
*       BWL_ConnectWpaAes()
*       BWL_ConnectWpaTkip()
*       BWL_ConnectWpa2Aes()
*       BWL_ConnectWpa2Tkip()
*
*******************************************************************************/
int32_t BWL_DisconnectAp
(
    BWL_Handle  hBwl    /* [in] BWL Handle */
)
{
    int32_t       err = 0;
    void        *wl = hBwl->wl;

    err = wlu_set( wl, WLC_DISASSOC, NULL, 0 );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_WpsConnectByPb()
*
*   Purpose:
*       Associate to an AP using WPS push button method.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_WpsConnectByPin()
*
*******************************************************************************/
#ifdef INCLUDE_WPS
int32_t BWL_WpsConnectByPb
(
    BWL_Handle  hBwl, 
    char        *pcNetIf, 
    char        *pKey, 
    uint32_t    ulKeyLength
)
{
    int32_t       err = 0;
    char bssid[6];
    char ssid[SIZE_SSID_LENGTH] = "broadcom\0";
    uint8 wsec = 1;
    uint band_num, active_band;
    char *bssid_ptr = bssid;
    char *pin = NULL;

    wps_osl_set_ifname( pcNetIf );
    config_init();

    if( find_pbc_ap((char *)bssid, (char *)ssid, &wsec) == 0 )
    {
        PRINTF(("%s, find_pbc_ap failed\n", __FUNCTION__));
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    /*
     * join. If user_bssid is specified, it might not
     * match the actual associated AP.
     * An implementation might want to make sure
     * it associates to the same bssid.
     * There might be problems with roaming.
     */
    leave_network();
    if (join_network_with_bssid(ssid, wsec, bssid_ptr)) {
        PRINTF(("Can not join [%s] network, Quit...\n", ssid));
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    /* update specific RF band */
    wps_get_bands(&band_num, &active_band);
    if (active_band == WLC_BAND_5G)
        active_band = WPS_RFBAND_50GHZ;
    else if (active_band == WLC_BAND_2G)
        active_band = WPS_RFBAND_24GHZ;
    else
        active_band = WPS_RFBAND_24GHZ;
    wps_update_RFBand((uint8)active_band);

    /* If user_bssid not defined, use associated AP's */
    if( wps_get_bssid( bssid ) )
    {
        PRINTF(("Can not get [%s] BSSID, Quit....\n", ssid));
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }
    bssid_ptr = bssid;

    /* setup raw 802.1X socket with "bssid" destination  */
    if( wps_osl_init(bssid) != WPS_SUCCESS )
    {
        PRINTF(("Initializing 802.1x raw socket failed. \n"));
        PRINTF(("Check PF PACKET support in kernel. \n"));
        wps_osl_deinit();
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    enroll_device(pin, ssid, wsec, bssid_ptr, pKey, ulKeyLength);


BWL_EXIT:
    wps_cleanup();
    return( err );
}
#endif

/*******************************************************************************
*
*   Name: BWL_WpsConnectByPin()
*
*   Purpose:
*       Associate to an AP using WPS PIN method.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_WpsConnectByPb()
*
*******************************************************************************/
#ifdef INCLUDE_WPS
int32_t BWL_WpsConnectByPin
(
    BWL_Handle  hBwl,
    char        *pcNetIf,
    char        *pcSsid,
    uint32_t    ulPin,
    char        *pKey,
    uint32_t    ulKeyLength
)
{
    int32_t               err = 0;
    wps_ap_list_info_t  *wpsaplist, *ap;
    uint8               wsec;
    uint32_t              band_num, active_band;
    char                *bssid_ptr = NULL;
    char                pin[9]; /* 8 digits + EOS */
    uint32_t              ulFound;


    /* Set up the network interface */
    wps_osl_set_ifname( pcNetIf );
    config_init();


    if( !wps_validateChecksum( ulPin ) )
    {
        PRINTF(( "\tInvalid PIN number parameter: %x\n", ulPin ));
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    /* get all the APs by calling scan and get scan results */
    wpsaplist = create_aplist();
    if( wpsaplist == NULL )
    {
        PRINTF(( "%s, create_aplist failed\n", __FUNCTION__ ));
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    /* filter out the AP that supports WPS */
    wps_get_aplist( wpsaplist, wpsaplist );


    /* find the BSSID associated with this SSID */
    ulFound = 0;
    ap      = wpsaplist;
    while( ap->used == TRUE)
    {
        if( strcmp( pcSsid, (char*)ap->ssid ) == 0 )
        {
            PRINTF(( "found %s  ", ap->ssid ));
            ulFound = 1;
            break;
        }
        ap++;
    }

    if( ulFound == 0)
    {
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }


    bssid_ptr = (char*)ap->BSSID;
    wsec      = ap->wep;
    sprintf( pin, "%08u", ulPin );
    PRINTF(( "pin =%s\n", pin ));
    PRINTF(( "bssid =%s\n", bssid_ptr ));

    leave_network();

    if( join_network_with_bssid( pcSsid, wsec, bssid_ptr ) )
    {
        PRINTF(("Can not join [%s] network, Quit...\n", pcSsid));
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    /* update specific RF band */
    wps_get_bands( &band_num, &active_band );
    if (active_band == WLC_BAND_5G)
        active_band = WPS_RFBAND_50GHZ;
    else if (active_band == WLC_BAND_2G)
        active_band = WPS_RFBAND_24GHZ;
    else
        active_band = WPS_RFBAND_24GHZ;
    wps_update_RFBand( (uint8)active_band );


    /* setup raw 802.1X socket with "bssid" destination  */
    if( wps_osl_init( bssid_ptr ) != WPS_SUCCESS )
    {
        PRINTF(("Initializing 802.1x raw socket failed. \n"));
        PRINTF(("Check PF PACKET support in kernel. \n"));
        wps_osl_deinit();
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }

    enroll_device( pin, pcSsid, wsec, bssid_ptr, pKey, ulKeyLength );

BWL_EXIT:
    wps_cleanup();
    return( err );
}
#endif


/*******************************************************************************
*
*   Name: BWL_Get802_11Modes()
*
*   Purpose:
*       Get 802.11n configuration modes.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*******************************************************************************/
int32_t BWL_Get802_11Modes(BWL_Handle hBwl, uint32_t *pModes)
{
    int32_t             err = 0;
    void                *wl = hBwl->wl;
    struct ether_addr   bssid;
    wl_bss_info_t       *bi;
    ScanInfo_t          tScanInfo;

    BWL_CHECK_ERR(pModes == NULL);

    memset( &bssid, 0, sizeof( bssid ) );
    memset( &tScanInfo, 0, sizeof( tScanInfo ) );

    err = wlu_get( wl, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN );
    BWL_CHECK_ERR( err );

    /* The adapter is associated. */
    *((uint32_t*)s_bufdata) = htod32( WLC_IOCTL_MAXLEN );
    err = wlu_get( wl, WLC_GET_BSS_INFO, s_bufdata, WLC_IOCTL_MAXLEN );
    BWL_CHECK_ERR( err );

    bi = (wl_bss_info_t*)(s_bufdata + 4);
    err = BWL_ParseBssInfo(bi, &tScanInfo);
    BWL_CHECK_ERR( err );

    *pModes = tScanInfo.ul802_11Modes;

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetCredential()
*
*   Purpose:
*       Get the stored credential from the driver.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*******************************************************************************/
int32_t BWL_GetCredential
(
    BWL_Handle      hBwl,   /* [in] BWL Handle */
    Credential_t    *pCred  /* [out] used to store credential */
)
{
    int32_t       err = 0;
    uint32_t      ulLen;

    PRINTF(( "--> BWL_GetCredential\n" ));
    err = BWL_GetInfraMode( hBwl, &(pCred->eNetOpMode) );
    BWL_CHECK_ERR( err );
    PRINTF(( "eNetOpMode = %d\n", pCred->eNetOpMode ));

    err = BWL_GetAuthType( hBwl, &(pCred->eAuthType) );
    BWL_CHECK_ERR( err );
    PRINTF(( "eAuthType = %d\n", pCred->eAuthType ));

    err = BWL_GetWSec( hBwl, &(pCred->eWSec) );
    BWL_CHECK_ERR( err );
    PRINTF(( "eWsec = %d\n", pCred->eWSec ));

    err = BWL_GetWpaAuth( hBwl, &(pCred->eWpaAuth) );
    BWL_CHECK_ERR( err );
    PRINTF(( "eWpaAuth = %d\n", pCred->eWpaAuth ));

    err = BWL_GetWpaSup( hBwl, &(pCred->eWpaSup) );
    BWL_CHECK_ERR( err );
    PRINTF(( "eWpaSup = %d\n", pCred->eWpaSup ));

    if( pCred->eWSec == eWSecWep )
    {
        err = BWL_GetWepIndex( hBwl, &(pCred->ulWepIndex) );
        BWL_CHECK_ERR( err );
        PRINTF(( "ulWepIndex = %d\n", pCred->ulWepIndex ));
    }


    err = BWL_GetCachedSsid( hBwl, pCred->acSSID, &ulLen );
    BWL_CHECK_ERR( err );


BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetConnectedInfo()
*
*   Purpose:
*       Fetch the BSS info and fill the ScanInfo_t structure
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*******************************************************************************/
int32_t BWL_GetConnectedInfo(BWL_Handle hBwl, ScanInfo_t *pScanInfo)
{
    int32_t             err = 0;
    void                *wl = hBwl->wl;
    struct ether_addr   bssid;
    wl_bss_info_t       *bi;

    BWL_CHECK_ERR(pScanInfo == NULL);

    memset( &bssid, 0, sizeof( bssid ) );

    err = wlu_get( wl, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN );
    BWL_CHECK_ERR( err );

    /* The adapter is associated. */
    *((uint32_t*)s_bufdata) = htod32( WLC_IOCTL_MAXLEN );
    err = wlu_get( wl, WLC_GET_BSS_INFO, s_bufdata, WLC_IOCTL_MAXLEN );
    BWL_CHECK_ERR( err );

    bi = (wl_bss_info_t*)(s_bufdata + 4);
    err = BWL_ParseBssInfo(bi, pScanInfo);
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );

}


/*******************************************************************************
*
*   Name: BWL_GetWepKey()
*
*   Purpose:
*       Get the stored WEP key from the driver.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*******************************************************************************/
int32_t BWL_GetWepKey
(
    BWL_Handle  hBwl,           /* [in] BWL Handle */
    uint32_t    ulIndex,        /* [in] WEP index 0-3 */
    uint32_t    ulIsPrimary,    /* [in] WEP current used index */
    char        *pcKey,         /* [out] WEP key */
    uint32_t    *pulLength      /* [in]/[out] WEP key length must be >= DOT11_MAX_KEY_SIZE */
)
{
    int32_t         err = 0;
    void            *wl = hBwl->wl;
    wl_wsec_key_t   key;
    uint32_t        ulLen;

    memset( &key, 0, sizeof( key ) );

    if( (NULL == pcKey) || (NULL == pulLength) ||
        (*pulLength < DOT11_MAX_KEY_SIZE) )
    {
        err = BWL_ERR_PARAM;
        BWL_CHECK_ERR( err );
    }

    if( ulIsPrimary )
        key.flags = WL_PRIMARY_KEY;

    key.index  = htod32( ulIndex );

    err = wlu_get( wl, WLC_GET_KEY, &key, sizeof( key ) );
    BWL_CHECK_ERR( err );

    ulLen = htod32( key.len );

    /* make sure that there is enough buffer to store the key */
    if( *pulLength < ulLen )
    {
        err = BWL_ERR_PARAM;
        BWL_CHECK_ERR( err );
    }

    /* update the key length and key */
    strncpy( pcKey, (char*)key.data, ulLen );
    *pulLength = ulLen;

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetEvent()
*
*   Purpose:
*       Set driver event message.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_ClearEvent()
*
*******************************************************************************/
int32_t BWL_SetEvent
(
    BWL_Handle      hBwl, 
    EventMessage_t  eEvent
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    i;
    uint8_t     event_inds_mask[ WL_EVENTING_MASK_LEN ]; /* 128-bit mask */

    err = wlu_iovar_get( wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN );
    BWL_CHECK_ERR( err );

    for (i = 0; i < sizeof(EventMessageTable)/sizeof(EventMessageTable[0]); i++)
    {
        if (EventMessageTable[i].eBwl == eEvent)
        {
            event_inds_mask[EventMessageTable[i].eWl / 8] |= 1 << (EventMessageTable[i].eWl % 8);

            err = wlu_iovar_set( wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN );
            BWL_CHECK_ERR( err );
            break;
        }
    }

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_ClearEvent()
*
*   Purpose:
*       Set driver's event message.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetEvent()
*       BWL_ParseEvent()
*
*******************************************************************************/
int32_t BWL_ClearEvent
(
    BWL_Handle      hBwl, 
    EventMessage_t  eEvent
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    i;
    uint8_t     event_inds_mask[ WL_EVENTING_MASK_LEN ]; /* 128-bit mask */

    err = wlu_iovar_get( wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN );
    BWL_CHECK_ERR( err );

    for (i = 0; i < sizeof(EventMessageTable)/sizeof(EventMessageTable[0]); i++)
    {
        if (EventMessageTable[i].eBwl == eEvent)
        {
            event_inds_mask[EventMessageTable[i].eWl / 8] &= ~(1 << (EventMessageTable[i].eWl % 8));
            err = wlu_iovar_set( wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN );
            BWL_CHECK_ERR( err );
            break;
        }
    }

BWL_EXIT:
    return( err );
}

/*******************************************************************************
*
*   Name: BWL_ParseEvent()
*
*   Purpose:
*       Parse the driver's event message.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetEvent()
*       BWL_ClearEvent()
*
*******************************************************************************/
int32_t BWL_ParseEvent
(
    BWL_Handle      hBwl, 
    void            *pBuff, 
    uint32_t        ulBufLength, 
    EventMessage_t  *pEvent
)
{
    int32_t         err = BWL_ERR_USAGE;
    void            *wl = hBwl->wl;
    uint32_t        i;
    bcm_event_t     *event;
    int32_t         event_type;

    if( wl == NULL )
        goto BWL_EXIT;
        
    if ( (pBuff == NULL) || (pEvent == NULL) || (ulBufLength < sizeof(bcm_event_t)) )
    {
        BWL_CHECK_ERR(err = BWL_ERR_PARAM);
    }

    event = (bcm_event_t *)pBuff;
    event_type = ntoh32(event->event.event_type);

    for (i = 0; i < sizeof(EventMessageTable)/sizeof(EventMessageTable[0]); i++)
    {
        if (EventMessageTable[i].eWl == event_type)
        {
            *pEvent = EventMessageTable[i].eBwl;
            err = BWL_ERR_SUCCESS;
            break;
        }
    }

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetSupAuthStatus()
*
*   Purpose:
*       This function is to get WPA authentication status.
*           (ie 4 way handshake status)
*       WLC_SUP_KEYD(6) is the status for authentication is completed.
*       Below shows the ioctl which this function is used
*       "sup_auth_status"(iovar):
*       get WPA authentication status
*       - WLC_SUP_DISCONNECTED(0): Not connected
*       - WLC_SUP_AUTHENTICATED(3): In authentication sequence
*       - WLC_SUP_KEYXCHANGE(5): In key exchange sequence
*       - WLC_SUP_KEYED(6): authentication completed.
*
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*******************************************************************************/
int32_t BWL_GetSupAuthStatus
(
    BWL_Handle  hBwl, 
    uint32_t    *pulStatus
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    uStatus;

    *pulStatus = 0;

    err = wlu_iovar_get( wl, "sup_auth_status", &uStatus, sizeof( uStatus ) );
    BWL_CHECK_ERR( err );

   *pulStatus = (uint32_t) htod32( uStatus );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetLinkStatus()
*
*   Purpose:
*       Returns the link status.  Return 1 if STA is connected (link is up), 0 if STA is
*       disconnected (link is down).
*
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*******************************************************************************/
int32_t BWL_GetLinkStatus
(
    BWL_Handle  hBwl,        /* [in] BWL Handle */
    uint32_t    *pulIsLinkUp /* [out] 1 is up, 0 is down */
)
{
    int32_t             err = 0;
    void                *wl = hBwl->wl;
    struct ether_addr   eth_addr;


    err = wlu_get( wl, WLC_GET_BSSID, &eth_addr, sizeof(struct ether_addr) );

    if( BWL_ERR_SUCCESS != err || 
        0 == memcmp(&eth_addr,&ether_null,sizeof(struct ether_addr)) ) 
    {
        *pulIsLinkUp = 0;
    }
    else 
    {  
        *pulIsLinkUp = 1;
    }

    return BWL_ERR_SUCCESS;
}


/*******************************************************************************
*
*   Name: BWL_GetRpcAgg()
*
*   Purpose:
*       Get RPC aggregation.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetRpcAgg()
*
*******************************************************************************/
int32_t BWL_GetRpcAgg
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t    *pulAgg  /* [out] Aggregation value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulAgg;

    err = wlu_iovar_get( wl, "rpc_agg", &ulAgg, sizeof( ulAgg ) );
    BWL_CHECK_ERR( err );

    *pulAgg = htod32( ulAgg );

BWL_EXIT:
    return( err );
}

/*******************************************************************************
*
*   Name: BWL_SetRpcAgg()
*
*   Purpose:
*       Set RPC aggregation.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetRpcAgg()
*
*******************************************************************************/
int32_t BWL_SetRpcAgg
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t    ulAgg  /* [in] Aggregation value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    err = wlu_iovar_set( wl, "rpc_agg", &ulAgg, sizeof( ulAgg ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetHtRestrict()
*
*   Purpose:
*       Get HT Rate restrict value.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetHtRestrict()
*
*******************************************************************************/
int32_t BWL_GetHtRestrict
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t    *pulVal   /* [out] Restrict value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulVal;

    err = wlu_iovar_get( wl, "ht_wsec_restrict", &ulVal, sizeof( ulVal ) );
    BWL_CHECK_ERR( err );

    *pulVal = htod32( ulVal );

BWL_EXIT:
    return( err );
}

/*******************************************************************************
*
*   Name: BWL_SetHtRestrict()
*
*   Purpose:
*       Set RPC aggregation.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetHtRestrict()
*
*******************************************************************************/
int32_t BWL_SetHtRestrict
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t    ulVal  /* [in] Restrict value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    err = wlu_iovar_set( wl, "ht_wsec_restrict", &ulVal, sizeof( ulVal ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetSisoTx()
*
*   Purpose:
*       Get SISO TX value.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetSisoTx()
*
*******************************************************************************/
int32_t BWL_GetSisoTx
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t    *pulVal  /* [out] SISO Value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulVal;

    err = wlu_iovar_get( wl, "siso_tx", &ulVal, sizeof( ulVal ) );
    BWL_CHECK_ERR( err );

    *pulVal = htod32( ulVal );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetSisoTx()
*
*   Purpose:
*       Set SISO TX value.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetSisoTx()
*
*******************************************************************************/
int32_t BWL_SetSisoTx
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t    ulVal  /* [in] SISO Value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    err = wlu_iovar_set( wl, "siso_tx", &ulVal, sizeof( ulVal ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetStaRetryTime()
*
*   Purpose:
*       Get STA retry time.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetStaRetryTime()
*
*******************************************************************************/
int32_t BWL_GetStaRetryTime
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t    *pulVal  /* [out] Value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulVal;

    err = wlu_iovar_get( wl, "sta_retry_time", &ulVal, sizeof( ulVal ) );
    BWL_CHECK_ERR( err );

    *pulVal = htod32( ulVal );

BWL_EXIT:
    return( err );
}

/*******************************************************************************
*
*   Name: BWL_SetStaRetryTime()
*
*   Purpose:
*       Set STA retry value.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetStaRetryTime()
*
*******************************************************************************/
int32_t BWL_SetStaRetryTime
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t    ulVal  /* [in] Value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    err = wlu_iovar_set( wl, "sta_retry_time", &ulVal, sizeof( ulVal ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetMimoBwCap()
*
*   Purpose:
*       Get the mimo bandwidth cap.
*       0 - 20 Mhz only
*       1 - 40 Mhz
*       2 - 20 Mhz in 2.4G, 40Mhz in 5G
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetMimoBwCap()
*
*******************************************************************************/
int32_t BWL_GetMimoBwCap
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t    *pulVal  /* [out] Value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulVal;

    err = wlu_iovar_get( wl, "mimo_bw_cap", &ulVal, sizeof( ulVal ) );
    BWL_CHECK_ERR( err );

    *pulVal = htod32( ulVal );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_SetMimoBwCap()
*
*   Purpose:
*       Set the mimo bandwidth cap.
*       0 - 20 Mhz only
*       1 - 40 Mhz
*       2 - 20 Mhz in 2.4G, 40Mhz in 5G
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetMimoBwCap()
*
*******************************************************************************/
int32_t BWL_SetMimoBwCap
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t    ulVal  /* [in] Value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    if( ulVal > WLC_N_BW_20IN2G_40IN5G )
    {
        BWL_CHECK_ERR( err = BWL_ERR_PARAM );
    }
    else
    {
        err = wlu_iovar_set( wl, "mimo_bw_cap", &ulVal, sizeof( ulVal ) );
        BWL_CHECK_ERR( err );
    }


BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetApBwCap()
*
*   Purpose:
*       Set the mimo bandwidth cap.
*       0 - 20 Mhz only
*       1 - 40 Mhz
*       2 - 20 Mhz in 2.4G, 40Mhz in 5G
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_GetApBwCap
(
    BWL_Handle  hBwl,           /* [in] BWL Handle */
    uint32_t    *pulBandWidth   /* [out] 0 is 20MHz or Not Connect, 1 is 40MHz */
)
{
    int32_t         err = 0;
    void            *wl = hBwl->wl;
    uint32_t        ulIsLinkUp=0;
    uint32_t        ulBandWidth=0;
    wl_bss_info_t   *bi;
    char            *pbuf=NULL;


    err = BWL_GetLinkStatus( hBwl, &ulIsLinkUp);
    BWL_CHECK_ERR( err );

    if( 0 == ulIsLinkUp )
    {  /* link is down */
        /* do nothing */
    }
    else
    {
        /* link is up */
        /* Get AP's Capability */
        pbuf = malloc( WLC_IOCTL_MAXLEN );

        if( NULL == pbuf )
        {
            BWL_CHECK_ERR( err = BWL_ERR_ALLOC );
        }

        *((uint32_t*)pbuf) = htod32( WLC_IOCTL_MAXLEN );
        err = wlu_get( wl, WLC_GET_BSS_INFO, pbuf, WLC_IOCTL_MAXLEN );
        BWL_CHECK_ERR( err );
        bi = (wl_bss_info_t*)(pbuf + 4);

        if( 0 == memcmp(&bi->BSSID,&ether_null,sizeof(struct ether_addr)) )
        {
        }
        else
        {
            if (dtoh32(bi->nbss_cap) & HT_CAP_40MHZ)
            {
                ulBandWidth = 1;
            }
        }
    }

    *pulBandWidth = htod32( ulBandWidth );

BWL_EXIT:
    if( pbuf )
    {
        free( pbuf );
    }
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetDptCredential()
*
*   Purpose:
*       Get the stored DPT credential from the driver.
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*******************************************************************************/
int32_t BWL_GetDptCredential
(
    BWL_Handle          hBwl,  /* [in] BWL Handle */
    DptCredential_t    *pCred  /* [out] used to store credential */
)
{
    int32_t       err = 0;
    void        *wl = hBwl->wl;
    uint32_t      ulWpaAuth;
    uint32_t      ulWSec;
    uint32_t      ii;


    err = wlu_iovar_get( wl, "dpt_wsec", &ulWSec, sizeof( ulWSec ) );
    BWL_CHECK_ERR( err );
    pCred->eWSec = (WSec_t)(htod32( ulWSec ));
    PRINTF(( "eWSec = %d\n", pCred->eWSec ));

    err = wlu_iovar_get( wl, "dpt_wpa_auth", &ulWpaAuth, sizeof( ulWpaAuth ) );
    BWL_CHECK_ERR( err );
    pCred->eWpaAuth = (WpaAuth_t)htod32( ulWpaAuth );
    PRINTF(( "eWpaAuth = %d\n", pCred->eWpaAuth ));

    err = wlu_iovar_get( wl, "dpt_pmk", &(pCred->Pmk), sizeof(pCred->Pmk) );
    BWL_CHECK_ERR( err );

    PRINTF(("key == "));
    for( ii = 0; ii < pCred->Pmk.KeyLen; ii++ )
    {
        PRINTF(( "%c", pCred->Pmk.Key[ii] ));
    }
    PRINTF(("\n"));

    err = wlu_iovar_get( wl, "dpt_fname", &(pCred->FName), sizeof( DptFName_t ) );
    BWL_CHECK_ERR( err );

    PRINTF(("friendly name == "));
    for( ii = 0; ii < pCred->FName.Len; ii++ )
    {
        PRINTF(( "%c", pCred->FName.name[ii] ));
    }
    PRINTF(("\n"));

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetDptMode()
*
*   Purpose:
*       Get DPT mode.
*       0 - disable
*       1 - enable
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_SetDptMode()
*
*******************************************************************************/
int32_t BWL_GetDptMode
(
    BWL_Handle  hBwl,    /* [in] BWL Handle */
    uint32_t    *pulVal  /* [out] Value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    ulVal;

    err = wlu_iovar_get( wl, "dpt", &ulVal, sizeof( ulVal ) );
    BWL_CHECK_ERR( err );

    *pulVal = htod32( ulVal );

BWL_EXIT:
    return( err );
}

/*******************************************************************************
*
*   Name: BWL_SetDptMode()
*
*   Purpose:
*       Set DPT mode.
*       0 - disable
*       1 - enable
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*       BWL_GetDptMode()
*
*******************************************************************************/
int32_t BWL_SetDptMode
(
    BWL_Handle  hBwl,  /* [in] BWL Handle */
    uint32_t    ulVal  /* [in] Value */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;

    err = wlu_iovar_set( wl, "dpt", &ulVal, sizeof( ulVal ) );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}

/*******************************************************************************
*
*   Name: BWL_GetRate()
*
*   Purpose:
*       Return the current rate/speed in 500 Kbits/s units
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_GetRate
(
	BWL_Handle	 hBwl,      /* [in] BWL Handle */
	int32_t     *plRate     /* [out] Rate      */
)
{
    int32_t err = 0;
    void    *wl = hBwl->wl;

    if ( (plRate == NULL) || (hBwl == NULL) )
    {
        BWL_CHECK_ERR(BWL_ERR_PARAM);
    }

    err = wlu_get(wl, WLC_GET_RATE, plRate, sizeof(int32_t));

    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}

/*******************************************************************************
*
*   Name: BWL_SetRSSIEventLevels()
*
*   Purpose:
*       Set the level to which we will receive event notifications for signal
*       strengh changes
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_SetRSSIEventLevels
(
    BWL_Handle      hBwl,          /* [in] BWL Handle */
    int32_t         *plLevel,      /* [in] value      */
    uint32_t        ulNumLevels    /* [in] value      */
)   
{
    wl_rssi_event_t rssi;
    int     i;
    int32_t err = 0;
    void    *wl = hBwl->wl;

    memset(&rssi, 0, sizeof(wl_rssi_event_t));

    rssi.rate_limit_msec = (plLevel == NULL) ? 0 : 500;
    rssi.num_rssi_levels = ulNumLevels;

    for (i = 0; i < ulNumLevels; i++)
    {
        rssi.rssi_levels[i] = plLevel[i];
    }

    err = wlu_iovar_set(wl, "rssi_event", &rssi, sizeof(wl_rssi_event_t));
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GetRSSI()
*
*   Purpose:
*       Fetch the RSSI for a current connected AP
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_GetRSSI
(
    BWL_Handle hBwl,    /* [in] BWL Handle */
	int32_t *plRSSI     /* [out] RSSI      */
)
{
    int32_t err = 0;
    void    *wl = hBwl->wl;

    if( plRSSI == NULL )
    {
        BWL_CHECK_ERR(BWL_ERR_PARAM);
    }

    err = wlu_get(wl, WLC_GET_RSSI, plRSSI, sizeof(int32_t));

    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_GenerateDptKey()
*
*   Purpose:
*       Set DPT mode.
*       0 - disable
*       1 - enable
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
#ifdef INCLUDE_WPS
int32_t BWL_GenerateDptKey
(
    BWL_Handle  hBwl,   /* [in] BWL Handle */
    WSecPmk_t   *dptkey /* [out] DPT Key */
)

{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint8       key[9] = "BRCM"; /* 8 chars */

    /* Use wps to generate PIN for now */
    err = wps_generatePin( (char*)key, 9, 0 );
    if( WPS_SUCCESS != err )
    {
        err = BWL_ERR_PARAM;
    }
    else
    {
        dptkey->KeyLen = 8;
        dptkey->Flags   = WSEC_PASSPHRASE;
        strncpy( (char*)dptkey->Key, (char*)key, dptkey->KeyLen );
        err = BWL_ERR_SUCCESS;
    }

    return( err );
}
#endif


/*******************************************************************************
*
*   Name: BWL_SetDptSecurity()
*
*   Purpose:
*       Set DPT security
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
#ifdef INCLUDE_WPS 
int32_t BWL_SetDptSecurity
(
    BWL_Handle  hBwl   /* [in] BWL Handle */
)
{
    int32_t     err = 0;
    void        *wl = hBwl->wl;
    uint32_t    dpt_wsec = 4, sup_wpa = 1, dpt_wpa_auth = 0x200;
    wsec_pmk_t  key;

    err = BWL_GenerateDptKey( hBwl, &key );
    BWL_CHECK_ERR( err );

    err = wlu_iovar_set( wl, "dpt_pmk", &key, sizeof(key));
    BWL_CHECK_ERR( err );

    err = wlu_iovar_set( wl, "dpt_wsec", &dpt_wsec, sizeof(dpt_wsec));
    BWL_CHECK_ERR( err );

    err = wlu_iovar_set( wl, "sup_wpa", &sup_wpa, sizeof(sup_wpa));
    BWL_CHECK_ERR( err );

    err = wlu_iovar_set( wl, "dpt_wpa_auth", &dpt_wpa_auth, sizeof(dpt_wpa_auth));
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );

}
#endif


/*******************************************************************************
*
*   Name: BWL_GetDptList()
*
*   Purpose:
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_GetDptList
(
    BWL_Handle  hBwl,   /* [in] BWL Handle */
    DptList_t   *data
)
{
    int32_t         err = 0;
    void            *wl = hBwl->wl;
    dpt_list_t      *list;
    unsigned char   buf[1024];


    err = wlu_iovar_get( wl, "dpt_list", buf, sizeof(DptList_t) );
    BWL_CHECK_ERR( err );

    {
        int i;
        list = (dpt_list_t *)buf;
        data->ulNum = list->num;
        for(i=0; i < list->num; i++)
        {
            memcpy(data->Sta[i].mac.octet, list->status[i].sta.ea.octet, 6);
            strncpy((char*)data->Sta[i].FName, (char*)list->status[i].name, list->status[i].fnlen);

            data->Sta[i].ulRssi = list->status[i].rssi;

            data->Sta[i].ulTxFailures   = list->status[i].sta.tx_failures;
            data->Sta[i].ulTxPkts       = list->status[i].sta.tx_pkts;
            data->Sta[i].ulRxUcastPkts = list->status[i].sta.rx_ucast_pkts;
            data->Sta[i].ulTxRate       = list->status[i].sta.tx_rate;
            data->Sta[i].ulRxRate       = list->status[i].sta.rx_rate;

            data->Sta[i].ulRxDecryptSucceeds = list->status[i].sta.rx_decrypt_succeeds;
            data->Sta[i].ulRxDecryptFailures = list->status[i].sta.rx_decrypt_failures;
        }
    }
BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_Get_counter()
*
*   Purpose:
*		Get value of specified counter
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/

int32_t BWL_GetCounter
(
    BWL_Handle      hBwl,    /* [in] BWL Handle */
    char            *pName,  /* [in] the counter name, NULL to dump all */
    uint32_t        *pVal    /* [out] the counter value */
)
{
    int32_t   err = 0;
    void     *wl = hBwl->wl;
    
    err = bwl_get_counter( wl, pName, pVal );
    BWL_CHECK_ERR( err );

BWL_EXIT:
    return( err );
}


/*******************************************************************************
*
*   Name: BWL_Get_RevInfo()
*
*   Purpose:
*       Get revision info
*
*   Returns:
*       BWL_ERR_xxx
*
*   See Also:
*
*
*******************************************************************************/
int32_t BWL_GetRevInfo
(
    BWL_Handle      hBwl,       /* [in] BWL Handle */
    RevInfo_t      *pRevInfo    /* [out] RevInfo  */
)
{
    int32_t   err = 0;
    void     *wl = hBwl->wl;
    wlc_rev_info_t wlc_rev_info;

    if( pRevInfo == NULL )
        return( err );
        
    memset(pRevInfo, 0, sizeof(RevInfo_t));
    memset(&wlc_rev_info, 0, sizeof(wlc_rev_info_t));

    err = wlu_get(wl, WLC_GET_REVINFO, &wlc_rev_info, sizeof(wlc_rev_info_t));
    if (err < 0) {
        return (err);
    }

    pRevInfo->ulVendorId    = dtoh32(wlc_rev_info.vendorid);
    pRevInfo->ulDeviceId    = dtoh32(wlc_rev_info.deviceid);
    pRevInfo->ulRadioRev    = dtoh32(wlc_rev_info.radiorev);
    pRevInfo->ulChipNum     = dtoh32(wlc_rev_info.chipnum);
    pRevInfo->ulChipRev     = dtoh32(wlc_rev_info.chiprev);
    pRevInfo->ulChipPkg     = dtoh32(wlc_rev_info.chippkg);
    pRevInfo->ulCoreRev     = dtoh32(wlc_rev_info.corerev);
    pRevInfo->ulBoardId     = dtoh32(wlc_rev_info.boardid);
    pRevInfo->ulBoardVendor = dtoh32(wlc_rev_info.boardvendor);
    pRevInfo->ulBoardRev    = dtoh32(wlc_rev_info.boardrev);
    pRevInfo->ulDriverRev   = dtoh32(wlc_rev_info.driverrev);
    pRevInfo->ulUcodeRev    = dtoh32(wlc_rev_info.ucoderev);
    pRevInfo->ulBus         = dtoh32(wlc_rev_info.bus);
    pRevInfo->ulPhyType     = dtoh32(wlc_rev_info.phytype);
    pRevInfo->ulPhyRev      = dtoh32(wlc_rev_info.phyrev);
    pRevInfo->ulAnaRev      = dtoh32(wlc_rev_info.anarev);

    return 0 ;

}
