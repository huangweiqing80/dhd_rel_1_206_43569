/*
 * Linux bwl test application
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bwltest.c,v 1.16 2010-12-16 18:48:00 $
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
/* sockets */
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
#include "bwl.h"
#include "wlu.h"
typedef struct sEventToString
{
    uint32  ulEvent;
    char    aEventName[30];
} EventToString_t;
int wl_format_ssid(char* ssid_buf, uint8* ssid, int ssid_len);
/* Event messages */
EventToString_t g_Events[] ={
{WLC_E_SET_SSID,                 "WLC_E_SET_SSID"},
{WLC_E_JOIN,                     "WLC_E_JOIN"},
{WLC_E_START,                    "WLC_E_START"},
{WLC_E_AUTH,                     "WLC_E_AUTH"},
{WLC_E_AUTH_IND,                 "WLC_E_AUTH_IND"},
{WLC_E_DEAUTH,                   "WLC_E_DEAUTH"},
{WLC_E_DEAUTH_IND,               "WLC_E_DEAUTH_IND"},
{WLC_E_ASSOC,                    "WLC_E_ASSOC"},
{WLC_E_ASSOC_IND,                "WLC_E_ASSOC_IND"},
{WLC_E_REASSOC,                  "WLC_E_REASSOC"},
{WLC_E_REASSOC_IND,              "WLC_E_REASSOC_IND"},
{WLC_E_DISASSOC,                 "WLC_E_DISASSOC"},
{WLC_E_DISASSOC_IND,             "WLC_E_DISASSOC_IND"},
{WLC_E_QUIET_START,              "WLC_E_QUIET_START"},
{WLC_E_QUIET_END,                "WLC_E_QUIET_END"},
{WLC_E_BEACON_RX,                "WLC_E_BEACON_RX"},
{WLC_E_LINK,                     "WLC_E_LINK"},
{WLC_E_MIC_ERROR,                "WLC_E_MIC_ERROR"},
{WLC_E_NDIS_LINK,                "WLC_E_NDIS_LINK"},
{WLC_E_ROAM,                     "WLC_E_ROAM"},
{WLC_E_TXFAIL,                   "WLC_E_TXFAIL"},
{WLC_E_PMKID_CACHE,              "WLC_E_PMKID_CACHE"},
{WLC_E_RETROGRADE_TSF,           "WLC_E_RETROGRADE_TSF"},
{WLC_E_PRUNE,                    "WLC_E_PRUNE"},
{WLC_E_AUTOAUTH,                 "WLC_E_AUTOAUTH"},
{WLC_E_EAPOL_MSG,                "WLC_E_EAPOL_MSG"},
{WLC_E_SCAN_COMPLETE,            "WLC_E_EAPOL_MSG"},
{WLC_E_ADDTS_IND,                "WLC_E_ADDTS_IND"},
{WLC_E_DELTS_IND,                "WLC_E_DELTS_IND"},
{WLC_E_BCNSENT_IND,              "WLC_E_BCNSENT_IND"},
{WLC_E_BCNRX_MSG,                "WLC_E_BCNRX_MSG"},
{WLC_E_BCNLOST_MSG,              "WLC_E_BCNLOST_MSG"},
{WLC_E_ROAM_PREP,                "WLC_E_ROAM_PREP"},
{WLC_E_PFN_NET_FOUND,            "WLC_E_PFN_NET_FOUND"},
{WLC_E_PFN_NET_LOST,             "WLC_E_PFN_NET_LOST"},
{WLC_E_RESET_COMPLETE,           "WLC_E_RESET_COMPLETE"},
{WLC_E_JOIN_START,               "WLC_E_JOIN_START"},
{WLC_E_ROAM_START,               "WLC_E_ROAM_START"},
{WLC_E_ASSOC_START,              "WLC_E_ASSOC_START"},
{WLC_E_IBSS_ASSOC,               "WLC_E_IBSS_ASSOC"},
{WLC_E_RADIO    ,                "WLC_E_RADIO"},
{WLC_E_PSM_WATCHDOG,             "WLC_E_PSM_WATCHDOG"},
//{WLC_E_CCX_ASSOC_START,          "WLC_E_CCX_ASSOC_START"},
//{WLC_E_CCX_ASSOC_ABORT,          "WLC_E_CCX_ASSOC_ABORT"},
{WLC_E_PROBREQ_MSG,              "WLC_E_PROBREQ_MSG"},
{WLC_E_SCAN_CONFIRM_IND,         "WLC_E_SCAN_CONFIRM_IND"},
{WLC_E_PSK_SUP,                  "WLC_E_PSK_SUP"},
{WLC_E_COUNTRY_CODE_CHANGED,     "WLC_E_COUNTRY_CODE_CHANGED"},
{WLC_E_EXCEEDED_MEDIUM_TIME,     "WLC_E_EXCEEDED_MEDIUM_TIME"},
{WLC_E_ICV_ERROR,                "WLC_E_ICV_ERROR"},
{WLC_E_UNICAST_DECODE_ERROR,     "WLC_E_UNICAST_DECODE_ERROR"},
{WLC_E_MULTICAST_DECODE_ERROR,   "WLC_E_MULTICAST_DECODE_ERROR"},
{WLC_E_TRACE,                    "WLC_E_TRACE"},
//{WLC_E_BTA_HCI_EVENT,            "WLC_E_BTA_HCI_EVENT"},
{WLC_E_IF,                       "WLC_E_IF"},
{WLC_E_RSSI,                     "WLC_E_RSSI"},
{WLC_E_PFN_SCAN_COMPLETE,        "WLC_E_PFN_SCAN_COMPLETE"},
{WLC_E_EXTLOG_MSG,               "WLC_E_EXTLOG_MSG"},
//{WLC_E_ACTION_FRAME,             "WLC_E_ACTION_FRAME"},
{WLC_E_PRE_ASSOC_IND,            "WLC_E_PRE_ASSOC_IND"},
{WLC_E_PRE_REASSOC_IND,          "WLC_E_PRE_REASSOC_IND"},
{WLC_E_CHANNEL_ADOPTED,          "WLC_E_CHANNEL_ADOPTED"},
{WLC_E_AP_STARTED,               "WLC_E_AP_STARTED"},
{WLC_E_DFS_AP_STOP,              "WLC_E_DFS_AP_STOP"},
{WLC_E_DFS_AP_RESUME,            "WLC_E_DFS_AP_RESUME"},
{WLC_E_LAST,                     "WLC_E_LAST"}};


static char *s_cmdbuff[] =
{
    "ver",
    "up",
    "down",
    "scan",
    "disassoc",
    "isup",
    "status",
    "scanresults",
    "ifconfig",
    "sup_wpa",
    "channel",
    "wpa_auth",
    "country",
    "channels_in_country",
    "infra",
    "wsec",
    "set_pmk",
    "get_pmk",
    "ssid",
    "get_cached_ssid",
    "auth",
    "addwep",
    "wps",
    "cred",
    "event",
    "processevent",
    "connect_no_wep",
    "connect_wep",
    "connect_tkip",
    "connect_aes",
    "connect_tkip2",
    "connect_aes2",
    "is_link_up",
    "dpt_cred",
    "rpc_agg",
    "ht_wsec_restrict",
    "dpt",
    "siso_tx",
    "dptkey",
    "dptlist",
    "sta_retry_time",
    "interference",
    "ap_bw_cap",
    "mimo_bw_cap",
    "counters",
    "revinfo",
    "scanabort",
    NULL
};

typedef struct BWL_P_Handle
{
    void    *wl;
} BWL_P_Handle;

//---------------------------------------------------------------------------
// BWL specifics
//---------------------------------------------------------------------------
#include "bwl.h"
int BWL_ProcessEvent(BWL_Handle hBwl);
char* BWL_LookUpEvent(BWL_Handle hBwl, uint32 ulEvent);

#ifndef BUILD_SHARED_LIB
/*
 * Name        : main
 * Description : Main entry point for the WPS stack
 * Arguments   : int argc, char *argv[] - command line parameters
 * Return type : int
 */
int
main(int argc, char* argv[])
{
#ifdef INCLUDE_WPS	
    int32 WPS_Init(void);
    WPS_Init();
#endif	

    {
        int32 BWL_Test(int argc, char **argv);
        BWL_Test( argc, argv );
    }
    return 0;
}
#endif


/*
 * Name        : main
 * Description : Main entry point for the WPS stack
 * Arguments   : int argc, char *argv[] - command line parameters
 * Return type : int
 */

int
BWL_Test(int argc, char* argv[])
{
    ScanInfo_t      *pData = NULL;
    uint32          ii;
    uint32          ulNumOfAp;
    BWL_Handle      hBwl = NULL;
    uint32          ulVal;
    int32           lErr = 0;
    uint32          ulChannels;
    uint32          aulChannels[BWL_MAX_CHANNEL];
    char            acCountry[WLC_CNTRY_BUF_SZ];
    char            acSsid[DOT11_MAX_SSID_LEN+1];

    if( argc < 2 )
    {
        printf( "supported commands:\n" );
        ii = 0;
        while( s_cmdbuff[ ii ] != NULL )
        {
            printf( "%s ", s_cmdbuff[ ii ] );
            ii++;
        }
        printf("\n");
        printf( "eg: %s up, %s scan, etc\n", argv[0], argv[0] );
        return( BWL_ERR_USAGE );
    }

    /* check for valid commands */
    ii = 0;
    while( s_cmdbuff[ ii ] != NULL )
    {
        if( !(strcmp(argv[1], s_cmdbuff[ ii ])) )
            break;
        ii++;
    }

    if( s_cmdbuff[ ii ] == NULL )
    {
        printf( "unsupported command: \"%s\"\n", argv[1] );
        return( BWL_ERR_USAGE );
    }


    lErr = BWL_Init( &hBwl );
    BWL_CHECK_ERR( lErr );
    if( lErr )
    {
        fprintf( stderr, "%s: wl driver adapter not found\n", argv[0] );
        return( BWL_ERR_USAGE );
    }

    if( !strcmp( argv[1], "ifconfig" ) )
    {
        pid_t pid;

        /* create a new process to execute the command */
        /* arg1 = ifconfig, arg2 = eth, arg3 = ip, arg4 = up */
        if( (pid = fork()) == 0 )
        {
            /* execlp( "ifconfig", "ifconfig", "eth1", "192.168.1.200", "up", NULL ); */
            /* this function returns if an error occurred */
            execlp( argv[1], argv[1], argv[2], argv[3], argv[4], NULL );

            /* if execlp() failed this is called */
            fprintf( stderr, "failed execlp %s\n", argv[1] );
        }
    }
    else if( !strcmp( argv[1], "ver" ) )
    {
        printf("*********************************************\n");
        printf("BWL - Broadcom Wireless App.\n");
        printf("Version: %s\n", BWL_VERSION_STR );
        printf("BldDate: %s %s\n", __DATE__, __TIME__);
        printf("*********************************************\n");
    }
    else if( !strcmp( argv[1], "up" ) )
    {
        lErr = BWL_Up( hBwl );
        BWL_CHECK_ERR( lErr );

        printf( "BWL is up\n" );
    }
    else if( !strcmp( argv[1], "isup" ) )
    {
        lErr = BWL_IsUp( hBwl, &ulVal );
        printf( "BWL is up = %d\n", ulVal );
    }
    else if( !strcmp( argv[1], "down" ) )
    {
        lErr = BWL_Down( hBwl );
        BWL_CHECK_ERR( lErr );

        printf( "BWL is down\n" );
    }
    else if( !strcmp( argv[1], "scan" ) )
    {
        ScanParams_t ScanParams;

        memset( &ScanParams, 0, sizeof(ScanParams) );
        ScanParams.lActiveTime  = BWL_DEFAULT_SCAN_DWELL_TIME;
        ScanParams.lPassiveTime = BWL_DEFAULT_SCAN_DWELL_TIME;
        ScanParams.lHomeTime    = BWL_DEFAULT_SCAN_DWELL_TIME;
        lErr = BWL_Scan( hBwl, &ScanParams );
        BWL_CHECK_ERR( lErr );
        sleep(5);

        /* Get the total IPs */
        lErr = BWL_GetScannedApNum( hBwl, &ulNumOfAp );
        BWL_CHECK_ERR( lErr );

        printf( "Num of Ap: %d\n", ulNumOfAp );
        pData = (ScanInfo_t*)malloc( ulNumOfAp * sizeof( ScanInfo_t ) );
        if( pData )
        {
            lErr = BWL_GetScanResults( hBwl, pData );
            BWL_CHECK_ERR( lErr );
            for( ii = 0; ii < ulNumOfAp; ii++ )
            {
                /* display data */
                printf( "SSID: \"%s\" BSSID: %02x:%02x:%02x:%02x:%02x:%02x RSSI: %d dB Chan: %d\n", pData[ii].tCredentials.acSSID,
                        pData[ii].BSSID.octet[0], pData[ii].BSSID.octet[1], pData[ii].BSSID.octet[2], 
                        pData[ii].BSSID.octet[3], pData[ii].BSSID.octet[4], pData[ii].BSSID.octet[5], 
                        pData[ii].lRSSI, pData[ii].ulChan );
            }
        }
    }
    else if( !strcmp( argv[1], "counters" ) )
    {
        uint32 uValue;
        if ( argc == 3) 
        {
            lErr = BWL_GetCounter(hBwl, argv[2], &uValue);
            if (!lErr ) 
                printf(" %s = %d (0x%x) \n", argv[2], uValue, uValue);
        }
        else
            BWL_GetCounter (hBwl, NULL, NULL);
    }
    else if( !strcmp( argv[1], "revinfo" ) )
    {
        RevInfo_t RevInfo;
        char b[8];
        lErr = BWL_GetRevInfo (hBwl, &RevInfo);
        BWL_CHECK_ERR( lErr );

        printf("vendorid 0x%x\n", RevInfo.ulVendorId);
        printf("deviceid 0x%x\n", RevInfo.ulDeviceId);
        printf("radiorev 0x%x\n", RevInfo.ulRadioRev);
        printf("chipnum 0x%x\n", RevInfo.ulChipNum);
        printf("chiprev 0x%x\n", RevInfo.ulChipRev);
        printf("chippackage 0x%x\n", RevInfo.ulChipPkg);
        printf("corerev 0x%x\n", RevInfo.ulCoreRev);
        printf("boardid 0x%x\n", RevInfo.ulBoardId);
        printf("boardvendor 0x%x\n", RevInfo.ulBoardVendor);
        if (RevInfo.ulBoardRev < 0x100)
                sprintf(b, "%d.%d", (RevInfo.ulBoardRev & 0xf0) >> 4, RevInfo.ulBoardRev & 0xf);
        else
                sprintf(b, "%c%03x", ((RevInfo.ulBoardRev & 0xf000) == 0x1000) ? 'P' : 'A', RevInfo.ulBoardRev & 0xfff);
        b[8]='\0';
        printf("boardrev %s\n", b);
        printf("driverrev 0x%x\n", RevInfo.ulDriverRev);
        printf("ucoderev 0x%x\n", RevInfo.ulUcodeRev);
        printf("bus 0x%x\n", RevInfo.ulBus);
        printf("phytype 0x%x\n", RevInfo.ulPhyType);
        printf("phyrev 0x%x\n", RevInfo.ulPhyRev);
        printf("anarev 0x%x\n", RevInfo.ulAnaRev);

    }
    else if( !strcmp( argv[1], "scanabort" ) )
    {
        lErr = BWL_ScanAbort (hBwl);
        BWL_CHECK_ERR( lErr );
    }
    else if( !strcmp( argv[1], "status" ) )
    {
        char pcSSID[DOT11_MAX_SSID_LEN + 1];
        int32 lRSSI;

        memset(pcSSID, 0, DOT11_MAX_SSID_LEN + 1);
        lErr = BWL_GetConnectedAp( hBwl, pcSSID, DOT11_MAX_SSID_LEN, &lRSSI );
        BWL_CHECK_ERR( lErr );

        printf("SSID: %s, RSSI= %d dBm\n", pcSSID, lRSSI);
    }
    else if( !strcmp( argv[1], "connect_no_wep" ) )
    {
        struct ether_addr peBSSID;
        if( argc == 4 )
        {
            if (!wl_ether_atoe(argv[3], &peBSSID)) {
                fprintf(stderr,"could not parse \"%s\" as an ethernet MAC address\n", argv[3]);
                lErr = -1;
                goto BWL_EXIT;
            }

            lErr = BWL_ConnectNoSec( hBwl, eNetOpModeInfra, argv[2] , &peBSSID);
            BWL_CHECK_ERR( lErr );
        } else if ( argc == 3 ) {
            lErr = BWL_ConnectNoSec( hBwl, eNetOpModeInfra, argv[2] , NULL);
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            printf( "%s %s <ssid> <bssid(optional)>\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "connect_wep" ) )
    {
        struct ether_addr peBSSID;
        if( argc == 7 )
        {
            if (!wl_ether_atoe(argv[6], &peBSSID)) 
            {
                fprintf(stderr,"could not parse \"%s\" as an ethernet MAC address\n", argv[6]);
                lErr = -1;
                goto BWL_EXIT;
            }

            lErr = BWL_ConnectWep(  hBwl,
                                    eNetOpModeInfra,
                                    argv[2], /* SSID */
                                    argv[3], /* Key */
                                    atoi(argv[4]), /* key index */
                                    atoi(argv[5]), /* 0 - open, 1 - shared */
                                    &peBSSID); /* BSSID */
            BWL_CHECK_ERR( lErr );
        } 
        else if( argc == 6 ) 
        {
            lErr = BWL_ConnectWep(  hBwl,
                                    eNetOpModeInfra,
                                    argv[2], /* SSID */
                                    argv[3], /* Key */
                                    atoi(argv[4]), /* key index */
                                    atoi(argv[5]),  /* 0 - open, 1 - shared */
                                    NULL);
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            printf( "%s %s <ssid> <key> <key index> <open, shared> <bssid(optional)>\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "connect_tkip" ) )
    {
        struct ether_addr peBSSID;
        if( argc == 5 )
        {
            if (!wl_ether_atoe(argv[4], &peBSSID)) 
            {
                fprintf(stderr,"could not parse \"%s\" as an ethernet MAC address\n", argv[4]);
                lErr = -1;
                goto BWL_EXIT;
            }
            lErr = BWL_ConnectWpaTkip(  hBwl,
                                        eNetOpModeInfra,
                                        argv[2], /* SSID */
                                        argv[3],  /* Key */
                                        &peBSSID); /*BSSID */
            BWL_CHECK_ERR( lErr );
        } else if( argc == 4 ) {
            lErr = BWL_ConnectWpaTkip(  hBwl,
                                        eNetOpModeInfra,
                                        argv[2], /* SSID */
                                        argv[3],  /* Key */
                                        NULL);
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            printf( "%s %s <ssid> <key> <bssid(optional)>\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "connect_aes" ) )
    {
        struct ether_addr peBSSID;
        if( argc == 5 )
        {
            if (!wl_ether_atoe(argv[4], &peBSSID)) 
            {
                fprintf(stderr,"could not parse \"%s\" as an ethernet MAC address\n", argv[4]);
                lErr = -1;
                goto BWL_EXIT;
            }

            lErr = BWL_ConnectWpaAes(   hBwl,
                                        eNetOpModeInfra,
                                        argv[2],  /* SSID */
                                        argv[3] , /* Key */
                                        &peBSSID);/* BSSID */
        } 
        else if( argc == 4 ) 
        {
            lErr = BWL_ConnectWpaAes(   hBwl,
                                        eNetOpModeInfra,
                                        argv[2], /* SSID */
                                        argv[3], /* Key */
                                        NULL);
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            printf( "%s %s <ssid> <key> <bssid(optional)>\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "connect_tkip2" ) )
    {
        struct ether_addr peBSSID;
        if( argc == 5 )
        {
            if (!wl_ether_atoe(argv[4], &peBSSID)) 
            {
                fprintf(stderr,"could not parse \"%s\" as an ethernet MAC address\n", argv[4]);
                lErr = -1;
                goto BWL_EXIT;
            }

            lErr = BWL_ConnectWpa2Tkip( hBwl,
                                        eNetOpModeInfra,
                                        argv[2], /* SSID */
                                        argv[3], /* Key */
                                        &peBSSID);
            BWL_CHECK_ERR( lErr );
        } else if( argc == 4 ) {
            lErr = BWL_ConnectWpa2Tkip( hBwl,
                                        eNetOpModeInfra,
                                        argv[2], /* SSID */
                                        argv[3], /* Key */
                                        NULL);
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            printf( "%s %s <ssid> <key> <bssid(optional)>\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "connect_aes2" ) )
    {
        struct ether_addr peBSSID;
        if( argc == 5 )
        {
            if (!wl_ether_atoe(argv[4], &peBSSID)) 
            {
                fprintf(stderr,"could not parse \"%s\" as an ethernet MAC address\n", argv[4]);
                lErr = -1;
                goto BWL_EXIT;
            }

            lErr = BWL_ConnectWpa2Aes(  hBwl,
                                        eNetOpModeInfra,
                                        argv[2], /* SSID */
                                        argv[3], /* Key */
                                        &peBSSID);
            BWL_CHECK_ERR( lErr );
        } else if( argc == 4 ) {
            lErr = BWL_ConnectWpa2Aes(  hBwl,
                                        eNetOpModeInfra,
                                        argv[2], /* SSID */
                                        argv[3], /* Key */
                                        NULL);
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            printf( "%s %s <ssid> <key> <bssid(optional)>\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "disassoc" ) )
    {
        lErr = BWL_DisconnectAp( hBwl );
        BWL_CHECK_ERR( lErr );
    }
    else if( !strcmp( argv[1], "scanresults" ) )
    {
        lErr = BWL_DisplayScanResults( hBwl);
        BWL_CHECK_ERR( lErr );
    }
    else if( !strcmp( argv[1], "sup_wpa" ) )
    {
        if( argc > 2 )
        {
            sscanf(argv[2], "%d", &ulVal);
            ulVal = (ulVal) ? WPA2_AUTH_PSK : 0;
            lErr = BWL_SetWpaSup( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetWpaSup( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %d\n", argv[1], ulVal );
        }
    }
    else if( !strcmp( argv[1], "channel" ) )
    {
        if( argc > 2 )
        {
            sscanf(argv[2], "%d", &ulVal);
            lErr = BWL_SetChannel( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetChannel( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %d\n", argv[1], ulVal );
        }
    }
    else if( !strcmp( argv[1], "country" ) )
    {
        if( argc > 2 )
        {
            lErr = BWL_SetCountry( hBwl, argv[2] );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetCountry( hBwl, acCountry );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %s\n", argv[1], acCountry );
        }
    }
    else if( !strcmp( argv[1], "wpa_auth" ) )
    {
        if( argc > 2 )
        {
            sscanf( argv[2], "%d", &ulVal );
            lErr = BWL_SetWpaAuth( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetWpaAuth( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %d\n", argv[1], ulVal );
        }
    }
    else if( !strcmp( argv[1], "auth" ) )
    {
        if( argc > 2 )
        {
            sscanf( argv[2], "%d", &ulVal );
            lErr = BWL_SetAuthType( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetAuthType( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %d\n", argv[1], ulVal );
        }
    }
    else if( !strcmp( argv[1], "channels_in_country" ) )
    {
        if( argc > 3 )
        {
            ulVal = (!strcmp( argv[3], "a" )) ? WLC_BAND_5G : WLC_BAND_2G;
        }
        else
        {
            ulVal = WLC_BAND_2G;
        }
        lErr = BWL_GetChannelsByCountry( hBwl, argv[2], ulVal, aulChannels, &ulChannels );
        BWL_CHECK_ERR( lErr );

        (ulVal == WLC_BAND_5G) ? printf( "5G band\n" ) : printf( "2G band\n" );
        for( ii = 0; ii < ulChannels; ii++ )
        {
            printf( "%d ", aulChannels[ ii ] );
        }
        printf( "\n" );
    }
    else if( !strcmp( argv[1], "infra" ) )
    {
        if( argc > 2 )
        {
            sscanf(argv[2], "%d", &ulVal);
            lErr = BWL_SetInfraMode( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetInfraMode( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %d\n", argv[1], ulVal );
        }
    }
    else if( !strcmp( argv[1], "wsec" ) )
    {
        if( argc > 2 )
        {
            sscanf(argv[2], "%d", &ulVal);
            lErr = BWL_SetWSec( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetWSec( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %d\n", argv[1], ulVal );
        }
    }
    else if( !strcmp( argv[1], "set_pmk" ) )
    {
        if( argc > 2 )
        {
            lErr = BWL_SetWSecKey( hBwl, argv[2] );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            BWL_CHECK_ERR( lErr = BWL_ERR_PARAM );
        }
    }
    else if( !strcmp( argv[1], "ssid" ) )
    {
        if( argc > 2 )
        {
           	lErr = BWL_SetSsid( hBwl, argv[2] , NULL);
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetSsid( hBwl, acSsid, &ulVal );
            wl_format_ssid( acSsid, (uint8*)acSsid, ulVal );
            printf( "ssid = %s\n", acSsid );
        }
    }
    else if( !strcmp( argv[1], "get_cached_ssid" ) )
    {
        lErr = BWL_GetCachedSsid( hBwl, acSsid, &ulVal );
        wl_format_ssid( acSsid, (uint8*)acSsid, (int)ulVal );
        printf( "cached ssid = %s\n", acSsid );
    }
    else if( !strcmp( argv[1], "addwep" ) )
    {
        if( argc > 3 )
        {
            sscanf( argv[2], "%d", &ulVal ); /* get the index */
            lErr = BWL_AddWepKey( hBwl, ulVal, argv[3],
                                  eCryptoAlgoAesCcm, 1 );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            printf( "%s %s <index> <key>\n", argv[0], argv[1] );
        }
    }
#ifdef INCLUDE_WPS	
    else if( !strcmp( argv[1], "wps" ) )
    {
        char key[129];
        uint32  ulPin  = BWL_INVALID_PIN; /* default to push button */

        if( argc == 5 )
        {
            sscanf( argv[4], "%d", &ulPin );
            lErr = BWL_WpsConnectByPin( hBwl, argv[2], argv[3], ulPin ,key, sizeof(key));
            BWL_CHECK_ERR( lErr );
        }
        else if( argc == 3 )
        {
            lErr = BWL_WpsConnectByPb( hBwl, argv[2] ,key , sizeof(key));

            BWL_CHECK_ERR( lErr );
        }
        else
        {
            printf( "%s %s [eth if] [ssid] [pin]\n", argv[0], argv[1] );
            printf( "%s %s eth1 \n", argv[0], argv[1] );
            printf( "%s %s eth1 BCMTUAN1 12345670\n", argv[0], argv[1] );
        }
    }
#endif
    else if( !strcmp( argv[1], "cred" ) )
    {
        Credential_t    Cred;

        if( argc == 2 )
        {
            printf( "calling BWL_GetCredential\n" );
            lErr = BWL_GetCredential( hBwl, &Cred );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            printf( "%s %s\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "event" ) )
    {
        if( argc == 3 )
        {
          pid_t pid;

            sscanf( argv[2], "%d", &ulVal );
            /* example: BWL_SetEvent(hBwl, WLC_E_DEAUTH_IND); */
            lErr = BWL_SetEvent( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );

            /* create a new process to execute handle the event */
            if( (pid = fork()) == 0 )
            {
                BWL_ProcessEvent( hBwl );
            }
        }
        else
        {
            printf( "%s %s <event number>\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "processevent" ) )
    {
        if( argc == 2 )
        {
            BWL_ProcessEvent( hBwl );
        }
        else
        {
            printf( "%s %s\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "is_link_up" ) )
    {
        if( argc == 2 )
        {
            lErr = BWL_GetLinkStatus( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %d\n", argv[1], ulVal );
        }
        else
        {
            printf( "%s %s\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "dpt_cred" ) )
    {
        DptCredential_t    Cred;

        if( argc == 2 )
        {
            printf( "calling BWL_GetDptCredential\n" );
            lErr = BWL_GetDptCredential( hBwl, &Cred );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            printf( "%s %s\n", argv[0], argv[1] );
        }
    }
    else if( !strcmp( argv[1], "rpc_agg" ) )
    {
        if( argc > 2 )
        {
            sscanf(argv[2], "%x", &ulVal);
            lErr = BWL_SetRpcAgg( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetRpcAgg( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %x\n", argv[1], ulVal );
        }
    }
    else if( !strcmp( argv[1], "ht_wsec_restrict" ) )
    {
        if( argc > 2 )
        {
            sscanf(argv[2], "%d", &ulVal);
            lErr = BWL_SetHtRestrict( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetHtRestrict( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %d\n", argv[1], ulVal );
        }
    }
    else if( !strcmp( argv[1], "dpt" ) )
    {
        if( argc > 2 )
        {
            sscanf(argv[2], "%d", &ulVal);
            lErr = BWL_SetDptMode( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetDptMode( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %d\n", argv[1], ulVal );
        }
    }
    else if( !strcmp( argv[1], "siso_tx" ) )
    {
        if( argc > 2 )
        {
            sscanf(argv[2], "%d", &ulVal);
            lErr = BWL_SetSisoTx( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr = BWL_GetSisoTx( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "%s == %d\n", argv[1], ulVal );
        }
    }
    else if( !strcmp( argv[1], "dptlist" ) )
    {
        DptList_t data;
        BWL_GetDptList(hBwl, &data);
    }
    else if( !strcmp( argv[1], "sta_retry_time" ) )
    {
        if( argc > 2 )
        {
            sscanf(argv[2], "%d", &ulVal);
            lErr = BWL_SetStaRetryTime( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
    }
    else if( !strcmp( argv[1], "ap_bw_cap" ) )
    {
        lErr = BWL_GetApBwCap( hBwl, &ulVal );
        BWL_CHECK_ERR( lErr );
        printf( "%s == %d\n", argv[1], ulVal );
    }
    else if( !strcmp( argv[1], "mimo_bw_cap" ) )
    {
        if( argc > 2 )
        {
            sscanf( argv[2], "%d", &ulVal);
            printf( "set %s = %d\n", argv[1], ulVal );
            lErr =  BWL_SetMimoBwCap( hBwl, ulVal );
            BWL_CHECK_ERR( lErr );
        }
        else
        {
            lErr =  BWL_GetMimoBwCap( hBwl, &ulVal );
            BWL_CHECK_ERR( lErr );
            printf( "get %s = %d\n", argv[1], ulVal );
        }
    }

BWL_EXIT:
    lErr = BWL_Uninit( hBwl );
    BWL_CHECK_ERR( lErr );

    if( pData )
        free( pData );

    return( lErr );
}


int BWL_ProcessEvent(BWL_Handle hBwl)
{
    int                 fd, err;
    struct sockaddr_ll  sll;
    bcm_event_t         *event;
    char                data[512];
    int                 event_type;
    struct ether_addr   *addr;
    struct ifreq        *pifr = (struct ifreq*) hBwl->wl;
    char                *pcName;


    /* the network interface must be avaliable at this point */
    /* if not do ifconfig eth1 up */

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_BRCM));
    if (fd < 0) {
        printf("Cannot create socket %d\n", fd);
        return -1;
    }

//    err = ioctl(fd, SIOCGIFINDEX, &ifr);
    err = ioctl(fd, SIOCGIFINDEX, pifr);
    if (err < 0) {
        printf("Cannot get index %d\n", err);
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETHER_TYPE_BRCM);
//    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_ifindex = pifr->ifr_ifindex;
    err = bind(fd, (struct sockaddr *)&sll, sizeof(sll));
    if (err < 0) {
        printf("Cannot get index %d\n", err);
        return -1;
    }

    while (1)
    {
        recv(fd, data, sizeof(data), 0);
        event = (bcm_event_t *)data;
        addr = (struct ether_addr *)&(event->event.addr);

        event_type = ntoh32(event->event.event_type);

        pcName = BWL_LookUpEvent(hBwl, event_type);
        if( pcName )
        {
            printf("%s\n", pcName );
        }
        else
        {
            printf("Unknow event\n" );
        }
    }

    return (0);
}

char* BWL_LookUpEvent(BWL_Handle hBwl, uint32 ulEvent)
{
    uint32  ii=0;

    do
    {
        if( g_Events[ii].ulEvent == ulEvent )
        {
            return( g_Events[ii].aEventName );
        }
        ii++;
    } while( g_Events[ii].ulEvent != WLC_E_LAST );

    return( NULL );
}
