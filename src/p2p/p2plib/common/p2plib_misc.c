/*
 * P2P Library API - Initialization/Miscellaneous functions (OS-independent)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_misc.c,v 1.309 2011-01-11 19:54:57 $
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/* P2P Library include files */
#include <BcmP2PAPI.h>
#include <p2plib_api.h>
#include <p2plib_int.h>
#include <p2pwl.h>

/* WL driver include files */
#include <bcmendian.h>
#include <wlioctl.h>
#include <bcmutils.h>
#include <bcmcrypto/passhash.h>
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
#include <bcmwifi_channels.h>
#endif

/* DHCP Server Library include files */
#if P2PAPI_ENABLE_DHCPD
#include <dhcp.h>
#endif /* P2PAPI_ENABLE_DHCPD */

#if !P2PAPI_USE_IDAUTH || !P2PAPI_USE_IDAUTH
#include <hslif.h>
#endif


#define WLAN_JOIN_ATTEMPTS	3
#define WLAN_POLLING_JOIN_COMPLETE_ATTEMPTS	20

#define P2P_MAX_TIMERS 32

/*
 * P2P Library global variables
 */
static struct ether_addr p2papi_null_eth_addr = { { 0, 0, 0, 0, 0, 0 } };


p2papi_notif_config_t p2papi_notifs = {
	(BCMP2P_NOTIFICATION_TYPE)0, (BCMP2P_NOTIFICATION_CALLBACK)NULL,
	(void *)NULL
};

/* Debug global variables */
#if P2PLOGGING
p2papi_instance_t *p2pdbg_hdl = NULL;
#endif /* P2PLOGGING */

#if (P2PAPI_ENABLE_DHCPD || P2PAPI_ENABLE_WPS)
/* WPS and DHCP debug logs will be redirected to this function */
static void
output_wps_log(int is_err, char *traceMsg)
{
	p2papi_log(BCMP2P_LOG_MED, TRUE, traceMsg);

}
#endif /* P2PAPI_ENABLE_DHCPD || P2PAPI_ENABLE_WPS */



/* Generate 64 hex digit pmk string by passphrase and ssid */
void
passphrase_to_pmk(char *passphrase, int passphrase_length,
	unsigned char *ssid, int ssid_length, char *pmk)
{
	passhash_t	passhash;
	int		i;

#if P2PAPI_ENABLE_DEBUG_SHOWKEY
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "passphrase_to_pmk: pp=%s\n", passphrase));
#else
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "passphrase_to_pmk\n"));
#endif /* P2PAPI_ENABLE_DEBUG_SHOWKEY */

	memset(pmk, 0, WSEC_MAX_PSK_LEN + 1);

	/* Create 64-hex-digit PMK from passphrase */
	if (0 != init_passhash(&passhash,
		passphrase, passphrase_length, ssid, ssid_length)) {
		/* No conversion, just copy */
		strncpy(pmk, passphrase, WSEC_MAX_PSK_LEN);
		return;
	}

	while (do_passhash(&passhash, 256) > 0)
		;

	/* Conert 256-bit  passhash to string */
	for (i = 0; i < 32; i++) {
		unsigned char lsd, msd;
		lsd = passhash.output[i]%16;
		msd = passhash.output[i]/16;
		pmk[i*2] = msd < 10 ? msd + '0' : msd - 10 + 'A';
		pmk[i*2+1] = lsd < 10 ? lsd + '0' : lsd - 10 + 'A';
	}
}

/* Character set for a P2P GO's SSID or WPA2-PSK passphrase.
 * See section 3.2.1 of the WFA P2P spec 1.01.
 */
char p2papi_random_char(void)
{
static char P2P_CHARSET[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
#define P2P_CHARSET_SIZE 	(sizeof(P2P_CHARSET) - 1)
#define GEN_RAND_P2P_CHAR	 P2P_CHARSET[p2papi_osl_random() % P2P_CHARSET_SIZE]

	return GEN_RAND_P2P_CHAR;
}

/* Generate a GO SSID compliant with P2P spec 1.01 section 3.2.1 */
void
p2papi_generate_go_ssid(p2papi_instance_t *hdl,
	brcm_wpscli_nw_settings *credential)
{
	strncpy(credential->ssid, "DIRECT-", sizeof(credential->ssid));
	credential->ssid[7] = p2papi_random_char();
	credential->ssid[8] = p2papi_random_char();
	credential->ssid[9] = '\0';

	/* Append the friendly name to the generated SSID */
	strncpy(&credential->ssid[9], (char*)hdl->fname_ssid,
		sizeof(credential->ssid) - 9);
	credential->ssid[sizeof(credential->ssid) - 1] = '\0';

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_generate_go_ssid: fname=%s ssid=%s\n",
		hdl->fname_ssid, credential->ssid));
}

static void
get_random_credential(p2papi_instance_t* hdl,
	brcm_wpscli_nw_settings *credential)
{
	/* ssid */
	unsigned short ssid_length, key_length;
	unsigned char random_ssid[33] = {0};
	unsigned char random_key[65] = {0};
	struct ether_addr mac_addr = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}};
	unsigned char *mac = mac_addr.octet;
	unsigned char macString[18];
	int i;

	p2pwlu_get_mac_addr(hdl, &mac_addr);
	sprintf((char*)macString, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	p2papi_osl_rand_bytes((unsigned char *)&ssid_length, sizeof(ssid_length));
	ssid_length = ((((long)ssid_length + 56791)*13579)%23) + 1;

	p2papi_osl_rand_bytes((unsigned char *)random_ssid, ssid_length);

	for (i = 0; i < ssid_length; i++) {
		if ((random_ssid[i] < 48) || (random_ssid[i] > 126))
			random_ssid[i] = random_ssid[i]%79 + 48;
	}

	random_ssid[ssid_length++] = macString[6];
	random_ssid[ssid_length++] = macString[7];
	random_ssid[ssid_length++] = macString[9];
	random_ssid[ssid_length++] = macString[10];
	random_ssid[ssid_length++] = macString[12];
	random_ssid[ssid_length++] = macString[13];
	random_ssid[ssid_length++] = macString[15];
	random_ssid[ssid_length++] = macString[16];
	strcpy(credential->ssid, (char *)random_ssid);

	/* keyMgmt */
	credential->authType = BRCM_WPS_AUTHTYPE_WPA2PSK;

	/* network key */
	p2papi_osl_rand_bytes((unsigned char *)&key_length, sizeof(key_length));
	key_length = ((((long)key_length + 56791)*13579)%8) + 8;
	i = 0;
	while (i < key_length) {
		p2papi_osl_rand_bytes(&random_key[i], 1);
		if ((islower(random_key[i]) || isdigit(random_key[i])) && (random_key[i] < 0x7f)) {
			i++;
		}
	}
	/* Store passphrase in p2papi_instance */
	memset(hdl->passphrase, 0, sizeof(hdl->passphrase));
	strncpy(hdl->passphrase, (char *)random_key, sizeof(random_key));

	/* Create 64-hex-digit PMK from passphrase and store it in nwKey */
	passphrase_to_pmk((char *)random_key, key_length,
		random_ssid, ssid_length, credential->nwKey);

	/* Crypto */
	credential->encrType = BRCM_WPS_ENCRTYPE_AES;
}

/* Generate random WPS credentials */
void
p2papi_wps_gen_rnd_cred(p2papi_instance_t* hdl,
	brcm_wpscli_nw_settings *outCredential)
{
	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);

	memset((char *)(outCredential), 0, sizeof(*outCredential));
	get_random_credential(hdl, outCredential);

	p2papi_generate_go_ssid(hdl, outCredential);
}


/* Initialize the API */
BCMP2P_STATUS
p2papi_init(uint32 version, void* reserved)
{
	(void) reserved;

	P2PLOG2("p2papi_init: version=%u, app expects %u\n",
		BRCMP2P_VERSION, version);
	if (version != BRCMP2P_VERSION) {
		P2PERR2("P2P Library version=%u but app expects %u\n",
			BRCMP2P_VERSION, version);
		return BCMP2P_VERSION_MISMATCH;
	}

	/* Initialize the OS-specific layer */
	if (!p2papi_osl_init()) {
		P2PLOG("p2papi_init: osl init failed!\n");
		return BCMP2P_CANT_TALK_TO_DRIVER;
	}

	return BCMP2P_SUCCESS;
}

/* Uninitialize the API */
BCMP2P_STATUS
p2papi_uninit(void)
{
	P2PLOG("p2papi_uninit\n");
	p2papi_osl_deinit();

/*	DHCPReset(); */

	return BCMP2P_SUCCESS;
}

/* Register for notifications of P2P Library events */
BCMP2P_STATUS
p2papi_register_notifications(int notificationType,
	BCMP2P_NOTIFICATION_CALLBACK funcCallback, void *pCallbackContext,
	void *pReserved)
{
	(void) pReserved;
	P2PLOG("p2papi_reg_notifs\n");

	if (p2papi_notifs.callback != NULL) {
		P2PLOG2("BCMP2PRegNotif: overwriting existing (old=0x%x new=0x%x)\n",
			p2papi_notifs.type, notificationType);
	}
	p2papi_notifs.type = (BCMP2P_NOTIFICATION_TYPE) notificationType;
	p2papi_notifs.callback = funcCallback;
	p2papi_notifs.cbContext = pCallbackContext;

	return BCMP2P_SUCCESS;
}

/* Unregister for event notifications */
BCMP2P_STATUS
p2papi_unregister_notifications(void)
{
	P2PLOG("p2papi_unreg_notifs\n");
	p2papi_notifs.type = (BCMP2P_NOTIFICATION_TYPE) 0;
	p2papi_notifs.callback = NULL;
	p2papi_notifs.cbContext = NULL;
	return BCMP2P_SUCCESS;
}

#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
typedef enum {
	VHTBW_NONE = 0,
	VHTBW_80 = 1,
	VHTBW_160 = 2,
	VHTBW_8080 = 3
} vhtbw_t;

typedef struct {
	BCMP2P_CHANNEL_CLASS channel_class;	/* global operating class */
	bool is_40mhz;						/* 40Mhz channel spacing */
	bool is_lower;						/* primary channel lower */
	vhtbw_t vhtbw;
	BCMP2P_UINT32 min_channel;			/* min channel */
	BCMP2P_UINT32 max_channel;			/* max channel */
} p2papi_channel_class_t;
static p2papi_channel_class_t channel_table[P2P_CHANLIST_SE_MAX_ENTRIES] = {
	{IEEE_2GHZ_20MHZ_CLASS_12,     false, false, VHTBW_NONE,   1, CH_MAX_2G_CHANNEL},
	{IEEE_5GHZ_20MHZ_CLASS_1,      false, false, VHTBW_NONE,  36,  48},
	{IEEE_5GHZ_20MHZ_CLASS_2_DFS,  false, false, VHTBW_NONE,  52,  64},
	{IEEE_5GHZ_20MHZ_CLASS_3,      false, false, VHTBW_NONE, 149, 161},
	{IEEE_5GHZ_20MHZ_CLASS_4_DFS,  false, false, VHTBW_NONE, 100, 144},
	{IEEE_5GHZ_20MHZ_CLASS_5,      false, false, VHTBW_NONE, 165, 165},
	{IEEE_5GHZ_40MHZ_CLASS_22,     true,   true, VHTBW_NONE,  36,  44},
	{IEEE_5GHZ_40MHZ_CLASS_23_DFS, true,   true, VHTBW_NONE,  52,  60},
	{IEEE_5GHZ_40MHZ_CLASS_24_DFS, true,   true, VHTBW_NONE, 100, 140},
	{IEEE_5GHZ_40MHZ_CLASS_25,     true,   true, VHTBW_NONE, 149, 157},
	{IEEE_5GHZ_40MHZ_CLASS_27,     true,  false, VHTBW_NONE,  40,  48},
	{IEEE_5GHZ_40MHZ_CLASS_28_DFS, true,  false, VHTBW_NONE,  56,  64},
	{IEEE_5GHZ_40MHZ_CLASS_29_DFS, true,  false, VHTBW_NONE, 104, 144},
	{IEEE_5GHZ_40MHZ_CLASS_30,     true,  false, VHTBW_NONE, 153, 161},
	{IEEE_2GHZ_40MHZ_CLASS_32,     true,   true, VHTBW_NONE,   1,   7},
	{IEEE_2GHZ_40MHZ_CLASS_33,     true,  false, VHTBW_NONE,   5,  11},
	{IEEE_5GHZ_80MHZ_CLASS_128,   false,  false, VHTBW_80,    42, 155},
	{IEEE_5GHZ_160MHZ_CLASS_129,  false,  false, VHTBW_160,   50, 114},
	{IEEE_5GHZ_8080MHZ_CLASS_130, false,  false, VHTBW_8080,  42, 155}
};
#else
/* 802.11 Annex E */
typedef struct {
	BCMP2P_CHANNEL_CLASS channel_class;	/* global operating class */
	bool is_40mhz;						/* 40Mhz channel spacing */
	bool is_lower;						/* primary channel lower */
	BCMP2P_UINT32 min_channel;			/* min channel */
	BCMP2P_UINT32 max_channel;			/* max channel */
} p2papi_channel_class_t;
static p2papi_channel_class_t channel_table[P2P_CHANLIST_SE_MAX_ENTRIES] = {
	{IEEE_2GHZ_20MHZ_CLASS_12,     false, false,   1, CH_MAX_2G_CHANNEL},
	{IEEE_5GHZ_20MHZ_CLASS_1,      false, false,  36,  48},
	{IEEE_5GHZ_20MHZ_CLASS_2_DFS,  false, false,  52,  64},
	{IEEE_5GHZ_20MHZ_CLASS_3,      false, false, 149, 161},
	{IEEE_5GHZ_20MHZ_CLASS_4_DFS,  false, false, 100, 140},
	{IEEE_5GHZ_20MHZ_CLASS_5,      false, false, 165, 165},
	{IEEE_5GHZ_40MHZ_CLASS_22,     true,   true,  36,  44},
	{IEEE_5GHZ_40MHZ_CLASS_23_DFS, true,   true,  52,  60},
	{IEEE_5GHZ_40MHZ_CLASS_24_DFS, true,   true, 100, 132},
	{IEEE_5GHZ_40MHZ_CLASS_25,     true,   true, 149, 157},
	{IEEE_5GHZ_40MHZ_CLASS_27,     true,  false,  40,  48},
	{IEEE_5GHZ_40MHZ_CLASS_28_DFS, true,  false,  56,  64},
	{IEEE_5GHZ_40MHZ_CLASS_29_DFS, true,  false, 104, 136},
	{IEEE_5GHZ_40MHZ_CLASS_30,     true,  false, 153, 161},
	{IEEE_2GHZ_40MHZ_CLASS_32,     true,   true,   1,   7},
	{IEEE_2GHZ_40MHZ_CLASS_33,     true,  false,   5,  11}
};
#endif /* ! defined (D11AC_IOTYPES) && defined (BCM_P2P_ACRATES) */

/* given a chanspec and a string buffer, format the chanspec as a
 * string, and return the original pointer a.
 * Min buffer length must be CHANSPEC_STR_LEN.
 * On error return NULL
 */
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)

typedef struct ch2center {
	uint8 min_ch;
	uint8 center_ch;
	uint8 max_ch;
} ch2center_t;

/* 80MHz channels in 5GHz band */
static const ch2center_t wf_5g_80m_chmap[] =
{{36, 42, 48}, {52, 58, 64}, {100, 106, 112}, {116, 122, 128}, {132, 138, 144},
{149, 155, 161}};
#define WF_NUM_5G_80M_CHMAP \
	(sizeof(wf_5g_80m_chmap)/sizeof(ch2center_t))

/* 160MHz channels in 5GHz band */
static const ch2center_t wf_5g_160m_chmap[] =
{{36, 50, 64}, {100, 114, 128}};
#define WF_NUM_5G_160M_CHMAP \
		(sizeof(wf_5g_160m_chmap)/sizeof(ch2center_t))
#endif /* defined (D11AC_IOTYPES) && defined (BCM_P2P_ACRATES) */


#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
/* bw in MHz, return the channel count from the center channel to the
 * the channel at the edge of the band
 */
static uint8
p2papi_center_chan_to_edge(uint bw)
{
	/* edge channels separated by BW - 10MHz on each side
	 * delta from cf to edge is half of that,
	 * MHz to channel num conversion is 5MHz/channel
	 */
	return (uint8)(((bw - 20) / 2) / 5);
}

/* return channel number of the low edge of the band
 * given the center channel and BW
 */
static uint8
p2papi_channel_low_edge(uint center_ch, uint bw)
{
	return (uint8)(center_ch - p2papi_center_chan_to_edge(bw));
}

/* return side band number given center channel and control channel
 * return -1 on error
 */
static int
p2papi_channel_to_sb(uint center_ch, uint ctl_ch, uint bw)
{
	uint lowest = p2papi_channel_low_edge(center_ch, bw);
	uint sb;

	if ((ctl_ch - lowest) % 4) {
		/* bad ctl channel, not mult 4 */
		return -1;
	}

	sb = ((ctl_ch - lowest) / 4);

	/* sb must be a index to a 20MHz channel in range */
	if (sb >= (bw / 20)) {
		/* ctl_ch must have been too high for the center_ch */
		return -1;
	}

	return sb;
}
char *
p2papi_chspec_ntoa(chanspec_t chspec, char *buf)
{
	return	wf_chspec_ntoa(chspec, buf);
}

chanspec_t
p2papi_chspec_aton(char *a)
{
	return wf_chspec_aton(a);
}

static uint
p2papi_channel_to_center_ch(uint ch, vhtbw_t vhtbw)
{
	ch2center_t const *ch2center_map;
	int		num_ch, i;

	if (vhtbw == VHTBW_80 || vhtbw == VHTBW_8080)
	{
		ch2center_map = wf_5g_80m_chmap;
		num_ch = WF_NUM_5G_80M_CHMAP;
	} else if (vhtbw == VHTBW_160) {
		ch2center_map = wf_5g_160m_chmap;
		num_ch = WF_NUM_5G_160M_CHMAP;
	} else {
		return -1;
	}

	for (i = 0; i < num_ch; i++) {
		if (ch >= ch2center_map[i].min_ch && ch <= ch2center_map[i].max_ch) {
			return ch2center_map[i].center_ch;
		}
	}

	return -1;
}

static BCMP2P_BOOL
p2papi_is_valid_vht_channel(p2papi_channel_class_t *table, uint channel)
{
	if (p2papi_channel_to_center_ch(channel, table->vhtbw) == -1)
		return false;
	return true;
}
#else
char *
p2papi_chspec_ntoa(chanspec_t chspec, char *buf)
{
	const char *band, *bw, *sb;
	uint channel;

	band = "";
	bw = "";
	sb = "";
	channel = CHSPEC_CHANNEL(chspec);
	/* check for non-default band spec */
	if ((CHSPEC_IS2G(chspec) && channel > CH_MAX_2G_CHANNEL) ||
	    (CHSPEC_IS5G(chspec) && channel <= CH_MAX_2G_CHANNEL))
		band = (CHSPEC_IS2G(chspec)) ? "b" : "a";
	if (CHSPEC_IS40(chspec)) {
		if (CHSPEC_SB_UPPER(chspec)) {
			sb = "u";
			channel += CH_10MHZ_APART;
		} else {
			sb = "l";
			channel -= CH_10MHZ_APART;
		}
	} else if (CHSPEC_IS10(chspec)) {
		bw = "n";
	}

	/* Outputs a max of 6 chars including '\0'  */
	snprintf(buf, 6, "%d%s%s%s", channel, band, bw, sb);
	return (buf);
}

/* given a chanspec string, convert to a chanspec.
 * On error return 0
 */
chanspec_t
p2papi_chspec_aton(char *a)
{
	char *endp = NULL;
	uint channel, band, bw, ctl_sb;
	char c;

	channel = strtoul(a, &endp, 10);

	/* check for no digits parsed */
	if (endp == a)
		return 0;

	if (channel > MAXCHANNEL)
		return 0;

	band = ((channel <= CH_MAX_2G_CHANNEL) ? WL_CHANSPEC_BAND_2G : WL_CHANSPEC_BAND_5G);
	bw = WL_CHANSPEC_BW_20;
#ifdef WL_CHANSPEC_CTL_SB_NONE
	ctl_sb = WL_CHANSPEC_CTL_SB_NONE;
#else
	ctl_sb = 0;
#endif

	a = endp;

	c = tolower(a[0]);
	if (c == '\0')
		goto done;

	/* parse the optional ['A' | 'B'] band spec */
	if (c == 'a' || c == 'b') {
		band = (c == 'a') ? WL_CHANSPEC_BAND_5G : WL_CHANSPEC_BAND_2G;
		a++;
		c = tolower(a[0]);
		if (c == '\0')
			goto done;
	}

	/* parse bandwidth 'N' (10MHz) or 40MHz ctl sideband ['L' | 'U'] */
	if (c == 'n') {
		bw = WL_CHANSPEC_BW_10;
	} else if (c == 'l') {
		bw = WL_CHANSPEC_BW_40;
		ctl_sb = WL_CHANSPEC_CTL_SB_LOWER;
		/* adjust channel to center of 40MHz band */
		if (channel <= (MAXCHANNEL - CH_20MHZ_APART))
			channel += CH_10MHZ_APART;
		else
			return 0;
	} else if (c == 'u') {
		bw = WL_CHANSPEC_BW_40;
		ctl_sb = WL_CHANSPEC_CTL_SB_UPPER;
		/* adjust channel to center of 40MHz band */
		if (channel > CH_20MHZ_APART)
			channel -= CH_10MHZ_APART;
		else
			return 0;
	} else {
		return 0;
	}

done:
	return (channel | band | bw | ctl_sb);
}
#endif /* else - defined (D11AC_IOTYPES) &&  defined (BCM_P2P_ACRATES) */

/* validate channel as per 802.11 Annex E */
BCMP2P_BOOL
p2papi_is_valid_channel(BCMP2P_CHANNEL *channel)
{
	bool is_found = false;
	int i;

	if (channel == 0)
		return BCMP2P_FALSE;

	for (i = 0; i < P2P_CHANLIST_SE_MAX_ENTRIES; i++) {
		p2papi_channel_class_t *table = &channel_table[i];
		if (table->channel_class == channel->channel_class) {
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
			if (table->vhtbw) {
				is_found = p2papi_is_valid_vht_channel(table, channel->channel);
				if (is_found == true)
					break;
			}
			else
#endif
			if (channel->channel >= table->min_channel &&
				channel->channel <= table->max_channel) {
				is_found = true;
				break;
			}
		}
	}

	if (!is_found) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_is_valid_channel: not valid class=%d, channel=%d\n",
			channel->channel_class, channel->channel));
		return BCMP2P_FALSE;
	}

	return BCMP2P_TRUE;
}

/* convert from chspec to channel as per 802.11 Annex E */
BCMP2P_BOOL
p2papi_chspec_to_channel(chanspec_t chspec,	BCMP2P_CHANNEL *channel)
{
	bool is_found = false;
	uint8 ch = CHSPEC_CHANNEL(chspec);
	bool is_40mhz = false;
	bool is_lower = false;
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
	vhtbw_t vhtbw = VHTBW_NONE;
#endif
	BCMP2P_CHANNEL_CLASS chclass = BCMP2P_LISTEN_CHANNEL_CLASS;
	int i;

	if (channel == 0)
		return BCMP2P_FALSE;

	/* initialize for a failure case */
	channel->channel_class = chclass;
	channel->channel = ch;

	if (CHSPEC_IS40(chspec)) {
		is_40mhz = true;
		if (CHSPEC_SB_UPPER(chspec)) {
			ch += CH_10MHZ_APART;
		} else {
			ch -= CH_10MHZ_APART;
			is_lower = true;
		}
	}
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
	else if (CHSPEC_IS80(chspec)) {
		vhtbw = VHTBW_80;
		ch = wf_chspec_ctlchan(chspec);
	}
#endif
	else if (!CHSPEC_IS20(chspec)) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_chspec_to_channel: unsupported chspec 0x%x\n", chspec));
		return BCMP2P_FALSE;
	}

	for (i = 0; i < P2P_CHANLIST_SE_MAX_ENTRIES; i++) {
		p2papi_channel_class_t *table = &channel_table[i];
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
		if (vhtbw) {
			if (vhtbw == table->vhtbw) {
				chclass = table->channel_class;
				is_found = p2papi_is_valid_vht_channel(table, ch);
				if (is_found)
					break;
			}
			continue;
		} else
#endif
		if (is_40mhz == table->is_40mhz &&
			is_lower == table->is_lower &&
			(ch >= table->min_channel &&
			ch <= table->max_channel)) {
			is_found = true;
			chclass = table->channel_class;
			break;
		}
	}

	if (!is_found) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_chspec_to_channel: not found 0x%x\n", chspec));
		return BCMP2P_FALSE;
	}

	channel->channel_class = chclass;
	channel->channel = ch;
	return BCMP2P_TRUE;
}

/* convert from channel to chspec as per 802.11 Annex E */
BCMP2P_BOOL
p2papi_channel_to_chspec(BCMP2P_CHANNEL *channel, chanspec_t *chspec)
{
	bool is_found = false;
	uint ch;
	uint band;
	uint bw;
	uint ctl_sb;
	int i;

	if (channel == 0 || chspec == 0)
		return BCMP2P_FALSE;

	ch = channel->channel;
	band = ((ch <= CH_MAX_2G_CHANNEL) ? WL_CHANSPEC_BAND_2G : WL_CHANSPEC_BAND_5G);
	bw = WL_CHANSPEC_BW_20;
#ifdef WL_CHANSPEC_CTL_SB_NONE
	ctl_sb = WL_CHANSPEC_CTL_SB_NONE;
#else
	ctl_sb = 0;
#endif

	for (i = 0; i < P2P_CHANLIST_SE_MAX_ENTRIES; i++) {
		p2papi_channel_class_t *table = &channel_table[i];
		if (channel->channel_class == table->channel_class) {
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
		if (table->vhtbw == VHTBW_80) {
			uint center_ch;
			bw = WL_CHANSPEC_BW_80;
			center_ch = p2papi_channel_to_center_ch(ch, VHTBW_80);
			if (center_ch == -1)
				return BCMP2P_FALSE;
			ctl_sb = p2papi_channel_to_sb(center_ch, ch, 80);
			if (ctl_sb == -1)
				return BCMP2P_FALSE;
			ch = center_ch;
			ctl_sb = ctl_sb << WL_CHANSPEC_CTL_SB_SHIFT;

		} else
#endif
			if (table->is_40mhz) {
				bw = WL_CHANSPEC_BW_40;
				if (table->is_lower) {
					ctl_sb = WL_CHANSPEC_CTL_SB_LOWER;
					ch += CH_10MHZ_APART;
				}
				else {
					ctl_sb = WL_CHANSPEC_CTL_SB_UPPER;
					ch -= CH_10MHZ_APART;
				}
			}
			is_found = true;
			break;
		}
	}

	if (!is_found) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_channel_to_chspec: not found class=%d, channel=%d\n",
			channel->channel_class, channel->channel));
		return BCMP2P_FALSE;
	}

	*chspec = ch | band | bw | ctl_sb;
	return BCMP2P_TRUE;
}

#ifdef BCM_P2P_OPTEXT
/* get heightest capable chanspec for a given channel */
BCMP2P_BOOL p2papi_channel_to_high_chspec(p2papi_instance_t *hdl, BCMP2P_CHANNEL *op_channel,
	chanspec_t *chspec)
{
	p2p_chanlist_t *chlist;
	BCMP2P_CHANNEL high_channel;
	int i, k;

	chlist = p2papi_get_non_dfs_channel_list(hdl);
	high_channel.channel = op_channel->channel;
	high_channel.channel_class = op_channel->channel_class;

#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
	if (high_channel.channel_class == IEEE_5GHZ_80MHZ_CLASS_128)
		goto end;

	/* check for 80Mhz capable chanspecs */
	for (i = 0; i < chlist->num_entries; i++) {
		p2p_chanlist_entry_t *entry = &chlist->entries[i];
		if (entry->band == IEEE_5GHZ_80MHZ_CLASS_128) {
			for (k = 0; k < entry->num_channels; k++) {
				if (entry->channels[k] == op_channel->channel) {
					/* update the channel class */
					high_channel.channel_class = entry->band;
					goto end;
				}
			}
		}
	}
#endif

	/* check  for 40Mhz channels */
	if (high_channel.channel_class == IEEE_5GHZ_40MHZ_CLASS_22 ||
		high_channel.channel_class == IEEE_5GHZ_40MHZ_CLASS_23_DFS ||
		high_channel.channel_class == IEEE_5GHZ_40MHZ_CLASS_24_DFS ||
		high_channel.channel_class == IEEE_5GHZ_40MHZ_CLASS_25 ||
		high_channel.channel_class == IEEE_5GHZ_40MHZ_CLASS_27 ||
		high_channel.channel_class == IEEE_5GHZ_40MHZ_CLASS_28_DFS ||
		high_channel.channel_class == IEEE_5GHZ_40MHZ_CLASS_29_DFS ||
		high_channel.channel_class == IEEE_5GHZ_40MHZ_CLASS_30)
		goto end;

	for (i = 0; i < chlist->num_entries; i++) {
		p2p_chanlist_entry_t *entry = &chlist->entries[i];
		if (entry->band == IEEE_5GHZ_40MHZ_CLASS_22 ||
			entry->band == IEEE_5GHZ_40MHZ_CLASS_23_DFS ||
			entry->band == IEEE_5GHZ_40MHZ_CLASS_24_DFS ||
			entry->band == IEEE_5GHZ_40MHZ_CLASS_25||
			entry->band == IEEE_5GHZ_40MHZ_CLASS_27 ||
			entry->band == IEEE_5GHZ_40MHZ_CLASS_28_DFS ||
			entry->band == IEEE_5GHZ_40MHZ_CLASS_29_DFS ||
			entry->band == IEEE_5GHZ_40MHZ_CLASS_30) {

			for (k = 0; k < entry->num_channels; k++) {
				if (entry->channels[k] == op_channel->channel) {
					high_channel.channel_class = entry->band;
					goto end;
				}
			}
		}
	}

end:

	return p2papi_channel_to_chspec(&high_channel, chspec);
}
#endif

/* Find channel class for a given channel and 40Mhz capable */
BCMP2P_BOOL
p2papi_find_channel_class(BCMP2P_UINT32 channel, bool is_40mhz,
	BCMP2P_CHANNEL_CLASS *channel_class)
{
	bool is_found = false;
	BCMP2P_CHANNEL_CLASS chclass = BCMP2P_LISTEN_CHANNEL_CLASS;
	int i;

	if (channel_class == 0)
		return BCMP2P_FALSE;

	for (i = 0; !is_found && i < P2P_CHANLIST_SE_MAX_ENTRIES; i++) {
		p2papi_channel_class_t *table = &channel_table[i];
		if (is_40mhz == table->is_40mhz &&
			(channel >= table->min_channel &&
			channel <= table->max_channel)) {
			if (is_40mhz && channel > CH_MAX_2G_CHANNEL) {
				BCMP2P_UINT32 ch;
				/* channel may be lower or upper so need to
				 * check for a multiple of the channel range
				 */
				for (ch = table->min_channel;
					!is_found && ch <= table->max_channel;
					ch += CH_20MHZ_APART * 2) {
					if (ch == channel) {
						is_found = true;
						chclass = table->channel_class;
					}
				}
			}
			else {
				/* 2Ghz sufficient to match channel range */
				is_found = true;
				chclass = table->channel_class;
			}
		}
	}

	if (!is_found) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_find_channel_class: not found channel=%d is_40mhz=%d\n",
			channel, is_40mhz));
		return BCMP2P_FALSE;
	}

	*channel_class = chclass;
	return BCMP2P_TRUE;
}

/* convert channels from array to list */
BCMP2P_BOOL p2papi_channel_array_to_list(
	int num_channels, BCMP2P_CHANNEL *channels, p2p_chanlist_t *channel_list)
{
	int i, j;

	memset(channel_list, 0, sizeof(*channel_list));

	for (i = 0; i < P2P_CHANLIST_SE_MAX_ENTRIES; i++) {
		p2papi_channel_class_t *table = &channel_table[i];
		p2p_chanlist_entry_t *entry =
			&channel_list->entries[channel_list->num_entries];
		entry->band = table->channel_class;
		/* find channels in channel class */
		for (j = 0; j < num_channels; j++) {
			BCMP2P_CHANNEL *ch = &channels[j];
			if (ch->channel_class == entry->band) {
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
				if (table->vhtbw) {
					if (p2papi_is_valid_vht_channel(table, ch->channel)) {
						/* add channel to channel list */
						entry->channels[entry->num_channels++]
							= ch->channel;
					}
				}
				else
#endif
				if (ch->channel >= (uint32)table->min_channel &&
					ch->channel <= (uint32)table->max_channel) {
					/* add channel to channel list */
					entry->channels[entry->num_channels++] = ch->channel;
				}
			}
		}
		if (entry->num_channels) {
			/* channels in channel class found */
			channel_list->num_entries++;
		}
	}

	if (channel_list->num_entries > 0)
		return BCMP2P_TRUE;
	else
		return BCMP2P_FALSE;
}

/* convert channels from list to array */
BCMP2P_BOOL p2papi_channel_list_to_array(p2p_chanlist_t *channel_list,
	int max_channels, BCMP2P_CHANNEL *channels, int *num_channels)
{
	int i, j;
	int count = 0;

	for (i = 0; i < channel_list->num_entries; i++) {
		p2p_chanlist_entry_t *entry = &channel_list->entries[i];
		for (j = 0; j < entry->num_channels; j++) {
			channels[count].channel_class = (BCMP2P_CHANNEL_CLASS)entry->band;
			channels[count].channel = entry->channels[j];
			if (++count == max_channels) {
				*num_channels = count;
				return BCMP2P_FALSE;
			}
		}
	}

	*num_channels = count;
	return BCMP2P_TRUE;
}

/* get driver channel list or user configured channel list if defined */
p2p_chanlist_t *p2papi_get_channel_list(p2papi_instance_t* hdl)
{
	if (hdl->user_channel_list != 0)
		/* user configured channel list */
		return hdl->user_channel_list;
	else
		/* driver channel list */
		return &hdl->channel_list;
}

/* get non-dfs channel list or user configured channel list if defined */
p2p_chanlist_t *p2papi_get_non_dfs_channel_list(p2papi_instance_t* hdl)
{
	if (hdl->user_channel_list != 0)
		/* user configured channel list */
		return hdl->user_channel_list;
	else
		/* non-dfs channel list */
		return &hdl->non_dfs_channel_list;
}

static void initialize_channel_list(p2papi_instance_t* hdl)
{
	int ret;
	wl_country_t cspec = {{0}, 0, {0}};
	chanspec_t c = 0, *chanspec;
	char abbrev[WLC_CNTRY_BUF_SZ] = ""; /* default.. current locale */
	char buf[sizeof(chanspec_t) + WLC_CNTRY_BUF_SZ +
		sizeof(uint32)*(WL_NUMCHANSPECS + 1)];
	int buflen;
	wl_uint32_list_t *list;
	int i, j;
	int num_chanspecs;
	BCMP2P_CHANNEL *ch;
	p2p_chanlist_t *channel_list = &hdl->channel_list;
	p2p_chanlist_t *non_dfs_channel_list = &hdl->non_dfs_channel_list;

	/* get country code */
	ret = p2papi_ioctl_get(hdl, WLC_GET_COUNTRY, &cspec, sizeof(cspec), 0);
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"initialize_channel_list: get country failed with %d!\n", ret));
		return;
	}
	memset(hdl->country, 0, sizeof(hdl->country));
	memcpy(hdl->country, cspec.country_abbrev, 2);
	/* v1.09 - country code 3rd byte is 0x04 */
	hdl->country[2] = 0x04;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "initialize_channel_list: country code=%c%c 0x%x\n",
		hdl->country[0], hdl->country[1], hdl->country[2]));

	memset(buf, 0, sizeof(buf));
	buflen = 0;

	/* Add chanspec argument */
	chanspec = (chanspec_t *) (buf + buflen);
	*chanspec = htodchanspec(c);
	buflen += sizeof(chanspec_t);

	/* Add country abbrev */
	strncpy(buf + buflen, abbrev, WLC_CNTRY_BUF_SZ);
	buflen += WLC_CNTRY_BUF_SZ;

	/* Add list */
	void * buf_tmpptr;
	uint32 list_count;

	list_count = htod32(WL_NUMCHANSPECS);

	buf_tmpptr = (void *)(buf + buflen);
	memcpy(buf_tmpptr, &list_count, sizeof(list_count));
	buflen += sizeof(list_count);
	ret = p2papi_iovar_buffer_get(hdl, "chanspecs", buf, buflen, buf, sizeof(buf));
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"initialize_channel_list: get chanspecs failed with %d!\n", ret));
		return;
	}

	list = (wl_uint32_list_t *)buf;
	num_chanspecs = dtoh32(list->count);

	ch = (BCMP2P_CHANNEL *) malloc(num_chanspecs * sizeof(BCMP2P_CHANNEL));
	if (ch == 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"initialize_channel_list: channel-class malloc failed\n"));
		return;
	}
	memset(ch, 0, num_chanspecs * sizeof(BCMP2P_CHANNEL));

	for (i = 0; i < num_chanspecs; i++) {
		c = (chanspec_t)dtoh32(list->element[i]);
		c = P2PWL_CHSPEC_IOTYPE_DTOH(c);
		p2papi_chspec_to_channel(c,	&ch[i]);
	}

	memset(channel_list, 0, sizeof(*channel_list));
	memset(non_dfs_channel_list, 0, sizeof(*non_dfs_channel_list));

	for (i = 0; i < P2P_CHANLIST_SE_MAX_ENTRIES; i++) {
		p2papi_channel_class_t *table = &channel_table[i];
		p2p_chanlist_entry_t *entry =
			&channel_list->entries[channel_list->num_entries];
		p2p_chanlist_entry_t *non_dfs_entry =
			&non_dfs_channel_list->entries[non_dfs_channel_list->num_entries];
		entry->band = table->channel_class;
		non_dfs_entry->band = table->channel_class;

		/* find channels in channel class */
		for (j = 0; j < num_chanspecs; j++) {
			if (table->channel_class == ch[j].channel_class) {
				BCMP2P_CHANNEL_CLASS channel_class;

				/* add channel to channel list */
				if (entry->num_channels < P2P_CHANNELS_MAX_ENTRIES) {
					entry->channels[entry->num_channels++] = ch[j].channel;
				}
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
				/* check if base channel is a dfs channel */
				if (!p2papi_find_channel_class(ch[j].channel, FALSE, &channel_class))
					channel_class = ch[j].channel_class;
#else
				channel_class = ch[j].channel_class;
#endif

				/* add channel to non-DFS channel list */
				if (channel_class != IEEE_5GHZ_20MHZ_CLASS_2_DFS &&
					channel_class != IEEE_5GHZ_20MHZ_CLASS_4_DFS &&
					channel_class != IEEE_5GHZ_40MHZ_CLASS_23_DFS &&
					channel_class != IEEE_5GHZ_40MHZ_CLASS_24_DFS &&
					channel_class != IEEE_5GHZ_40MHZ_CLASS_28_DFS &&
					channel_class != IEEE_5GHZ_40MHZ_CLASS_29_DFS) {

					if (non_dfs_entry->num_channels < P2P_CHANNELS_MAX_ENTRIES) {
						non_dfs_entry->channels[non_dfs_entry->num_channels++]
							= ch[j].channel;
						BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
							"non_dfs_channel = %d\n", __FUNCTION__, ch[j].channel));
					}
				} else {
					BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
						"DFS_channel = %d\n", __FUNCTION__, ch[j].channel));
				}
			}
		}
		if (entry->num_channels) {
			/* channels in channel class found */
			channel_list->num_entries++;
		}
		if (non_dfs_entry->num_channels) {
			/* channels in channel class found */
			non_dfs_channel_list->num_entries++;
		}
	}

	free(ch);
}

static void initialize_default_runtime_config(p2papi_instance_t* hdl)
{
	/* set defalt option to turn on/off multi-social-channels for discovery */
	hdl->enable_multi_social_channels = P2PAPI_ENABLE_MULTI_CHANNEL;

	/* Time required for STA peer to wait for AP peer to start WPS registrar.
	* By default, STA peer needs to wait P2PAPI_WPS_AP_CONFIG_TMO_MS
	* for AP peer to get configured . However, the max value can be
	* set in P2PAPI_WPS_AP_CONFIG_TMO_MS is limited to 2550 ms. This is
	* not enough since AP peer may take 4 seconds to start DHCP on Windows.
	*/
	hdl->peer_wps_go_cfg_tmo_ms = P2PAPI_WPS_AP_CONFIG_TMO_MS;
	hdl->extra_peer_go_cfg_tmo_ms = P2PAPI_EXTRA_AP_CONFIG_TMO_MS;

	/* Parameters for sending the provision discovery request to the target peer
	* and wait for a response.
	* If no response is received from the peer, retry up to N times D ms apart.
	* N and D are selected to ensure the frame can be received by the target
	* even if the target is a GO running cycling in and out of power save.
	*/
	hdl->max_provdis_retries = P2PAPI_MAX_PROVDIS_RETRIES;
	hdl->provdis_retry_delay_ms = P2PAPI_PROVDIS_RETRY_DELAY_MS;
	hdl->provdis_resp_wait_ms = P2PAPI_PROVDIS_RESP_WAIT_MS;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"initialize_default_runtime_config() enable_multi_social_channels=%d\n",
		hdl->enable_multi_social_channels));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"extra_peer_go_cfg_tmo_ms=%d,"
		" provdis(max_retries=%d,delay_ms=%d,resp_wait_ms=%d)\n",
		hdl->extra_peer_go_cfg_tmo_ms,
		hdl->max_provdis_retries,
		hdl->provdis_retry_delay_ms,
		hdl->provdis_resp_wait_ms));

}

/* Open a new instance of the P2P library */
BCMP2P_STATUS
p2papi_open(char *if_name, char *primary_if_name,
	p2papi_instance_t **instanceHdl)
{
	p2papi_instance_t* hdl;
	int ret;
	struct ether_addr my_mac_addr;
	P2PWL_HDL wl;
	BCMP2P_BOOL is_up;
	int value;
        BCMP2P_STATUS status;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "Compile options:\n"));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  P2PAPI_ENABLE_WPS=%d\n",
		P2PAPI_ENABLE_WPS));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  P2PAPI_ENABLE_MULTI_CHANNEL=%d\n",
		P2PAPI_ENABLE_MULTI_CHANNEL));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  P2PAPI_ENABLE_DHCPD=%d\n",
		P2PAPI_ENABLE_DHCPD));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  P2PAPI_USE_IDAUTH=%d\n",
		P2PAPI_USE_IDAUTH));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  P2PAPI_USE_IDSUP=%d\n",
		P2PAPI_USE_IDSUP));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_open: if_name=%s, primary_if_name=%s, sz=%u\n",
		if_name, primary_if_name, sizeof(p2papi_instance_t)));

	*instanceHdl = NULL;
	hdl = (p2papi_instance_t *) malloc(sizeof(*hdl));
	if (hdl == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_open malloc failed\n"));
		return BCMP2P_NOT_ENOUGH_SPACE;
	}

	memset(hdl, 0, sizeof(*hdl));
	hdl->magic = P2PAPI_HDL_MAGIC_NUMBER;
	P2PAPI_CHECK_P2PHDL(hdl);
#if P2PLOGGING
	p2pdbg_hdl = hdl;
#endif /* P2PLOGGING */

	strncpy(hdl->if_name, if_name, sizeof(hdl->if_name));
	hdl->if_name[sizeof(hdl->if_name) - 1] = '\0';
	strncpy(hdl->primary_if_name, primary_if_name,
		sizeof(hdl->primary_if_name));
	hdl->primary_if_name[sizeof(hdl->primary_if_name) - 1] = '\0';
	hdl->bssidx[P2PAPI_BSSCFG_PRIMARY] = 0;

	hdl->enable_dhcp = TRUE;
	hdl->enable_p2p = TRUE;
	p2papi_reset_state(hdl);

	hdl->default_discovery_timeout_secs = P2PAPI_DEFAULT_DISCOVERY_TIMEOUT;
	hdl->default_scan_duration_ms = P2PAPI_DEFAULT_DISCOVERY_INIT_SCAN_MS;
	hdl->default_listen_channel.channel_class =	BCMP2P_LISTEN_CHANNEL_CLASS;
	hdl->default_listen_channel.channel = P2PAPI_DEFAULT_LISTEN_CHANNEL;
	hdl->default_friendly_name = P2PAPI_DEFAULT_FRIENDLY_NAME;

	hdl->cancel_discovery_timeout_ms = 5000;
	hdl->cancel_connect_timeout_ms = 6000;
	hdl->discovery_timeout = hdl->default_discovery_timeout_secs;
	hdl->scan_duration_ms = hdl->default_scan_duration_ms;
	memcpy(&hdl->listen_channel, &hdl->default_listen_channel,
		sizeof(hdl->listen_channel));
	strcpy((char*)hdl->fname_ssid, hdl->default_friendly_name);
	hdl->fname_ssid_len = (uint32) strlen((char*)hdl->fname_ssid);

	/* Generate a random value for our tx tie breaker bit */
	p2papi_osl_rand_bytes((unsigned char *) &hdl->tx_tie_breaker,
		sizeof(hdl->tx_tie_breaker));
	hdl->tx_tie_breaker &= 0x01;

	/* Generate a random value for our initial GO negotiation dialog token */
	p2papi_osl_rand_bytes((unsigned char *) &hdl->gon_dialog_token,
		sizeof(hdl->gon_dialog_token));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_open: gon_dialog_token = %d\n", hdl->gon_dialog_token));

	/* initialize run-time config and allow OSL to overwrite these settings
	 * at p2papi_osl_open()
	 */
	initialize_default_runtime_config(hdl);


	/* Intialize the timer system */
	bcmseclib_init_timer_utilities_ex(P2P_MAX_TIMERS, &hdl->timer_mgr);


	hdl->osl_hdl = p2papi_osl_open(hdl, if_name, primary_if_name);
	if (hdl->osl_hdl == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_open: osl open failed!\n"));
		status = BCMP2P_ERROR;
		goto fail;
	}
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

#ifndef SOFTAP_ONLY
	p2papi_fsm_reset(hdl);
#endif

	/* Check if we can talk to the WL interface */
	ret = p2pwlu_check_wl_if(hdl);
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_open: check_wl failed with %d!\n", ret));
		status = BCMP2P_CANT_TALK_TO_DRIVER;
		goto fail;

	}

	/* Apply the APSTA and P2P WL settings that need to be applied before
	 * bringing up the WL interface.
	 */
	ret = p2pwlu_p2p_apsta_setup(hdl);
	if (ret == BCMP2P_FAIL_TO_SETUP_P2P_APSTA) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, 
			"p2papi_open: failed to setup apsta\n", ret));
		status =  (BCMP2P_STATUS) ret;
		goto fail;
	}

	/* disable mpc */
	value = 0;
	p2pwl_iovar_set_bss(wl, "mpc", &value, sizeof(value), 0);

	/* Bring up the driver if it is not up already */
	is_up = p2pwlu_isup(hdl);
	if (!is_up) {
		ret = p2pwlu_up(hdl);
		if (ret != 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl up' failed with %d\n",
				ret));
			status = BCMP2P_CANT_TALK_TO_DRIVER;
			goto fail;
		}
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_WAIT_WL_UP, 100);
		is_up = p2pwlu_isup(hdl);
	}

	p2papi_init_driver_event_masks(hdl);

	/* Debug: Print our primary MAC address.
	 * Note: On Windows this MAC address cannot be used for sending frames;
	 * the virtual interface address must be used instead.
	 */
	p2pwlu_get_mac_addr(hdl, &my_mac_addr);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_open: my MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
		my_mac_addr.octet[0], my_mac_addr.octet[1],
		my_mac_addr.octet[2], my_mac_addr.octet[3],
		my_mac_addr.octet[4], my_mac_addr.octet[5]));

	/* initialize country and channel list */
	initialize_channel_list(hdl);

	/* check if 'p2p' is supported in the driver */
	hdl->is_p2p_supported = (p2pwlu_is_p2p_supported(hdl) == 0) ? false : true;

	/* Initialize the OSL's raw frame receiver/manager */
	if (p2papi_osl_start_raw_rx_mgr(hdl) != BCME_OK) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_open: raw rx start error\n"));
		status = BCMP2P_FAIL_TO_START_RAW_RX;
		goto fail;
	}
	hdl->is_raw_rx_mgr_running = TRUE;
	if (p2papi_enable_driver_events(hdl, FALSE) != BCME_OK) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_open: enable events error\n"));
		status = BCMP2P_FAIL_TO_ENABLE_EVENTS;
		goto fail;
	}

#if P2PAPI_ENABLE_WPS
	/* Redirect WPS debug logs to our p2plib log function */
	brcm_wpscli_redirect_logs(output_wps_log);
#endif

#ifndef SOFTAP_ONLY
	hdl->sd.svc_req_entries = NULL;
#endif /* not SOFTAP_ONLY */

	*instanceHdl = (p2papi_instance_t *) hdl;

#if !P2PAPI_USE_IDAUTH || !P2PAPI_USE_IDSUP
	/* Init sequence for external auth/supp */
	hslif_init();
#endif

	/* Ensure the wireless interface is up */
	if (!p2pwl_isup(wl)) {
		if (p2pwl_up(wl) != 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_open: unable to bring up driver\n"));
			status = BCMP2P_INVALID_HANDLE;
			goto fail;
		}
	}


	/* Initialize the Action Frame Transmitter */
	(void) p2papi_aftx_api_init(hdl);
	hdl->af_tx_max_retries = P2PAPI_MAX_AF_TX_RETRIES;
	hdl->af_tx_retry_ms = P2PAPI_AF_TX_RETRY_DELAY_MS;

	return BCMP2P_SUCCESS;

fail:
        p2papi_osl_close(hdl, hdl->osl_hdl);
        free(hdl);
	return status;
}

BCMP2P_STATUS
p2papi_close(p2papi_instance_t* hdl)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_close\n"));
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	P2PAPI_GET_WL_HDL(hdl);

	/* If our connection BSS is still up, bring it down */
	if (p2pwlu_bss_isup(hdl)) {
		(void) p2pwlu_bss(hdl, FALSE);
	}

	p2papi_stop_pbc_timer(hdl);


#ifndef SOFTAP_ONLY
	/* Disable P2P Device discovery and remove P2P IEs */
	p2papi_disable_discovery(hdl);
/*	p2papi_deinit_discovery(hdl); */
#endif

	/* If the softAP is enabled, disable it */
	if (p2papi_is_softap_on(hdl)) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_close: softAP still on!\n"));
	}

	/* Remove any remaining P2P and WPS IEs we added */
	hdl->is_connecting = FALSE;
	hdl->is_p2p_discovery_on = FALSE;
	p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_DEVICE);
	p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_CONNECTION);

	/* Stop raw frame rx */
	if (hdl->is_raw_rx_mgr_running) {
		p2papi_osl_stop_raw_rx_mgr(hdl);
		hdl->is_raw_rx_mgr_running = FALSE;
	}

#ifndef SOFTAP_ONLY
	/* Release service request list buffer */
	if (hdl->sd.svc_req_entries) {
		free(hdl->sd.svc_req_entries);
		hdl->sd.svc_req_entries = NULL;
	}
#endif /* not  SOFTAP_ONLY */

	p2papi_deinit_driver_event_masks(hdl);

	/* Release IE data of old discovered peers */
	p2papi_reset_peer_ie_data(hdl);

	/* Close the OSL */
	p2papi_osl_close(hdl, hdl->osl_hdl);

	/* Deinitialize timers */
	bcmseclib_deinit_timer_utilities_ex(hdl->timer_mgr);


#if !P2PAPI_USE_IDAUTH || !P2PAPI_USE_IDSUP
	/* Close out the external/supp lib */
	/* NB: invalidates hdl->ext_auth_supp_ctx, no problem since we're
	 * about to free the whole hdl
	 */

	/* Deinit external security module. This call is asynchronous. For now,
	 * wait for it to complete. We should use a completion callback instead.
	 */
	hslif_deinit();
	p2posl_sleep_ms(1000);
#endif

	/* Deinitialize the Action Frame Transmitter */
	(void) p2papi_aftx_api_deinit(hdl);

	if (hdl->user_channel_list != 0) {
		free(hdl->user_channel_list);
		hdl->user_channel_list = 0;
	}

	free(hdl);
	return BCMP2P_SUCCESS;
}

/* save the bsscfg index */
int p2papi_save_bssidx(struct p2papi_instance_s* hdl, int usage, int bssidx)
{
	void *wl;
	int ret;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_ERROR;

	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return BCMP2P_INVALID_HANDLE;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
	           "p2papi_save_bssidx: usage=%d bssidx=%d\n", usage, bssidx));

	wl = P2PAPI_GET_WL_HDL(hdl);

	/* lock ioctl mutex */
	ret = p2papi_osl_ioctl_lock(hdl);
	if (ret == 0)
	{
		char *log_line = NULL;

		if (usage == P2PAPI_BSSCFG_DEVICE)
		{
			hdl->bssidx[P2PAPI_BSSCFG_DEVICE] = bssidx;
			p2posl_save_bssidx(wl, usage, bssidx);
		}
		else if (usage == P2PAPI_BSSCFG_CONNECTION)
		{
			hdl->bssidx[P2PAPI_BSSCFG_CONNECTION] = bssidx;
			p2posl_save_bssidx(wl, usage, bssidx);
		}
		else{
			log_line = "p2papi_save_bssidx: unknown usage!\n";
		}

		/* unlock ioctl mutex */
		p2papi_osl_ioctl_unlock(hdl);

		if (log_line != NULL)
		{
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, log_line));
		}
	}
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_save_bssidx: ioctl mutex lock failed!\n"));

	return 0;
}



/* Generate a random link configuration */
BCMP2P_STATUS
p2papi_generate_rnd_link_cfg(p2papi_instance_t* hdl, PBCMP2P_CONFIG pConfig)
{
	brcm_wpscli_nw_settings credentials;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_ERROR;

	BCMP2P_INIT_BCMP2P_CONFIG(pConfig);
	memcpy(&pConfig->operatingChannel, &hdl->op_channel,
		sizeof(pConfig->operatingChannel));
	pConfig->encryption = BCMP2P_ALGO_AES;
	pConfig->authentication = BCMP2P_WPA_AUTH_WPA2PSK;
	p2papi_wps_gen_rnd_cred(hdl, &credentials);
	strncpy((char*) pConfig->keyWPA, credentials.nwKey,
		sizeof(pConfig->keyWPA));
	pConfig->keyWPA[sizeof(pConfig->keyWPA)-1] = '\0';
	pConfig->ip_addr = 0xc0a81001;
	pConfig->netmask = 0xffffff00;
	pConfig->WPSConfig.wpsEnable = FALSE;
	pConfig->WPSConfig.wpsPin[0] = '\0';
	pConfig->DHCPConfig.DHCPOption = BCMP2P_DHCP_OFF;
	pConfig->DHCPConfig.starting_ip = 0;
	pConfig->DHCPConfig.ending_ip = 0;

	return BCMP2P_SUCCESS;
}

#ifndef SOFTAP_ONLY
BCMP2P_STATUS
p2papi_get_peer_info(p2papi_instance_t* hdl, BCMP2P_PEER_INFO *pBuffer,
    uint32 buffLength, uint32 *numEntries)
{
	int max_entries = buffLength / sizeof(BCMP2P_PEER_INFO);
	int i;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	*numEntries = 0;
	P2PAPI_GET_WL_HDL(hdl);

	if (p2papi_is_ap(hdl)) {

		P2PAPI_DATA_LOCK(hdl);
		*numEntries = hdl->client_list_count;
		if (*numEntries > (uint32) max_entries)
			/* caller provided buffer is not large enough */
			status = BCMP2P_NOT_ENOUGH_SPACE;
		else  {
			for (i = 0;
				i < (int) *numEntries && i < max_entries;
				i++) {
				memset(pBuffer, 0, sizeof(*pBuffer));
				pBuffer->length = sizeof(*pBuffer);
				memcpy(pBuffer->mac_address, hdl->client_list[i].p2p_int_addr,
					sizeof(pBuffer->mac_address));
				pBuffer->is_p2p = hdl->client_list[i].is_p2p_client;
				
				/* Set peer IE data */
				pBuffer->ie_data_len = hdl->client_list[i].ie_data_len;
				memcpy(pBuffer->ie_data, hdl->client_list[i].ie_data,
						pBuffer->ie_data_len);

				/* Log Peer IE data */
				p2papi_log_hexdata(BCMP2P_LOG_INFO, "p2papi_get_peer_info: peer IE data",
					pBuffer->ie_data, pBuffer->ie_data_len);
				pBuffer++;
			}
		}
		P2PAPI_DATA_UNLOCK(hdl);
	} else if (p2papi_is_sta(hdl)) {
		struct ether_addr bssid;
		if (p2papi_osl_is_associated(hdl, &bssid)) {
			*numEntries = 1;
			if (max_entries < 1)
				/* caller provided buffer is not large enough */
				status = BCMP2P_NOT_ENOUGH_SPACE;
			else
			{
				memset(pBuffer, 0, sizeof(*pBuffer));
				pBuffer->length = sizeof(*pBuffer);
				memcpy(pBuffer->mac_address, bssid.octet,
					sizeof(pBuffer->mac_address));

				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_get_peer_info: Peer bssid %02x:%02x:%02x:%02x:%02x:%02x\n",
					pBuffer->mac_address[0], pBuffer->mac_address[1],
					pBuffer->mac_address[2], pBuffer->mac_address[3],
					pBuffer->mac_address[4], pBuffer->mac_address[5]));

				/* Use peer association response IE data */ 
				if (memcmp(pBuffer->mac_address, hdl->peer_int_addr.octet, 6) == 0) {
					pBuffer->ie_data_len = hdl->peer_assocrsp_ie_len;
					if (pBuffer->ie_data_len > 0)
						memcpy(pBuffer->ie_data, hdl->peer_assocrsp_ie_data,
							hdl->peer_assocrsp_ie_len);
				}
			}
		}
	}

	return status;
}

BCMP2P_STATUS
p2papi_del_peer_info(p2papi_instance_t* hdl, struct ether_addr* int_addr)
{
	BCMP2P_STATUS status = BCMP2P_ERROR;
	int i;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	P2PAPI_DATA_LOCK(hdl);

	if (p2papi_is_ap(hdl)) {
		/* search client list */
		for (i = 0;	i < hdl->client_list_count; i++) {
			if (memcmp(int_addr, hdl->client_list[i].p2p_int_addr,
				sizeof(*int_addr)) == 0) {
				/* found it */
				status = BCMP2P_SUCCESS;
				break;
			}
		}

		/* delete if found */
		if (status == BCMP2P_SUCCESS) {
			/* i already indexes found item */
			for (; i < hdl->client_list_count; i++) {
				int j = i + 1;
				if (j < hdl->client_list_count) {
					/* shift items */
					memcpy(&hdl->client_list[i], &hdl->client_list[j],
						sizeof(hdl->client_list[i]));
				}
			}
			hdl->client_list_count--;
		}

	}

	P2PAPI_DATA_UNLOCK(hdl);

	return status;
}

BCMP2P_STATUS
p2papi_get_peer_ip_info(p2papi_instance_t* hdl,
	PBCMP2P_PEER_IPINFO pBuffer, uint32 buffLength, uint32 *numEntries)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	(void) pBuffer;
	(void) buffLength;
	*numEntries = 0;

	/* not implemented yet */
	return BCMP2P_UNIMPLEMENTED;
}

BCMP2P_BOOL
p2papi_is_discovering(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return FALSE;
/*
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_is_discovering: %d\n",
		hdl->is_discovering));
*/
	return (BCMP2P_BOOL) hdl->is_discovering;
}

BCMP2P_BOOL
p2papi_is_listen_only(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return FALSE;
/*
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_is_listen_only: %d\n",
		hdl->is_listen_only));
*/
	return (BCMP2P_BOOL) (hdl->is_discovering && hdl->is_listen_only);
}

BCMP2P_BOOL
p2papi_is_connecting(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return FALSE;
	return (BCMP2P_BOOL) hdl->is_connecting;
}

BCMP2P_BOOL
p2papi_is_sta(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return FALSE;
	return (hdl->is_connected && !hdl->is_ap);
}

BCMP2P_BOOL
p2papi_is_ap(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return FALSE;
	return (hdl->is_p2p_group || (hdl->is_connected && hdl->is_ap));
}
#endif /* SOFTAP_ONLY */


BCMP2P_BOOL
p2papi_is_softap_on(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return FALSE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);

	if ((hdl->is_connecting || hdl->is_connected) && hdl->is_ap) {
		return p2pwlu_bss_isup(hdl);
	}
	return FALSE;
}

BCMP2P_BOOL
p2papi_is_softap_ready(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return FALSE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);

	return (BCMP2P_BOOL)(hdl->is_ap && hdl->ap_ready);
}

/* Enable or disable the DHCP server.  Call this only on the AP peer. */
BCMP2P_STATUS
p2papi_dhcp_enable(p2papi_instance_t* hdl, BCMP2P_BOOL on_off)
{
	BCMP2P_STATUS ret = BCMP2P_ERROR;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_dhcp_enable: %d\n", on_off));
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_ERROR;

#if P2PAPI_ENABLE_DHCPD
	if (on_off) {
		/* Open the OS firewall to allow DHCP server IP packets */
		if (!p2papi_osl_dhcp_open_firewall(hdl)) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_dhcp_enable: open firewall failed!\n"));
			goto exit;
		}

		/* Redirect DHCP debug logs to our p2plib log function */
		DHCP_Redirect_Logs(output_wps_log);

		/* If the DHCP server is not already running
		 *   Init the DHCP server
		 */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
 		"p2papi_dhcp_enable:DHCP_init(subnet=0x%x sIP=%d endIP=%d svrIP=0x%x Dns=0x%x)\n",
		hdl->dhcp_subnet, hdl->dhcp_start_ip, hdl->dhcp_end_ip,
		hdl->ap_config.ip_addr, hdl->ap_config.DHCPConfig.dns1));

		hdl->dhcpd_hdl = DHCP_init(hdl->dhcp_subnet, hdl->dhcp_start_ip,
			hdl->dhcp_end_ip, hdl->ap_config.ip_addr, hdl->ap_config.DHCPConfig.dns1);

		if (!hdl->dhcpd_hdl) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_dhcp_enable: init DHCP server failed!\n"));
			goto exit;
		}

		/* Run the DHCP server asynchronously */
		if (!p2papi_osl_dhcp_run_server(hdl, hdl->dhcpd_hdl)) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_dhcp_enable: run DHCP server failed!\n"));
			goto exit;
		}
	} else {
		if (hdl->dhcpd_hdl) {
			hdl->dhcpd_hdl = NULL;

			/* End the thread running the DHCP server */
			if (!p2papi_osl_dhcp_end_server(hdl, hdl->dhcpd_hdl)) {
				BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
					"p2papi_dhcp_enable: stop DHCP server failed!\n"));
				goto exit;
			}

			/* Deinitialize the DHCP server */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_dhcp_enable: calling DHCP_Unload()\n"));
			DHCP_Unload();

			/* Close the OS firewall holes opened for the DHCP server */
			if (!p2papi_osl_dhcp_close_firewall(hdl)) {
				BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
					"p2papi_dhcp_enable: close firewall failed!\n"));
				goto exit;
			}
		}
	}
	ret = BCMP2P_SUCCESS;
exit:
	if (ret == BCMP2P_SUCCESS) {
		hdl->dhcp_on = on_off ? true : false;
	}

#else /* !P2PAPI_ENABLE_DHCPD */

	if (on_off) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_dhcp_enable: not running the DHCP server\n"));
		hdl->dhcpd_hdl = NULL;
	}
	hdl->dhcp_on = FALSE;
	ret = BCMP2P_SUCCESS;
#endif /* P2PAPI_ENABLE_DHCPD */

	return ret;
}

BCMP2P_BOOL
p2papi_is_dhcp_on(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return FALSE;

	return (BCMP2P_BOOL) hdl->dhcp_on;
}


p2papi_peer_info_t *
p2papi_find_peer(p2papi_instance_t* hdl, uint8 *mac_addr)
{
	p2papi_peer_info_t *peer = NULL;
	int i;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return NULL;
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"p2papi_find_peer: peer MAC=%02x:%02x:%02x:%02x:%02x:%02x count=%u\n",
		mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		mac_addr[4], mac_addr[5], hdl->peer_count));

	/* Find our hdl->peer_info[] index from the mac addr */
	for (i = 0; i < hdl->peer_count; i++) {
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"  i=%d: mac=%02x:%02x:%02x:%02x:%02x:%02x ssid=%s isgrp=%d\n", i,
			hdl->peers[i].mac.octet[0], hdl->peers[i].mac.octet[1],
			hdl->peers[i].mac.octet[2], hdl->peers[i].mac.octet[3],
			hdl->peers[i].mac.octet[4], hdl->peers[i].mac.octet[5],
			hdl->peers[i].ssid, hdl->peers[i].is_p2p_group));
		if (memcmp(&hdl->peers[i].mac.octet, mac_addr,
			sizeof(hdl->peers[i].mac.octet)) == 0) {
			peer = &hdl->peers[i];
			BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
				"p2papi_find_peer: found at index=%d\n", i));
			BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
				"  bssid=%02x:%02x:%02x:%02x:%02x:%02x\n", i,
				hdl->peers[i].bssid.octet[0], hdl->peers[i].bssid.octet[1],
				hdl->peers[i].bssid.octet[2], hdl->peers[i].bssid.octet[3],
				hdl->peers[i].bssid.octet[4], hdl->peers[i].bssid.octet[5]));
			break;
		}
	}
	return peer;
}

/* Wait for the peer to disconnect.  Returns only when the peer disconnects */
int
p2papi_wait_for_disconnect(void* p2pHdl)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHdl;
	int count = 0;
	int result;

	P2PAPI_CHECK_P2PHDL(p2pHdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	if (!hdl->is_connected)
		return 0;

	P2PLOG("p2papi_wait_for_disc: enter\n");

	/* Polling loop to check if we are still joined to the peer */
	while (hdl->is_connected) {
/*		P2PLOG1("p2papi_wait_for_disc: poll %d\n", i++); */
		if (hdl->is_ap) {
			result = p2pwlu_get_assoc_count(hdl, TRUE, &count);
			if (result != 0) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_wait_for_disc: ioctl failed\n"));
			} else if (count == 0) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_wait_for_disc: no associated STAs\n"));
				break;
			}
		} else { /* is STA */
			if (!p2pwlu_is_associated(hdl)) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_wait_for_disc: not associated\n"));
				break;
			} else if (hdl->disconnect_detected) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_wait_for_disc: disconnect detected\n"));
				break;
			} else {
				BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
					"p2papi_wait_for_disc: associated\n"));
			}
		}
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_DISCONNECT_POLL, 500);
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_wait_for_disc: exit (disconnect detected)\n"));
	return 0;
}

int
p2papi_act_only_as_sta(void *p2pHdl, bool onOff)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHdl;

	P2PAPI_CHECK_P2PHDL(p2pHdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);

	/* Acting only as a STA is not allowed if already associated to an AP */
	if (onOff) {
		if (p2pwlu_is_associated(hdl)) {
			return -1;
		}
		hdl->act_only_as_sta = TRUE;
		hdl->act_only_as_ap = FALSE;
	} else {
		hdl->act_only_as_sta = FALSE;
	}
	return 0;
}

int
p2papi_act_only_as_ap(void *p2pHdl, bool onOff)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHdl;

	if (onOff) {
		hdl->act_only_as_ap = TRUE;
		hdl->act_only_as_sta = FALSE;
	} else {
		hdl->act_only_as_ap = FALSE;
	}
	return 0;
}

/*
 * Global variable accessor functions
 */

/* Get a ptr to our current event notifications */
p2papi_notif_config_t*
p2papi_get_notifs(p2papi_instance_t *hdl)
{
	(void) hdl;
	return &p2papi_notifs;
}

/* Get/set our OSL handle */
void*
p2papi_get_osl_hdl(p2papi_instance_t *hdl)
{
	return hdl->osl_hdl;
}
void
p2papi_set_osl_hdl(p2papi_instance_t *hdl, void *oslhdl)
{
	hdl->osl_hdl = oslhdl;
}

/* Get our discovered peers list */
void
p2papi_get_peers_array(p2papi_instance_t *hdl,
    p2papi_peer_info_t** peers_array, unsigned int *peers_count)
{
	*peers_array = hdl->peers;
	*peers_count = hdl->peer_count;
}

/* Get our negotiated WPS credentials */
brcm_wpscli_nw_settings*
p2papi_get_wps_credentials(p2papi_instance_t *hdl)
{
	return &hdl->credentials;
}

/* Get our P2P social timeout */
int
p2papi_get_discovery_timeout(p2papi_instance_t *hdl)
{
	return hdl->discovery_timeout;
}

/* Get our peer's P2P Device Address */
struct ether_addr*
p2papi_get_peer_mac(p2papi_instance_t *hdl)
{
	return &hdl->peer_dev_addr;
}

/* Do an application notification callback.
 * This is a common implementation called by most OSL implementations of
 * p2posl_bss_isup().  DO NOT call this function directly from the
 * common code -- call p2papi_osl_do_notify_cb() instead to allow the OSL to
 * override the common implementation if necessary.
 */
void
p2papi_common_do_notify_cb(p2papi_instance_t* hdl,
	BCMP2P_NOTIFICATION_TYPE type, BCMP2P_NOTIFICATION_CODE code)
{
	void *notif_data = NULL;
	int notif_data_length = 0;
#ifndef SOFTAP_ONLY
	BCMP2P_DISCOVER_ENTRY *peer_info;
	BCMP2P_INVITE_PARAM*	invite_params;
	uint8	*status_code;
	uint8	*minor_rc;
#endif /* SOFTAP_ONLY */

	(void) hdl;

	/* Do nothing if no callback fn is registered */
	if (p2papi_notifs.callback == NULL) {
		return;
	}
	/* Do nothing if this notification type is not enabled */
	if (0 == (p2papi_notifs.type & type)) {
		return;
	}

	/* Get any necessary notification data based on the notif type */
	switch (code) {
#ifndef SOFTAP_ONLY
	case BCMP2P_NOTIF_PROVISION_DISCOVERY_REQUEST:
	case BCMP2P_NOTIF_PROVISION_DISCOVERY_RESPONSE:
	case BCMP2P_NOTIF_PROVISION_DISCOVERY_TIMEOUT:
		peer_info = (BCMP2P_DISCOVER_ENTRY *) malloc(sizeof(*peer_info));
		if (peer_info == NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: peer_info malloc failed\n"));
			return;
		}
		memset(peer_info, 0, sizeof(*peer_info));
		strncpy((char*)peer_info->ssid, (char*)hdl->pd.device_name,
			sizeof(peer_info->ssid));
		peer_info->ssid[sizeof(peer_info->ssid) - 1] = '\0';
		memcpy(peer_info->mac_address, hdl->pd.peer_mac.octet,
			sizeof(peer_info->mac_address));
		peer_info->channel = hdl->pd.channel;
		peer_info->wps_cfg_methods = hdl->pd.config_methods;
		peer_info->wps_device_pwd_id = hdl->peer_gon_device_pwd_id;		
		notif_data = (void*) peer_info;
		notif_data_length = sizeof(*peer_info);
		break;
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_STA_ACK:
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_AP_ACK:
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL:
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_NO_PROV_INFO:
	case BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_REQUEST_RECEIVED:
		peer_info = (BCMP2P_DISCOVER_ENTRY *) malloc(sizeof(*peer_info));
		if (peer_info == NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: peer_info malloc failed\n"));
			return;
		}
		memset(peer_info, 0, sizeof(*peer_info));
		strncpy((char*)peer_info->ssid, (char*)hdl->peer_ssid,
			sizeof(peer_info->ssid));
		peer_info->ssid[sizeof(peer_info->ssid) - 1] = '\0';
		peer_info->ssidLength = (uint32) strlen((char*)hdl->peer_ssid);
		memcpy(peer_info->mac_address, hdl->peer_dev_addr.octet,
			sizeof(peer_info->mac_address));
		peer_info->channel = hdl->gon_peer_listen_channel;
		peer_info->wps_cfg_methods = hdl->pd.config_methods;		
		peer_info->wps_device_pwd_id = hdl->peer_gon_device_pwd_id;
		notif_data = (void*) peer_info;
		notif_data_length = sizeof(*peer_info);
		break;
	case BCMP2P_NOTIF_P2P_INVITE_REQ:
		invite_params = (BCMP2P_INVITE_PARAM*) malloc(sizeof(*invite_params));
		if (invite_params == NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: invite_params malloc failed\n"));
			return;
		}
		memcpy(invite_params, &hdl->invite_req, sizeof(*invite_params));
		notif_data = (void*) invite_params;
		notif_data_length = sizeof(*invite_params);
		break;
	case BCMP2P_NOTIF_P2P_INVITE_RSP:
		invite_params = (BCMP2P_INVITE_PARAM*) malloc(sizeof(*invite_params));
		if (invite_params == NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: invite_params malloc failed\n"));
			return;
		}
		memcpy(invite_params, &hdl->invite_rsp, sizeof(*invite_params));
		notif_data = (void*) invite_params;
		notif_data_length = sizeof(*invite_params);
		break;
	case BCMP2P_NOTIF_DEV_DISCOVERABILITY_RSP:
		status_code = (uint8 *)malloc(sizeof(hdl->status_code));
		if (status_code == NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: status_code malloc failed\n"));
			return;
		}
		*status_code = hdl->status_code;
		notif_data = (void*) status_code;
		notif_data_length = sizeof(hdl->status_code);
		break;
	case BCMP2P_NOTIF_P2P_PRESENCE_REQ:
	case BCMP2P_NOTIF_P2P_PRESENCE_RSP:
		notif_data = malloc(sizeof(BCMP2P_PRESENCE_PARAM));
		if (notif_data == NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: notif_data malloc failed\n"));
			return;
		}
		memcpy(notif_data, &hdl->presence.notify_params, sizeof(BCMP2P_PRESENCE_PARAM));
		notif_data_length = sizeof(BCMP2P_PRESENCE_PARAM);
		break;
	case BCMP2P_NOTIF_SVC_RESP_RECEIVED:
	case BCMP2P_NOTIF_SVC_REQ_RECEIVED:
	case BCMP2P_NOTIF_SVC_COMEBACK_RESP_RECEIVED:
	case BCMP2P_NOTIF_SVC_COMEBACK_REQ_RECEIVED:
	case BCMP2P_NOTIF_SVC_REQ_COMPLETED:
	case BCMP2P_NOTIF_SVC_RSP_COMPLETED:
		notif_data = malloc(sizeof(BCMP2P_SERVICE_DISCOVERY_PARAM));
		if (notif_data == NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: notif_data malloc failed\n"));
			return;
		}
		memcpy(notif_data, &hdl->sd.notify_params, sizeof(BCMP2P_SERVICE_DISCOVERY_PARAM));
		notif_data_length = sizeof(BCMP2P_SERVICE_DISCOVERY_PARAM);
		break;
	case BCMP2P_NOTIF_PRIMARY_IF_DISCONNECTED:
		minor_rc = (uint8 *)malloc(sizeof(hdl->minor_rc));
		if (minor_rc == NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: minor_rc malloc failed\n"));
			return;
		}
		*minor_rc = hdl->minor_rc;
		notif_data = (void*) minor_rc;
		notif_data_length = sizeof(hdl->minor_rc);
		break;
	case BCMP2P_NOTIF_CREATE_LINK_COMPLETE:
	{
		BCMP2P_PERSISTENT *persist;
		notif_data = malloc(sizeof(BCMP2P_PERSISTENT));
		if (notif_data == NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: notif_data malloc failed\n"));
			return;
		}
		persist = (BCMP2P_PERSISTENT *)notif_data;
		memset(persist, 0, sizeof(*persist));
		persist->is_go = hdl->is_p2p_group;
		memcpy(&persist->peer_dev_addr,
			p2papi_get_peer_dev_addr(hdl),
			sizeof(persist->peer_dev_addr));
		{
			/* find peer info to get persistence flag */
			uint8 dev_addr[6];
			dev_addr[0] = persist->peer_dev_addr.octet[0];
			dev_addr[1] = persist->peer_dev_addr.octet[1];
			dev_addr[2] = persist->peer_dev_addr.octet[2];
			dev_addr[3] = persist->peer_dev_addr.octet[3];
			dev_addr[4] = persist->peer_dev_addr.octet[4];
			dev_addr[5] = persist->peer_dev_addr.octet[5];
			p2papi_peer_info_t *peer_info;
			peer_info = p2papi_find_peer(hdl, dev_addr);
			if (peer_info)
			{
				persist->peer_supports_persistence = peer_info->is_persistent_group;
			}
			else
			{
				BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: persist "
				           "- can't find peer! invite req? %s\n", hdl->invite_req.groupSsid));
				if (memcmp(hdl->invite_req.srcDevAddr.octet,
				           persist->peer_dev_addr.octet,
					   sizeof(hdl->invite_req.srcDevAddr.octet)) == 0)
				{
					BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "   invite flags %d\n", hdl->invite_req.inviteFlags));
					if (hdl->invite_req.inviteFlags & BCMP2P_INVITE_FLAG_REINVOKE)
						persist->peer_supports_persistence = 1;
				}
			}
		}
		{
			/* find peer info to get persistence flag */
			uint8 dev_addr[6];
			dev_addr[0] = persist->peer_dev_addr.octet[0];
			dev_addr[1] = persist->peer_dev_addr.octet[1];
			dev_addr[2] = persist->peer_dev_addr.octet[2];
			dev_addr[3] = persist->peer_dev_addr.octet[3];
			dev_addr[4] = persist->peer_dev_addr.octet[4];
			dev_addr[5] = persist->peer_dev_addr.octet[5];
			p2papi_peer_info_t *peer_info;
			peer_info = p2papi_find_peer(hdl, dev_addr);
			if (peer_info)
			{
				persist->peer_supports_persistence = peer_info->is_persistent_group;
			}
			else
			{
				BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_common_do_notify_cb: persist "
				           "- can't find peer! invite req? %s\n", hdl->invite_req.groupSsid));
				if (memcmp(hdl->invite_req.srcDevAddr.octet,
				           persist->peer_dev_addr.octet,
					   sizeof(hdl->invite_req.srcDevAddr.octet)) == 0)
				{
					BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "   invite flags %d\n", hdl->invite_req.inviteFlags));
					if (hdl->invite_req.inviteFlags & BCMP2P_INVITE_FLAG_REINVOKE)
						persist->peer_supports_persistence = 1;
				}
			}
		}		
		p2papi_get_go_credentials(hdl,
			persist->ssid, persist->pmk,
			persist->is_go ? persist->passphrase : 0);
		notif_data_length = sizeof(BCMP2P_PERSISTENT);
	}
	break;
#endif /* not SOFTAP_ONLY */
	default:
		break;
	}

	P2PVERB2("p2papi_osl_do_notify_cb: type=%d code=0x%x\n", type, code);
	p2papi_notifs.callback(code, p2papi_notifs.cbContext, notif_data, notif_data_length);

	if (notif_data)
		free(notif_data);
}

int
p2papi_common_apply_sta_security(p2papi_instance_t* hdl, char in_ssid[],
	brcm_wpscli_authtype in_authType, brcm_wpscli_encrtype in_encrType,
	char in_nwKey[], uint16 in_wepIndex)
{
	int ret = 0;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	uint32 wsec = 0;
	P2PWL_HDL wl;
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];
#if P2PAPI_USE_IDSUP
	int sup_wpa;
	wsec_pmk_t pmk;
	wl_wsec_key_t wlkey;
	unsigned char *data = wlkey.data;
	char hex[] = "XX";
	char *keystr;
	size_t keylen;
#endif

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	/* get auth */
	auth = (in_authType == BRCM_WPS_AUTHTYPE_SHARED);

	/* get wpa_auth */
	if (in_authType == BRCM_WPS_AUTHTYPE_WPAPSK)
		wpa_auth |= WPA_AUTH_PSK;
	if (in_authType == BRCM_WPS_AUTHTYPE_WPA2PSK)
		wpa_auth |= WPA2_AUTH_PSK;
	if (in_authType == BRCM_WPS_AUTHTYPE_WPAPSK_WPA2PSK)
		wpa_auth |= WPA_AUTH_PSK | WPA2_AUTH_PSK;

	/* get wsec */
	if (in_encrType == BRCM_WPS_ENCRTYPE_WEP)
		wsec |= WEP_ENABLED;
	else if (in_encrType == BRCM_WPS_ENCRTYPE_TKIP)
		wsec |= TKIP_ENABLED;
	else if (in_encrType == BRCM_WPS_ENCRTYPE_AES)
		wsec |= AES_ENABLED;
	else if (in_encrType == BRCM_WPS_ENCRTYPE_TKIP_AES)
		wsec |= TKIP_ENABLED | AES_ENABLED;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"apply_sta_sec: ssid=%.*s\n",
		DOT11_MAX_SSID_LEN, in_ssid));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"             : auth=%d wauth=%d wsec=%d wepix=%d bssidx=%d\n",
		auth, wpa_auth, wsec, in_wepIndex, bssidx));
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
	/* for security, do not display the 'in_nwKey' in 'unencrypted' format */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"             : nwKey=%s\n", in_nwKey));
#endif

	/* set infrastructure mode */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s infra %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		infra));
	ret = p2posl_wl_ioctl_bss(wl, WLC_SET_INFRA, &infra, sizeof(int), TRUE, bssidx);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"apply_sta_sec: infra error %d\n", auth, ret));
		goto exit;
	}

	/* set mac-layer auth */
	ret = p2pwlu_bssiovar_setint(hdl, "auth",
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], auth);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"apply_sta_sec: auth error %d\n", auth, ret));
		goto exit;
	}

	/* set wsec */
	ret = p2pwlu_bssiovar_setint(hdl, "wsec",
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], wsec);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"apply_sta_sec: wsec error %d\n", ret));
		goto exit;
	}

	/* set upper-layer auth */
	ret = p2pwlu_bssiovar_setint(hdl, "wpa_auth",
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], wpa_auth);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"apply_sta_sec: wpa_auth error %d\n", ret));
		goto exit;
	}

#if P2PAPI_USE_IDSUP
	/* set in-driver supplicant */
	sup_wpa = ((wpa_auth & WPA_AUTH_PSK) == 0)? 0: 1;
	sup_wpa |= ((wpa_auth & WPA2_AUTH_PSK) == 0)? 0: 1;
	ret = p2pwlu_bssiovar_setint(hdl, "sup_wpa",
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], sup_wpa);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"apply_sta_sec: sup_wpa error %d\n", ret));
		goto exit;
	}

	/* set the key if wsec */
	if (wsec == WEP_ENABLED) {
		memset(&wlkey, 0, sizeof(wl_wsec_key_t));
		if (in_wepIndex < 4)
			wlkey.index = in_wepIndex;
		else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"apply_sta_sec: bad WEP index %d\n", in_wepIndex));
		}
		switch (strlen(in_nwKey)) {
		/* ASIC */
		case 5:
		case 13:
		case 16:
			wlkey.len = (uint32) strlen(in_nwKey);
			memcpy(data, in_nwKey, wlkey.len + 1);
			break;
		case 10:
		case 26:
		case 32:
		case 64:
			wlkey.len = (uint32) strlen(in_nwKey) / 2;
			keystr = in_nwKey;
			while (*keystr) {
				strncpy(hex, keystr, 2);
				*data++ = (char) strtoul(hex, NULL, 16);
				keystr += 2;
			}
			break;
		default:
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"Bad STA WEP key str=%s len=%d\n", in_nwKey,
				strlen(in_nwKey)));
			ret = -1;
			goto exit;
		}

		switch (wlkey.len) {
		case 5:
			wlkey.algo = CRYPTO_ALGO_WEP1;
			break;
		case 13:
			wlkey.algo = CRYPTO_ALGO_WEP128;
			break;
		case 16:
			/* default to AES-CCM */
			wlkey.algo = CRYPTO_ALGO_AES_CCM;
			break;
		case 32:
			wlkey.algo = CRYPTO_ALGO_TKIP;
			break;
		default:
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"Bad STA WEP len %d\n", wlkey.len));
			ret = -1;
			goto exit;
		}

		/* Set as primary key by default */
		wlkey.flags |= WL_PRIMARY_KEY;

#if P2PAPI_ENABLE_DEBUG_SHOWKEY
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl addwep %d %s\n",
			wlkey.index, in_nwKey));
#else
		/* for security, do not display 'in_nwKey' in 'unencrypted' format */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl addwep %d ***\n",
			wlkey.index));
#endif

		ret = p2pwlu_bssiovar_set(hdl, "wsec_key",
			hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], &wlkey,
			sizeof(wlkey));
		if (ret < 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"apply_sta_sec: wsec_key error %d\n", ret));
			goto exit;
		}
	} else if ((wsec & ~SES_OW_ENABLED) != 0) {
		keylen = strlen(in_nwKey);
		if (keylen < WSEC_MIN_PSK_LEN || keylen > WSEC_MAX_PSK_LEN) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"Bad passphrase '%s' - length must be %d...%d chars\n",
				in_nwKey, WSEC_MIN_PSK_LEN, WSEC_MAX_PSK_LEN));
			ret = -1;
			goto exit;
		}
		memset(&pmk, 0, sizeof(wsec_pmk_t));
		pmk.key_len = keylen;
		pmk.flags = WSEC_PASSPHRASE;
		strncpy((char *)pmk.key, in_nwKey, sizeof(pmk.key));
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s set_pmk %s\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, bssidx), in_nwKey));
#else
		/* for security reason, do not display the key in unencrypted format */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s set_pmk ***\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, bssidx)));
#endif
		ret = p2posl_wl_ioctl_bss(wl, WLC_SET_WSEC_PMK, &pmk, sizeof(pmk),
			TRUE, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
		if (ret < 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"apply_sta_sec: set_pmk error %d\n", ret));
			goto exit;
		}
	}
#else
	/* use an external supplicant */
	printf("p2papi_common_apply_sta_security: bsscfg; index %d ifname %s\n",
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION],
		p2papi_osl_get_sta_mode_ifname(hdl));

	hdl->ext_auth_supp_ctx = hslif_init_ctx();
	if (hdl->ext_auth_supp_ctx == NULL) {
		P2PERR("p2papi_open: failed to init external auth/supp ctx\n");
		ret = BCMP2P_INVALID_HANDLE;
		goto exit;
	}

	ret = hslif_set_cfg(hdl->ext_auth_supp_ctx,
		p2papi_osl_get_sta_mode_ifname(hdl), /* ifname */
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], /* bsscfg index */
		0,							/* supplicant */
		in_ssid, wpa_auth, wsec, in_nwKey);

#endif /* P2PAPI_USE_IDSUP */

exit:
	return ret;
}

#if P2PAPI_USE_IDSUP
static int
p2papi_add_wep_key(p2papi_instance_t* hdl, int key_index,
	char *wep_key, BCMP2P_BOOL is_primary)
{
	int ret = 0;
	wl_wsec_key_t wlkey;
	unsigned char *data = wlkey.data;
	char hex[] = "XX";
	char *keystr;
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];

	memset(&wlkey, 0, sizeof(wl_wsec_key_t));
	wlkey.index = key_index;
	if (is_primary) {
		wlkey.flags |= WL_PRIMARY_KEY;
	}

	/* Get the wep key and convert from hex to binary if needed */
	switch (strlen(wep_key)) {
	case 5:
	case 13:
	case 16:
		/* binary key */
		wlkey.len = (uint32) strlen(wep_key);
		if (wlkey.len > sizeof(wlkey.data))
			wlkey.len = sizeof(wlkey.data);
		memcpy(data, wep_key, wlkey.len + 1);
		break;
	case 10:
	case 26:
	case 32:
	case 64:
		/* ascii hex key */
		wlkey.len = (uint32) strlen(wep_key) / 2;
		if (wlkey.len > sizeof(wlkey.data)) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"add_wep_key: WEP key too long: %d\n", wlkey.len));
			wlkey.len = sizeof(wlkey.data);
		}
		keystr = wep_key;
		while (*keystr) {
			strncpy(hex, keystr, 2);
			*data++ = (char) strtoul(hex, NULL, 16);
			keystr += 2;
		}
		break;
	default:
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "Bad AP WEP key %s len=%d i=%d\n",
			wep_key, strlen(wep_key), key_index));
		return -1;
	}

	/* Derive the WEP encryption type from on the key length */
	switch (wlkey.len) {
	case 5:
		wlkey.algo = CRYPTO_ALGO_WEP1;
		break;
	case 13:
		wlkey.algo = CRYPTO_ALGO_WEP128;
		break;
	case 16:
		/* default to AES-CCM */
		wlkey.algo = CRYPTO_ALGO_AES_CCM;
		break;
	case 32:
		wlkey.algo = CRYPTO_ALGO_TKIP;
		break;
	default:
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"Bad AP WEP len %d\n", wlkey.len));
		return -1;
	}

	/* Pass the key to the WL driver.
	 * For security, do not display the key in unencrypted format.
	 */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl addwep -C %d %d ***\n",
		bssidx, wlkey.index));

	/* Uncomment this debug log only when debugging - it shows the key */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"   wlkey.index=%d algo=%d flags=0x%x len=%d key=%s\n",
		wlkey.index, wlkey.algo, wlkey.flags, wlkey.len, wep_key));

	if ((ret = p2pwlu_bssiovar_set(hdl, "wsec_key", bssidx, &wlkey,
		sizeof(wlkey))) < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"add_wep_key: wsec_key error %d\n", ret));
		return ret;
	}
	return ret;
}

static int
p2papi_del_wep_key(p2papi_instance_t* hdl, int key_index)
{
	int ret = 0;
	wl_wsec_key_t wlkey;
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];

	memset(&wlkey, 0, sizeof(wlkey));
	wlkey.index = key_index;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl rmwep -C %d %u\n",
		bssidx, wlkey.index));
	ret = p2pwlu_bssiovar_set(hdl, "wsec_key", bssidx, &wlkey, sizeof(wlkey));
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"apply_ap_wep: rm wsec_key error %d\n", ret));
	}
	return ret;
}

static int
p2papi_apply_ap_wep_keys(p2papi_instance_t* hdl, uint16 in_wepIndex)
{
	int ret = 0;
	char *wep_key;
	int i;

	if (in_wepIndex >= 4) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "Bad WEP index %d\n",
			in_wepIndex));
		return -1;
	}


	/* Add the primary key first */
	wep_key = (char*) hdl->ap_config.WEPKey[in_wepIndex];
	p2papi_add_wep_key(hdl, in_wepIndex, wep_key, TRUE);

	/* Add/del the remaining WEP keys */
	for (i = 0; i < 4; i++) {
		if (i != in_wepIndex) {
			wep_key = (char*) hdl->ap_config.WEPKey[i];
			if (wep_key[0] == '\0') {
				ret = p2papi_del_wep_key(hdl, i);
			} else {
				ret = p2papi_add_wep_key(hdl, i, wep_key, FALSE);
			}
			if (ret != 0)
				return ret;
		}
	}

	return ret;
}
#endif /* P2PAPI_USE_IDSUP */

/* Apply security settings to the soft AP.
 * Note: for WEP, the 4 WEP keys are obtained from hdl->ap_config and not
 * from the in_nwKey parameter.
 */
int
p2papi_common_apply_ap_security(p2papi_instance_t* hdl, char in_ssid[],
	brcm_wpscli_authtype in_authType, brcm_wpscli_encrtype in_encrType,
	char in_nwKey[], uint16 in_wepIndex)
{
	int ret = 0;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	uint8 wsec = 0;
	P2PWL_HDL wl;
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];
#if P2PAPI_USE_IDAUTH
	wsec_pmk_t pmk;
#endif

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	/* get auth */
	auth = (in_authType == BRCM_WPS_AUTHTYPE_SHARED) ? 1 : 0;

	/* get wpa_auth */
	if (in_authType == BRCM_WPS_AUTHTYPE_WPAPSK)
		wpa_auth |= WPA_AUTH_PSK;
	else if (in_authType == BRCM_WPS_AUTHTYPE_WPA2PSK)
		wpa_auth |= WPA2_AUTH_PSK;
	else if (in_authType == BRCM_WPS_AUTHTYPE_WPAPSK_WPA2PSK)
		wpa_auth |= WPA_AUTH_PSK | WPA2_AUTH_PSK;

	/* get wsec */
	if (in_encrType == BRCM_WPS_ENCRTYPE_WEP)
		wsec |= WEP_ENABLED;
	else if (in_encrType == BRCM_WPS_ENCRTYPE_TKIP)
		wsec |= TKIP_ENABLED;
	else if (in_encrType == BRCM_WPS_ENCRTYPE_AES)
		wsec |= AES_ENABLED;
	else if (in_encrType == BRCM_WPS_ENCRTYPE_TKIP_AES)
		wsec |= TKIP_ENABLED | AES_ENABLED;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"apply_ap_sec: ssid=%.*s auth=%d wauth=%d wsec=%d wepix=%d\n",
		DOT11_MAX_SSID_LEN, in_ssid, auth, wpa_auth, wsec, in_wepIndex));
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"            : nwKey=%s\n", in_nwKey));
#endif

	/* set infrastructure mode */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl infra %d\n", infra));
	ret = p2posl_wl_ioctl_bss(wl, WLC_SET_INFRA, &infra, sizeof(int), TRUE, bssidx);
	if (ret < 0) {
		P2PERR1("apply_ap_sec: infra error %d\n", ret);
		return ret;
	}

	/* set mac-layer auth */
	ret = p2pwlu_bssiovar_setint(hdl, "auth", bssidx, auth);
	if (ret < 0) {
		P2PERR1("apply_ap_sec: auth error %d\n", ret);
		return ret;
	}

	/* Allow open WPS joins even though we have security applied */
	if (hdl->use_wps) {
		wsec |= SES_OW_ENABLED;
	}

	/* set wsec */
	ret = p2pwlu_bssiovar_setint(hdl, "wsec", bssidx, wsec);
	if (ret < 0) {
		P2PERR1("apply_ap_sec: wsec error %d\n", ret);
		return ret;
	}

	/* if WPA or WPA2, set eap_restrict to 1 */
	if ((wpa_auth & WPA_AUTH_PSK) || (wpa_auth & WPA2_AUTH_PSK)) {
		ret = p2pwlu_bssiovar_setint(hdl, "eap_restrict", bssidx, 1);
		if (ret < 0) {
			P2PERR1("apply_ap_sec: eap_restrict error %d\n", ret);
			return ret;
		}
	}

	/* set upper-layer auth */
	ret = p2pwlu_bssiovar_setint(hdl, "wpa_auth", bssidx, wpa_auth);
	if (ret < 0) {
		P2PERR1("apply_ap_sec: wpa_auth error %d\n", ret);
		return ret;
	}

	/* If any encryption is enabled, set wsec_restrict */
	if (wsec != 0) {
		ret = p2pwlu_bssiovar_setint(hdl, "wsec_restrict", bssidx, 1);
		if (ret < 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"apply_ap_sec: wl wsec_restrict - error %d\n", ret));
		}
	}

#if P2PAPI_USE_IDAUTH
	/* If WEP, get the WEP keys and pass them to the WL driver */
	if ((wsec & WEP_ENABLED) != 0) {
		ret = p2papi_apply_ap_wep_keys(hdl, in_wepIndex);
		if (ret != 0)
			return ret;
	} else if ((wsec & ~SES_OW_ENABLED) != 0) {
		/* Set the "auth_wpa" iovar to 1 before "set_pmk" - needed for some
		 * driver versions.  This iovar is different from and unrelated to the
		 * "wpa_auth" iovar.
		 */
		ret = p2pwlu_bssiovar_setint(hdl, "auth_wpa", bssidx, 1);
		if (ret < 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"NOTE: this ioctl error is normal and can be ignored.\n"));
		}

		memset(&pmk, 0, sizeof(wsec_pmk_t));
		if (strlen(in_nwKey) < WSEC_MIN_PSK_LEN ||
			strlen(in_nwKey) > WSEC_MAX_PSK_LEN) {
			P2PERR2("passphrase must be between %d and %d characters long\n",
				WSEC_MIN_PSK_LEN, WSEC_MAX_PSK_LEN);
			return -1;
		}
		pmk.key_len = (uint32) strlen(in_nwKey);
		pmk.flags = WSEC_PASSPHRASE;
		strncpy((char *)pmk.key, in_nwKey, strlen(in_nwKey));

#if P2PAPI_ENABLE_DEBUG_SHOWKEY
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s set_pmk %s  (bssidx=%d)\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, bssidx),
			in_nwKey, bssidx));
#else
		/* For security, do not display the key in unencrypted format. */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s set_pmk ***  (bssidx=%d)\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, bssidx), bssidx));
#endif
		ret = p2posl_wl_ioctl_bss(wl, WLC_SET_WSEC_PMK, &pmk, sizeof(pmk),
			TRUE, bssidx);
		if (ret < 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "---wl set_pmk: error %d\n", ret));
			return ret;
		}
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "apply_ap_sec: no wsec\n"));
	}

	/* set BSS ssid - this requires the following sequence:
	 * - bring down the bss
	 * - set the SSID iovar for the bss
	 * - bring up the bss
	 */

#else
	/* user an external authenticator */
	printf("p2papi_common_apply_ap_security: bsscfg index %d ifname %s\n",
		bssidx, p2papi_osl_get_ap_mode_ifname(hdl));

	hdl->ext_auth_supp_ctx = hslif_init_ctx();
	if (hdl->ext_auth_supp_ctx == NULL) {
		P2PERR("p2papi_open: failed to init external auth/supp ctx\n");
		return BCMP2P_INVALID_HANDLE;
	}

	ret = hslif_set_cfg(hdl->ext_auth_supp_ctx,
		p2papi_osl_get_ap_mode_ifname(hdl),	/* ifname */
		bssidx,					/* bsscfg index */
		1,						/* authenticator */
		in_ssid, wpa_auth,
		4,
		in_nwKey);
#endif /* P2PAPI_USE_IDAUTH */

	return ret;
}

static int
p2papi_common_join(p2papi_instance_t *hdl, char *ssid, size_t ssid_len)
{
	int ret = -1;
	int i, j;

	for (i = 0; i < WLAN_JOIN_ATTEMPTS; i++) {
		/* initiate join */
		p2pwlu_join(hdl, ssid, ssid_len);

		/* poll for the results until we got BSSID */
		for (j = 0; j < WLAN_POLLING_JOIN_COMPLETE_ATTEMPTS; j++) {

			/* join time */
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_STA_JOINED_POLL, 100);

			/* exit if associated */
			if (p2pwlu_is_associated(hdl)) {
				ret = 0;
				goto exit;
			}
		}
	}

exit:
	return ret;
}

static int
p2papi_common_join_bssid(p2papi_instance_t *hdl, char *ssid, size_t ssid_len,
	struct ether_addr *bssid, int num_chanspec, chanspec_t *chanspec)
{
	int ret = -1;
	int i, j;
	uint32 join_scan_ms;
	int max_poll_complete_attempts;
	int poll_complete_interval = 100; /* in ms */


	if (num_chanspec == 1)
		join_scan_ms = P2PWL_JOIN_SCAN_PASSIVE_TIME_LONG;
	else
		join_scan_ms = P2PWL_JOIN_SCAN_PASSIVE_TIME;

	for (i = 0; i < WLAN_JOIN_ATTEMPTS; i++) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_common_join_bssid: attempt %d, %d channels, bssidx=%d\n",
			i, num_chanspec, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]));

		/* initiate join */
		p2pwlu_join_bssid(hdl, ssid, ssid_len, bssid, num_chanspec, chanspec);

		max_poll_complete_attempts = WLAN_POLLING_JOIN_COMPLETE_ATTEMPTS +
			(join_scan_ms * num_chanspec) / poll_complete_interval;
		/* poll for the results until we got BSSID */
		for (j = 0; j < max_poll_complete_attempts; j++) {

			/* join time */
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_STA_JOINED_POLL, poll_complete_interval);

			/* exit if associated */
			if (p2pwlu_is_associated(hdl)) {
				ret = 0;
				goto exit;
			}
		}
	}

exit:
	return ret;
}

int
p2papi_common_do_sta_join(p2papi_instance_t* hdl, char in_ssid[],
	struct ether_addr *in_bssid)
{
	int ret = -1;
	bool join_bssid = false;
	int ssid_len;
	char *ssid;
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];

	/* figure out how to do the join */
	/* if 'in_ssid' is specified and if 'in_bssid' is not specified */
	/* use 'in_ssid' join, otherwise use 'join with parameters */
	ssid_len = strlen(in_ssid);
	if (ssid_len > 0 && in_bssid == NULL)
	{
		join_bssid = false; /* or use 'ether_bcast' for bssid ? */
		ssid = in_ssid;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_common_do_sta_join: ssid=%s, bssidx=%d\n", ssid, bssidx));
	}
	else
	{
		join_bssid = true;
		if (ssid_len == 0)
		{
			ssid = "DIRECT-";
			ssid_len = strlen(ssid);
		}
		else
			ssid = in_ssid;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_common_do_sta_join: ssid=%s bssidx=%d\n",
			ssid, bssidx));
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"    bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
			in_bssid->octet[0], in_bssid->octet[1], in_bssid->octet[2],
			in_bssid->octet[3], in_bssid->octet[4], in_bssid->octet[5]));
	}

	hdl->is_connection_secured = FALSE;

	if (!join_bssid) {
		if (p2papi_common_join(hdl, ssid, ssid_len) == 0)
			hdl->is_connected = TRUE;
	}
	else {
		/* attempt first channel then remaining channel list */
		if (p2papi_common_join_bssid(hdl, ssid, ssid_len, in_bssid,
			1, hdl->join_chanspec) == 0)
			hdl->is_connected = TRUE;
		else if (p2papi_common_join_bssid(hdl, ssid, ssid_len, in_bssid,
			hdl->num_join_chanspec - 1, &hdl->join_chanspec[1]) == 0)
			hdl->is_connected = TRUE;
	}

	if (hdl->is_connected) {
		hdl->is_connecting = FALSE;
		hdl->disconnect_detected = FALSE;
		P2PLOG("p2papi_common_do_sta_join: STA is connected\n");
		ret = 0;
	}

	return ret;
}

int
p2papi_cleanup_ap_security(p2papi_instance_t* hdl)
{
	int ret = 0;
	wl_wsec_key_t wlkey;
	wsec_pmk_t pmk;
	P2PWL_HDL wl;
	int i;
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	if (bssidx == 0)
	{
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_cleanup_ap_sec: NOP (connection-bsscfg=%d is invalid)\n",
			bssidx));
		return 0;
	}

#if !P2PAPI_USE_IDAUTH
	/* Deinit external security context. */
	hslif_deinit_ctx(hdl->ext_auth_supp_ctx);
	hdl->ext_auth_supp_ctx = NULL;
#endif   /* !P2PAPI_USE_IDAUTH */

	if (hdl->credentials.encrType == BRCM_WPS_ENCRTYPE_WEP) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_cleanup_ap_sec: WEP, ix=%d\n",
			hdl->credentials.wepIndex));
		memset(&wlkey, 0, sizeof(wl_wsec_key_t));
		/* wlkey.len 0 means remove the key */
		/* wlkey.ea 0 means remove the default key */
/*		wlkey.index = hdl->credentials.wepIndex - 1; */

		for (i = 0; i < 4; i++) {
			wlkey.index = i;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl rmwep -C %d %u\n",
				bssidx, wlkey.index));
			if ((ret = p2pwlu_bssiovar_set(hdl, "wsec_key", bssidx, &wlkey,
				sizeof(wlkey))) < 0) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"cleanup_ap_sec: wsec_key error %d\n", ret));
			}
		}

		/* Clear wsec_restrict */
		p2pwlu_set_wsec_restrict(hdl, 0);
	}
	else if (hdl->credentials.encrType == BRCM_WPS_ENCRTYPE_TKIP ||
		hdl->credentials.encrType == BRCM_WPS_ENCRTYPE_AES ||
		hdl->credentials.encrType == BRCM_WPS_ENCRTYPE_TKIP_AES) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_cleanup_ap_sec: WPA/WPA2\n"));
		memset(&pmk, 0, sizeof(wsec_pmk_t));
		pmk.key_len = 8;
		pmk.flags = WSEC_PASSPHRASE;

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s set_pmk <zero len key>\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, bssidx)));
		ret = p2posl_wl_ioctl_bss(wl, WLC_SET_WSEC_PMK, &pmk, sizeof(pmk),
			TRUE, bssidx);
		if (ret < 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "---wl set_pmk: error %d\n", ret));
			return ret;
		}

		if ((ret = p2pwlu_bssiovar_setint(hdl, "eap_restrict",
			bssidx, 0)) < 0) {
			P2PERR1("cleanup_ap_sec: eap_restrict error %d\n", ret);
			return ret;
		}

	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "cleanup_ap_sec: no security\n"));
	}

	return ret;
}


/* Create the AP mode BSSCFG */
int
p2papi_create_ap_bss(p2papi_instance_t* hdl)
{
	int ret = 0;
	P2PWL_HDL wl;
	int bssidx = 0;

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_create_ap_bss enter, ssid=%s\n",
		hdl->credentials.ssid));

	/* Do any OS-specific actions needed to create the P2P connection BSS */
	ret = p2papi_osl_create_bss(hdl, TRUE);
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_create_ap_bss: osl_create_bss failed\n"));
		goto fail;
	}
	bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_create_ap_bss: bssidx=%u (%u) ssid=%s\n",
		bssidx, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], hdl->credentials.ssid));

	/* Set the BSS's ssid - this can be done only when the BSS is down */
	if (hdl->enable_p2p) {
		(void) p2pwlu_set_ssid(hdl, (uint8*)hdl->credentials.ssid,
			strlen(hdl->credentials.ssid));
	} else {
		(void) p2pwlu_set_ssid(hdl, hdl->fname_ssid, hdl->fname_ssid_len);
	}

	/* Set the "closednet" WL driver iovar based on whether a hidden SSID
	 * was specified.
	 */
	(void) p2pwl_bssiovar_setint(wl, "closednet", bssidx,
		(hdl->ap_config.hideSSID) ? 1 : 0);

	/* For non-P2P SoftAP mode, do a delay to wait for the WLC_E_LINK event
	 * which carries the network interface name.
	 */
	if (!hdl->enable_p2p) {
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_WAIT_BSS_START, 600);
	}


fail:
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_create_ap_bss: exit, ret=%d conn-bssidx=%d\n", ret, bssidx));
	return ret;
}

/* Bring down and delete the AP mode BSS */
int
p2papi_delete_ap_bss(p2papi_instance_t* hdl)
{
	int result;
	BCMP2P_BOOL is_up;
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_del_ap_bss: enter, conn-bssidx=%d\n", bssidx));

	/* Do any OS-specific actions needed prior to bringing down the BSS */
	p2papi_osl_ap_mode_ifdown(hdl);

	/* Bring down the connection BSS */
	result = p2pwlu_bss(hdl, FALSE);
	if (result != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_del_ap_bss: bss teardown failed: %d\n", result));
	}
	is_up = p2pwlu_bss_isup(hdl);
	if (is_up)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_del_ap_bss: BSS still up\n"));

	/* Delete the BSS */
	p2papi_osl_delete_bss(hdl, bssidx);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_del_ap_bss: exit, conn-bssidx=%d\n",
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]));
	return 0;
}


/* Create the STA mode BSS */
int
p2papi_create_sta_bss(p2papi_instance_t* hdl)
{
	int ret = 0;
	int bssidx = 0;

	P2PAPI_CHECK_P2PHDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_create_sta_bss enter: idx=%d\n",
		bssidx));

	/* Do any OS-specific actions needed to create the P2P connection BSS */
	ret = p2papi_osl_create_bss(hdl, FALSE);
	if (ret != 0) {
		goto fail;
	}
	bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];

fail:
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_create_sta_bss: exit, ret=%d conn-bssidx=%d\n",
		ret, bssidx));
	return ret;
}

/* Bring down and delete the STA mode BSSCFG */
int
p2papi_delete_sta_bss(p2papi_instance_t* hdl)
{
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];

	P2PAPI_CHECK_P2PHDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_delete_sta_bss\n"));

	/* Forget any saved IEs for this BSSCFG */
	p2papi_reset_saved_p2p_wps_ies(hdl, P2PAPI_BSSCFG_CONNECTION);

	/* Do any OS-specific actions needed prior to bringing down the BSSCFG */
	p2papi_osl_sta_mode_ifdown(hdl);

	/* Delete the BSSCFG */
	p2papi_osl_delete_bss(hdl, bssidx);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_delete_sta_bss exit: conn-bssidx before=%u after=%u\n",
		bssidx, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]));
	return 0;
}


/* Set the soft AP network interface to the DHCP server's hardcoded static IP
 * address.
 */
BCMP2P_BOOL
p2papi_set_ap_ipaddr(p2papi_instance_t* hdl)
{
	BCMP2P_BOOL ret = TRUE;

	if (hdl->ap_config.ip_addr == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_set_ap_ipaddr: not setting AP IP addr\n"));
		return ret;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_set_ap_ipaddr: ipaddr=0x%08x netmask=%08x\n",
		hdl->ap_config.ip_addr, hdl->ap_config.netmask));
	ret = p2papi_osl_set_ap_ipaddr(hdl, hdl->ap_config.ip_addr,
		hdl->ap_config.netmask);
	if (!ret) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_set_ap_ipaddr failed!\n"));
	}

	return ret;
}

static BCMP2P_STATUS
p2papi_set_wmm(p2papi_instance_t* hdl, bool wl_down_allowed)
{
	int old_val = 0;
	int val = 0;
	int old_val_ps = 0;
	int val_ps = 0;
	int result;
	P2PWL_HDL	wl;
	BCMP2P_BOOL is_up;

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	/* Get the existing WMM setting in the driver */
	result = p2pwl_iovar_getint_bss(wl, "wme", &old_val, 0);
	if (result != 0) {
		BCMP2PLOG((BCMP2P_LOG_WARN, TRUE, "'wl wme' read failed.\n"));
		hdl->warning = BCMP2P_WARN_IOCTL_NOT_SUPPORTED;
		return BCMP2P_ERROR;
	}

	/* Get the existing WMM power save setting in the driver */
	result = p2pwl_iovar_getint_bss(wl, "wme_apsd", &old_val_ps, 0);
	if (result != 0) {
		BCMP2PLOG((BCMP2P_LOG_WARN, TRUE, "'wl wme_apsd' read failed.\n"));
		hdl->warning = BCMP2P_WARN_IOCTL_NOT_SUPPORTED;
		return BCMP2P_ERROR;
	}

	/* if the driver's WMM setting already matches the required setting in the
	 * softAP configuration data, do nothing and return.
	 */
	val = hdl->ap_config.enableWMM ? 1 : 0;
	val_ps = hdl->ap_config.enableWMM_PS ? 1 : 0;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_set_wmm: old wme=%d apsd=%d, new wme=%d apsd=%d\n",
		old_val, old_val_ps, val, val_ps));
	if (val == old_val && val_ps == old_val_ps)
		return BCMP2P_SUCCESS;

	/* If the WL driver is already up then we cannot change the WMM settings
	 * because that requires bringing down the driver.
	 */
	/* Bring down WL driver before we can change WMM settings. */
	is_up = p2pwlu_isup(hdl);
	if (is_up) {
		if (wl_down_allowed) {
			result = p2pwlu_down(hdl);
			if (result != 0) {
				BCMP2PLOG((BCMP2P_LOG_WARN, TRUE,
					"Setting WMM failed due to 'wl down' fail.\n"));
				hdl->warning = BCMP2P_WARN_DRIVER_ALREADY_UP;
				return BCMP2P_ERROR;
			}
		} else {
			BCMP2PLOG((BCMP2P_LOG_WARN, TRUE,
				"Setting WMM failed - 'wl down' not allowed.\n"));
			hdl->warning = BCMP2P_WARN_DRIVER_ALREADY_UP;
			return BCMP2P_ERROR;
		}
	}

	if (val != old_val) {
		/* Set the driver's WMM setting */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl wme %u\n", val));
		result = p2pwl_iovar_set_bss(wl, "wme", &val, sizeof(val), 0);
		if (result != 0) {
			BCMP2PLOG((BCMP2P_LOG_WARN, TRUE, "Enabling WMM failed.\n"));
			hdl->warning = BCMP2P_WARN_IOCTL_NOT_SUPPORTED;
			return BCMP2P_ERROR;
		}
	}

	if (val_ps != old_val_ps) {
		/* Set the driver's WMM power save setting */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl wme_apsd %u\n", val_ps));
		result = p2pwl_iovar_set_bss(wl, "wme_apsd", &val_ps, sizeof(val_ps),
			0);
		if (result != 0) {
			BCMP2PLOG((BCMP2P_LOG_WARN, TRUE, "Enabling WMM power save failed.\n"));
			hdl->warning = BCMP2P_WARN_IOCTL_NOT_SUPPORTED;
			return BCMP2P_ERROR;
		}
	}

	return BCMP2P_SUCCESS;
}

/* Handler for WPSCLI status callbacks */
static brcm_wpscli_status
p2papi_proc_wpscli_status(brcm_wpscli_request_ctx cb_context,
	brcm_wpscli_status status, brcm_wpscli_status_cb_data cb_data)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)cb_context;

	if (status == WPS_STATUS_PROTOCOL_START_EXCHANGE) {
		hdl->is_wps_enrolling = TRUE;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_proc_wpscli_status: is_wps_enrolling, is_prov=1\n"));
		hdl->is_provisioning = TRUE;
	} else if (status == WPS_STATUS_PROTOCOL_END_EXCHANGE) {
		hdl->is_wps_enrolling = FALSE;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_proc_wpscli_status: !is_wps_enrolling, is_prov=0\n"));
		hdl->is_provisioning = FALSE;
	}

	if (hdl->is_wps_enrolling != hdl->is_wps_enrolling_old) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_proc_wpscli_status: enroll state change, update IEs\n"));
		p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_DEVICE);
		p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_CONNECTION);
		hdl->is_wps_enrolling_old = hdl->is_wps_enrolling;
	}

	return status;
}

/* Create the soft AP BSSCFG. Do not bring it up yet. */
int
p2papi_softap_enable(p2papi_instance_t* hdl, BCMP2P_BOOL is_wps_pbc_mode)
{
	int result;
	int val = 0;
	P2PWL_HDL	wl;
	BCMP2P_BOOL is_up;
	int bssidx = 0;

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_softap_enable: is_wps_pbc=%u\n",
		is_wps_pbc_mode));

	hdl->ap_security_applied = FALSE;
	hdl->is_in_softap_cleanup = FALSE;

	/* Set the driver's WMM and WMM power save to match our softAP
	 * configuration data.  If this fails, do not return an error.  This is
	 * not a fatal error and the soft AP can still operate.
	 */
	if (!hdl->enable_p2p)
		result = p2papi_set_wmm(hdl, FALSE);

	/* Bring up the driver if it is not up already */
	is_up = p2pwlu_isup(hdl);
	if (!is_up) {
		result = p2pwlu_up(hdl);
		if (result != 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl up' failed with %d\n",
				result));
			return result;
		}
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_WAIT_WL_UP, 100);
		is_up = p2pwlu_isup(hdl);
	}

	/* Create the AP mode BSSCFG */
	result = p2papi_create_ap_bss(hdl);
	if (result != 0) {
		return result;
	}
	bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];

	/* Set the max # of associated clients based on the softAP config data */
	if (hdl->ap_config.maxClients > BCMP2P_MAX_SOFTAP_CLIENTS ||
		hdl->ap_config.maxClients == 0) {
		hdl->ap_config.maxClients = BCMP2P_MAX_SOFTAP_CLIENTS;
	}
	val = (int) hdl->ap_config.maxClients;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s maxassoc %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		val));
	result = p2pwl_iovar_set_bss(wl, "maxassoc", &val, sizeof(val), 0);
	if (result != 0) {
		/* Debug - see if the driver supports the "maxassoc" iovar */
		result = p2pwl_iovar_get_bss(wl, "maxassoc", &val, sizeof(val), 0);
		/* Do not return an error here.  Some driver builds do not support
		 * the "maxassoc" iovar.
		 */
		/* return result; */
	}

#if P2PAPI_ENABLE_WPS
	if (hdl->use_wps) {
		brcm_wpscli_status status;
		char *if_name = p2papi_osl_get_ap_mode_ifname(hdl);

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_softap_enable: brcm_wpscli_open(%s)\n", if_name));
		status = brcm_wpscli_open(if_name, BRCM_WPSCLI_ROLE_SOFTAP, (void*)hdl,
			(brcm_wpscli_status_cb)p2papi_proc_wpscli_status);

		if (status == WPS_STATUS_SUCCESS) {
		} else {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_softap_enable: brcm_wpscli_open(%s) failed.\n", if_name));
		}
	}
#endif /* P2PAPI_ENABLE_WPS */

	/* Clear the group clients list */
	hdl->assoclist_count = 0;
	memset(hdl->assoclist, 0, sizeof(hdl->assoclist));

	return 0;
}

int
p2papi_softap_disable_nolock(p2papi_instance_t* hdl)
{
	int result = 0;

	P2PAPI_CHECK_P2PHDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_softap_disable\n"));

#if P2PAPI_ENABLE_WPS
	if (hdl->use_wps) {
		/* Remove the WPS IE from beacons and probe responses */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_softap_disable: brcm_wpscli_softap_disable_wps\n"));
		(void) brcm_wpscli_softap_disable_wps();

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_softap_disable: brcm_wpscli_close\n"));
		(void) brcm_wpscli_close();
	}
#endif /* P2PAPI_ENABLE_WPS */

	/* Clean up encryption keys */
	p2papi_cleanup_ap_security(hdl);

	/* Forget any saved IEs for this BSSCFG */
	p2papi_reset_saved_p2p_wps_ies_nolock(hdl, P2PAPI_BSSCFG_CONNECTION);

	/* Bring down and delete the AP mode BSS */
	result = p2papi_delete_ap_bss(hdl);
	hdl->ap_security_applied = FALSE;
	hdl->ap_ready = FALSE;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_softap_disable: end\n"));
	return result;
}
int
p2papi_softap_disable(p2papi_instance_t* hdl)
{
	int ret;

	P2PAPI_DATA_LOCK(hdl);
	ret = p2papi_softap_disable_nolock(hdl);
	P2PAPI_DATA_UNLOCK(hdl);
	return ret;
}

/* Enable/Disable P2P functionality for a Soft AP */
void
p2papi_enable_p2p(p2papi_instance_t* hdl, BCMP2P_BOOL on_off)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return;

	hdl->enable_p2p = on_off ? true : false;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_enable_p2p: %d\n",
		hdl->enable_p2p));
}

void
p2papi_enable_wps(p2papi_instance_t* hdl, BCMP2P_BOOL on_off)
{
	hdl->ap_config.WPSConfig.wpsEnable = on_off ? true : false;
	hdl->use_wps = hdl->ap_config.WPSConfig.wpsEnable;
}


/* Deauthenticate a STA */
BCMP2P_STATUS
p2papi_deauth_sta(p2papi_instance_t* hdl, unsigned char* sta_mac)
{
	int ret;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	ret = p2pwlu_deauth_sta(hdl, sta_mac, DOT11_RC_UNSPECIFIED);
#ifndef SOFTAP_ONLY
	p2papi_del_peer_info(hdl, (struct ether_addr*)sta_mac);
#endif /* SOFTAP_ONLY */
	return (ret == 0) ? BCMP2P_SUCCESS : BCMP2P_ERROR;
}

/* Get a list of associated STAs */
BCMP2P_STATUS
p2papi_get_assoclist(p2papi_instance_t* hdl,
	unsigned int in_maclist_max, struct ether_addr *io_maclist,
	unsigned int *out_maclist_count)
{
	BCMP2P_STATUS ret;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	/* Get the assoclist from the WL driver */
	*out_maclist_count = 0;
	ret = (BCMP2P_STATUS) p2pwlu_get_assoclist(hdl, in_maclist_max,
		io_maclist, out_maclist_count);

	if (ret == BCMP2P_NOT_ENOUGH_SPACE) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_get_assoclist: no more space, list truncated\n"));
		ret = BCMP2P_SUCCESS;
	}
	return ret;
}

/* Get the current operating channel number */
BCMP2P_STATUS
p2papi_get_channel(p2papi_instance_t* hdl, BCMP2P_CHANNEL *channel)
{
	int ret;
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];
	chanspec_t chspec;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	ret = p2pwlu_get_chanspec(hdl, &chspec, bssidx);
	p2papi_chspec_to_channel(chspec, channel);
	return (ret == 0) ? BCMP2P_SUCCESS : BCMP2P_ERROR;
}

/*
 * Ioctl/iovar functions.
 */
BCMP2P_STATUS
p2papi_ioctl_get(p2papi_instance_t* hdl, int cmd, void *buf, int len,
	int bssidx)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (p2pwlu_ioctl_get_bss(hdl, cmd, buf, len, bssidx))
		return BCMP2P_ERROR;
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_ioctl_set(p2papi_instance_t* hdl, int cmd, void *buf, int len,
	int bssidx)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (p2pwlu_ioctl_set_bss(hdl, cmd, buf, len, bssidx))
		return BCMP2P_ERROR;
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_iovar_get(p2papi_instance_t* hdl, const char *iovar, void *outbuf,
	int len)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (p2pwlu_iovar_get(hdl, iovar, outbuf, len))
		return BCMP2P_ERROR;
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_iovar_set(p2papi_instance_t* hdl, const char *iovar, void *param, int paramlen)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (p2pwlu_iovar_set(hdl, iovar, param, paramlen))
		return BCMP2P_ERROR;
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_iovar_integer_get(p2papi_instance_t* hdl, const char *iovar, int *pval)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (p2pwlu_iovar_getint(hdl, iovar, pval))
		return BCMP2P_ERROR;
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_iovar_integer_set(p2papi_instance_t* hdl, const char *iovar, int val)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (p2pwlu_iovar_setint(hdl, iovar, val))
		return BCMP2P_ERROR;
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_iovar_buffer_get(p2papi_instance_t* hdl, const char *iovar, void *param,
	int paramlen, void *bufptr, int buflen)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (p2pwlu_iovar_getbuf(hdl, iovar, param, paramlen, bufptr, buflen))
		return BCMP2P_ERROR;
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_iovar_buffer_set(p2papi_instance_t* hdl, const char *iovar, void *param,
	int paramlen, void *bufptr, int buflen)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (p2pwlu_iovar_setbuf(hdl, iovar, param, paramlen, bufptr, buflen))
		return BCMP2P_ERROR;
	return BCMP2P_SUCCESS;
}

/* Get the SoftAP's IP address */
BCMP2P_STATUS
p2papi_get_ip_addr(p2papi_instance_t* hdl,
	BCMP2P_IP_ADDR *out_ipaddr, BCMP2P_IP_ADDR *out_netmask)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	*out_ipaddr = hdl->ap_config.ip_addr;
	*out_netmask = hdl->ap_config.netmask;
	return BCMP2P_SUCCESS;
}


/* Sets the mode of the MAC filter list */
BCMP2P_STATUS
p2papi_set_maclist_mode(p2papi_instance_t* hdl, BCMP2P_MAC_FILTER_MODE mode)
{
	P2PWL_HDL wl;
	int ret;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	ret = p2pwl_set_macmode(wl, (int)mode,
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
	return (ret == 0) ? BCMP2P_SUCCESS : BCMP2P_ERROR;
}

/* Set the MAC filter's MAC address list */
BCMP2P_STATUS
p2papi_set_maclist(p2papi_instance_t* hdl,
	BCMP2P_ETHER_ADDR *macList, BCMP2P_UINT32 macListCount)
{
	P2PWL_HDL wl;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	/* Lock our instance data because we will be writing its ioctl buffer */
	P2PAPI_DATA_LOCK(hdl);
	(void) p2pwl_set_maclist(wl, P2PAPI_IOCTL_BUF(hdl), WLC_IOCTL_MAXLEN,
		(struct ether_addr*)macList, macListCount,
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
	P2PAPI_DATA_UNLOCK(hdl);

	return BCMP2P_SUCCESS;
}

/* Get the current MAC filter list and filter mode */
BCMP2P_STATUS
p2papi_get_maclist(p2papi_instance_t* hdl,
	BCMP2P_UINT32 macListMax, BCMP2P_ETHER_ADDR *macList,
	BCMP2P_UINT32 *macListCount, BCMP2P_MAC_FILTER_MODE *mode)
{
	P2PWL_HDL wl;
	int val;
	int ret;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	ret = p2pwl_get_macmode(wl, &val, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
	if (ret == 0)
		*mode = (BCMP2P_MAC_FILTER_MODE)val;
	else
		return BCMP2P_ERROR;

	/* Lock our instance data because we will be writing its ioctl buffer */
	P2PAPI_DATA_LOCK(hdl);
	ret = p2pwl_get_maclist(wl, P2PAPI_IOCTL_BUF(hdl), WLC_IOCTL_MAXLEN,
		macListMax, (struct ether_addr*)macList, macListCount,
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
	P2PAPI_DATA_UNLOCK(hdl);

	return BCMP2P_SUCCESS;
}

/* Generate our P2P Device Address and P2P Interface Address from our primary
 * MAC address.
 */
void
p2papi_generate_bss_mac(bool same_int_dev_addrs,
	struct ether_addr *in_primary_mac,
	struct ether_addr *out_dev_addr, struct ether_addr *out_int_addr)
{
	/* Generate the P2P Device Address.  This consists of the device's
	 * primary MAC address with the locally administered bit set.
	 */
	memcpy(out_dev_addr, in_primary_mac, sizeof(*out_dev_addr));
	out_dev_addr->octet[0] |= 0x02;

	/* Generate the P2P Interface Address.  If the discovery and connection
	 * BSSCFGs need to simultaneously co-exist, then this address must be
	 * different from the P2P Device Address.
	 */
	memcpy(out_int_addr, out_dev_addr, sizeof(*out_int_addr));
	if (!same_int_dev_addrs) {
		/* @@@TEMP:
		 */
		out_int_addr->octet[4] ^= 0x80;
	}
}

/* Get the OS network interface name of the connected P2P connection. */
char*
p2papi_get_netif_name(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return "";
	return hdl->conn_ifname;
}

/* Get our randomly generated P2P Group Owner name */
char*
p2papi_get_go_name(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return "";
	return hdl->credentials.ssid;
}

BCMP2P_STATUS
p2papi_get_go_credentials(p2papi_instance_t* hdl,
	BCMP2P_UINT8* outSSID, BCMP2P_UINT8* outKeyWPA, BCMP2P_UINT8* outPassphrase)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	if (outSSID) {
		memcpy(outSSID, hdl->credentials.ssid, BCMP2P_MAX_SSID_LEN);
	}
	if (outKeyWPA) {
		strncpy((char*)outKeyWPA, hdl->credentials.nwKey,
			sizeof(hdl->credentials.nwKey));
	}
	if (outPassphrase) {
		if (hdl->is_p2p_group)
			strncpy((char*)outPassphrase, hdl->passphrase,
				sizeof(hdl->passphrase));
		else
			/* No passphrase when not a GO */
			memset(outPassphrase, 0, 1);
	}
	return BCMP2P_SUCCESS;
}

/* Get the P2P Device Address of the GO we are connected to */
struct ether_addr*
p2papi_get_go_dev_addr(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return &p2papi_null_eth_addr;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_get_go_dev_addr: is_conn=%d is_ap=%d\n",
		hdl->is_connected, hdl->is_ap));
	if (!hdl->is_connected || hdl->is_ap) {
		return &p2papi_null_eth_addr;
	}

	return &hdl->peer_dev_addr;
}


BCMP2P_STATUS
p2papi_enable_persistent(p2papi_instance_t* hdl, BCMP2P_BOOL enable)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_enable_persistent: enable=%d\n", enable));
	hdl->persistent_grp = enable;
	return BCMP2P_SUCCESS;
}

BCMP2P_BOOL
p2papi_is_persistent_enabled(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	return hdl->persistent_grp;
}

BCMP2P_BOOL
p2papi_in_persistent_group(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	return hdl->in_persist_grp;
}

/* Get our P2P Device Address */
struct ether_addr*
p2papi_get_p2p_dev_addr(void *handle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) handle;
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return &p2papi_null_eth_addr;

	return &hdl->p2p_dev_addr;
}

/* Get our P2P Interface Address */
struct ether_addr*
p2papi_get_p2p_int_addr(void *handle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) handle;
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return &p2papi_null_eth_addr;

	return &hdl->conn_ifaddr;
}

/* Get peer P2P Device Address */
struct ether_addr*
p2papi_get_peer_dev_addr(void *handle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) handle;
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return &p2papi_null_eth_addr;

	return &hdl->peer_dev_addr;
}

/* Get peer P2P Interface Address */
struct ether_addr*
p2papi_get_peer_int_addr(void *handle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) handle;
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return &p2papi_null_eth_addr;

	return &hdl->peer_int_addr;
}

/* Enable/Disable WPS PBC overlap detection */
int
p2papi_enable_pbc_overlap(void *handle, BCMP2P_BOOL enable)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) handle;
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return -1;

	hdl->disable_pbc_overlap = !enable;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_enable_pbc_overlap: disable_pbc_overlap=%d\n",
		hdl->disable_pbc_overlap));

	/* Update the driver event masks */
	if (hdl->disable_pbc_overlap) {
		hdl->event_mask[WLC_E_PROBREQ_MSG/8] &= ~(1 << (WLC_E_PROBREQ_MSG % 8));
		hdl->event_mask_prb[WLC_E_PROBREQ_MSG/8] &=
			~(1 << (WLC_E_PROBREQ_MSG % 8));
	} else {
		hdl->event_mask[WLC_E_PROBREQ_MSG/8] |= 1 << (WLC_E_PROBREQ_MSG % 8);
		hdl->event_mask_prb[WLC_E_PROBREQ_MSG/8] |=
			1 << (WLC_E_PROBREQ_MSG % 8);
	}

	/* Apply the updated driver event mask */
	if (p2papi_enable_driver_events(hdl, FALSE) != BCME_OK) {
		P2PERR("p2papi_enable_pbc_overlap: enable events error\n");
		return BCMP2P_FAIL_TO_ENABLE_EVENTS;
	}
	return 0;
}

/* Conditional sleep - sleep while cancel is false
 * Returns true if sleep cancelled.
 */
bool
p2papi_conditional_sleep_ms(P2PAPI_OSL_SLEEP_REASON reason, bool *cancel, uint32 ms)
{
	uint32 resolution = 25; /* ms */
	uint32 remaining = ms;

	while (!*cancel && remaining > 0) {
		uint32 sleep = remaining < resolution ? remaining : resolution;
		p2papi_osl_sleep_ms(reason, sleep);
		remaining -= sleep;
	}
	return *cancel;
}

/*
 * Set power saving mode
 */
BCMP2P_STATUS
p2papi_set_power_saving_mode(p2papi_instance_t* hdl, int mode)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
	{
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_set_power_saving_mode: Invalid handle 0x%x.\n", hdl));
		return BCMP2P_INVALID_HANDLE;
	}

	if (!hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_set_power_saving_mode: "
			"Connection bss is not up.\n"));
		return BCMP2P_ERROR;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_set_power_saving_mode: mode=%d\n", mode));
	if (p2pwlu_set_PM(hdl, mode, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION])) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_set_power_saving_mode: failed to set mode %d\n", mode));
		return BCMP2P_ERROR;
	}

	return BCMP2P_SUCCESS;
}

/*
 * Get power saving mode
 */
BCMP2P_STATUS
p2papi_get_power_saving_mode(p2papi_instance_t* hdl, int *mode)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (!hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_get_power_saving_mode: "
			"Connection bss is not up.\n"));
		return BCMP2P_ERROR;
	}

	if (p2pwlu_get_PM(hdl, mode, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]) < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_get_power_saving_mode: failed to get mode.\n"));
		return BCMP2P_ERROR;
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_get_power_saving_mode: mode=%d\n", *mode));

	return BCMP2P_SUCCESS;
}

/* enable/disable persistent capability */
BCMP2P_STATUS
p2papi_enable_intra_bss(p2papi_instance_t* hdl,	BCMP2P_BOOL enable)
{
	int val;
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	hdl->is_intra_bss = enable;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_enable_intra_bss: %d\n",
		hdl->is_intra_bss));
	/* set intra-bss distribution */
	val = hdl->is_intra_bss ? 0 : 1;
	val = htod32(val);
	p2pwl_iovar_set_bss(P2PAPI_GET_WL_HDL(hdl), "ap_isolate", &val, sizeof(int),
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);

	p2papi_refresh_ies(hdl);
	return BCMP2P_SUCCESS;
}

/* enable/disable concurrent operation capability */
BCMP2P_STATUS
p2papi_enable_concurrent(p2papi_instance_t* hdl, BCMP2P_BOOL enable)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	hdl->is_concurrent = enable;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_enable_concurrent: %d\n",
		hdl->is_concurrent));
	p2papi_refresh_ies(hdl);
	return BCMP2P_SUCCESS;
}

#ifndef SOFTAP_ONLY
/* enable/disable P2P invitation capability */
BCMP2P_STATUS
p2papi_enable_invitation(p2papi_instance_t* hdl, BCMP2P_BOOL enable)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	hdl->is_invitation = enable;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_enable_invitation: %d\n",
		hdl->is_invitation));
	return BCMP2P_SUCCESS;
}

/* enable/disable service discovery capability */
BCMP2P_STATUS
p2papi_enable_service_discovery(p2papi_instance_t* hdl,	BCMP2P_BOOL enable)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	hdl->sd.is_service_discovery = (enable == BCMP2P_TRUE) ? true : false;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_enable_service_discovery: %d\n",
		hdl->sd.is_service_discovery));
	return BCMP2P_SUCCESS;
}

/* enable/disable client discovery capability */
BCMP2P_STATUS
p2papi_enable_client_discovery(p2papi_instance_t* hdl, BCMP2P_BOOL enable)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	hdl->is_client_discovery = enable;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_enable_client_discovery: %d\n",
		hdl->is_client_discovery));
	return BCMP2P_SUCCESS;
}
#endif /* not  SOFTAP_ONLY */


/* Wrapper for malloc() that allows adding debug logs */
void*
p2papi_malloc(size_t size, const char *file, int line)
{
	void *p = malloc(size);

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "%s:%d malloc %p (%d bytes)\n",
		file, line, p, size));
	if (p == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "%s:%d malloc %d bytes FAILED!\n",
			file, line, size));
	}

	return p;
}

/* Wrapper for realloc() that allows adding debug logs */
void*
p2papi_realloc(void* p, size_t size, const char *file, int line)
{
	void *p2 = realloc(p, size);

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "%s:%d realloc old=%p new=%p (%d bytes)\n",
		file, line, p, p2, size));
	if (p2 == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "%s:%d realloc %d bytes FAILED!\n",
			file, line, size));
	}

	return p2;
}

/* Wrapper for free() that allows adding debug logs */
void
p2papi_free(void *p, const char *file, int line)
{
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "%s:%d free %p\n",
		file, line, p));
	if (p == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "%s:%d attempted free of NULL ptr!\n",
			file, line));
	}
	else
		free(p);
}


/* Wrapper for p2papi_osl_data_lock() that allows adding debug logs */
int
p2papi_data_lock(p2papi_instance_t *hdl, const char *file, int line,
	BCMP2P_LOG_LEVEL log_level)
{
	BCMP2PLOG((log_level, TRUE, "p2papi_data_lock %s:%d\n", file, line));
	return p2papi_osl_data_lock(hdl);
}

/* Wrapper for p2papi_osl_data_unlock() that allows adding debug logs */
int
p2papi_data_unlock(p2papi_instance_t *hdl, const char *file, int line,
	BCMP2P_LOG_LEVEL log_level)
{
	BCMP2PLOG((log_level, TRUE, "p2papi_data_unlock %s:%d\n", file, line));
	return p2papi_osl_data_unlock(hdl);
}

/* Atomic test and set using the instance data lock */
BCMP2P_BOOL
p2papi_atomic_test_and_set(p2papi_instance_t *hdl, BCMP2P_BOOL *flag,
	const char *file, int line)
{
	BCMP2P_BOOL ret;

	(void) file;
	(void) line;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_atomic_test_and_set: %s:%d\n",
		file, line));

	P2PAPI_DATA_LOCK(hdl);
	ret = *flag;
	*flag = TRUE;
	P2PAPI_DATA_UNLOCK(hdl);

	return ret;
}

/* Set action frame tx parameters */
int
p2papi_set_af_tx_params(void* p2pHandle, unsigned int max_retries,
	unsigned int retry_timeout_ms)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	hdl->af_tx_max_retries = max_retries;
	hdl->af_tx_retry_ms = retry_timeout_ms;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_set_af_tx_params: max=%d ms=%d\n",
		hdl->af_tx_max_retries, hdl->af_tx_retry_ms));

	return BCMP2P_SUCCESS;
}

void
p2papi_add_timer(void* p2pHandle, bcmseclib_timer_t *t, uint ms, bool periodic)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	bcmseclib_add_timer(t, ms, periodic);
	p2papi_osl_timer_refresh(hdl);
}

BCMP2P_STATUS
p2papi_add_mgmt_custom_ie(p2papi_instance_t *hdl, BCMP2P_MGMT_IE_FLAG ie_flag,
	BCMP2P_UINT8 *ie_buf, int ie_buf_len, BCMP2P_BOOL set_immed)
{
	BCMP2P_STATUS status;

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"p2papi_add_mgmt_custom_ie: Entered. ie_flag %d, set_immed %d\n",
		ie_flag, set_immed));

	if (ie_flag >= BCMP2P_MGMT_IE_FLAG_TOTAL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_add_mgmt_custom_ie: Invalid ie_flag %d\n", ie_flag));
		return BCMP2P_INVALID_PARAMS;
	}

	if (hdl->custom_mgmt_ie[ie_flag].ie_buf != NULL) {
		free(hdl->custom_mgmt_ie[ie_flag].ie_buf);

		hdl->custom_mgmt_ie[ie_flag].ie_buf = NULL;
		hdl->custom_mgmt_ie[ie_flag].ie_buf_len = 0;
	}

	hdl->custom_mgmt_ie[ie_flag].ie_buf = (uint8 *)P2PAPI_MALLOC(ie_buf_len);
	if (hdl->custom_mgmt_ie[ie_flag].ie_buf) {
		memcpy(hdl->custom_mgmt_ie[ie_flag].ie_buf, ie_buf, ie_buf_len);
		hdl->custom_mgmt_ie[ie_flag].ie_buf_len = ie_buf_len;
	}
	else {
		hdl->custom_mgmt_ie[ie_flag].ie_buf_len = 0;
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_add_mgmt_custom_ie: ie_buf malloc failed\n"));
		return BCMP2P_NOT_ENOUGH_SPACE;
	}

	if (set_immed) {
		int vndr_ie_flag;
		uint8 **old_ie_buf;
		int *old_ie_buf_len;
		vndr_ie_t *custom_ie = (vndr_ie_t *)ie_buf;
		p2papi_bsscfg_type_t bsscfg_type;
		int bssidx;

		/* Get bbsscfg type */
		bsscfg_type = p2papi_is_ap(hdl) ? P2PAPI_BSSCFG_CONNECTION : P2PAPI_BSSCFG_DEVICE;

		p2papi_saved_ie_t *saved_ie = &hdl->saved_ie[bsscfg_type];
		bssidx = p2papi_get_bsscfg_idx(hdl, bsscfg_type);

		switch (ie_flag) {
		case BCMP2P_MGMT_IE_FLAG_BEACON:
			vndr_ie_flag = VNDR_IE_BEACON_FLAG;
			old_ie_buf = &saved_ie->beacon_custom_ie_buf;
			old_ie_buf_len = &saved_ie->beacon_custom_ie_len;
			break;
		case BCMP2P_MGMT_IE_FLAG_PRBREQ:
			vndr_ie_flag = VNDR_IE_PRBREQ_FLAG;
			old_ie_buf = &saved_ie->probreq_custom_ie_buf;
			old_ie_buf_len = &saved_ie->probreq_custom_ie_len;
			break;
		case BCMP2P_MGMT_IE_FLAG_PRBRSP:
			vndr_ie_flag = VNDR_IE_PRBRSP_FLAG;
			old_ie_buf = &saved_ie->probrsp_custom_ie_buf;
			old_ie_buf_len = &saved_ie->probrsp_custom_ie_len;
			break;
		case BCMP2P_MGMT_IE_FLAG_ASSOCREQ:
			vndr_ie_flag = VNDR_IE_ASSOCREQ_FLAG;
			old_ie_buf = &saved_ie->assocreq_custom_ie_buf;
			old_ie_buf_len = &saved_ie->assocreq_custom_ie_len;
			break;
		case BCMP2P_MGMT_IE_FLAG_ASSOCRSP:
			vndr_ie_flag = VNDR_IE_ASSOCRSP_FLAG;
			old_ie_buf = &saved_ie->assocrsp_custom_ie_buf;
			old_ie_buf_len = &saved_ie->assocrsp_custom_ie_len;
			break;
		default:
			status = BCMP2P_ERROR;
			goto exit;
		};

		if (*old_ie_buf && *old_ie_buf_len > 0) {
			/* Delete custom IE */
			if (0 != p2papi_replace_and_save_ie(hdl, vndr_ie_flag,
				custom_ie->oui[0], custom_ie->oui[1], custom_ie->oui[2],
				custom_ie->id, bssidx, old_ie_buf, old_ie_buf_len,
				custom_ie->data, ie_buf_len - 5)) {
				status = BCMP2P_ERROR;
				goto exit;
			}
		}
	}

	status = BCMP2P_SUCCESS;

exit:
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"p2papi_add_mgmt_custom_ie: Exiting. status %d\n", status));
	return status;
}

BCMP2P_STATUS
p2papi_add_acf_custom_ie(p2papi_instance_t *hdl, BCMP2P_ACF_IE_FLAG ie_flag,
	BCMP2P_UINT8 *ie_buf, int ie_buf_len)
{
	if (hdl->custom_acf_ie[ie_flag].ie_buf != NULL) {
		free(hdl->custom_acf_ie[ie_flag].ie_buf);
	}

	hdl->custom_acf_ie[ie_flag].ie_buf = (uint8 *)malloc(ie_buf_len);
	if (hdl->custom_acf_ie[ie_flag].ie_buf) {
		memcpy(hdl->custom_acf_ie[ie_flag].ie_buf, ie_buf, ie_buf_len);
		hdl->custom_acf_ie[ie_flag].ie_buf_len = ie_buf_len;
	}

	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_del_mgmt_custom_ie(p2papi_instance_t *hdl, BCMP2P_MGMT_IE_FLAG ie_flag)
{
	BCMP2P_STATUS status;
	int vndr_ie_flag;
	uint8 **old_ie_buf;
	int *old_ie_buf_len;
	p2papi_bsscfg_type_t bsscfg_type;
	int bssidx;

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"p2papi_del_mgmt_custom_ie: Entered. ie_flag %d\n", ie_flag));

	if (ie_flag >= BCMP2P_MGMT_IE_FLAG_TOTAL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_del_mgmt_custom_ie: Invalid ie_flag %d\n", ie_flag));
		return BCMP2P_INVALID_PARAMS;
	}

	if (hdl->custom_mgmt_ie[ie_flag].ie_buf != NULL) {
		free(hdl->custom_mgmt_ie[ie_flag].ie_buf);

		hdl->custom_mgmt_ie[ie_flag].ie_buf = NULL;
		hdl->custom_mgmt_ie[ie_flag].ie_buf_len = 0;
	}

	/* Get bbsscfg type */
	bsscfg_type = hdl->is_ap? P2PAPI_BSSCFG_CONNECTION : P2PAPI_BSSCFG_DEVICE;

	p2papi_saved_ie_t *saved_ie = &hdl->saved_ie[bsscfg_type];
	bssidx = p2papi_get_bsscfg_idx(hdl, bsscfg_type);

	switch (ie_flag) {
	case BCMP2P_MGMT_IE_FLAG_BEACON:
		vndr_ie_flag = VNDR_IE_BEACON_FLAG;
		old_ie_buf = &saved_ie->beacon_custom_ie_buf;
		old_ie_buf_len = &saved_ie->beacon_custom_ie_len;
		break;
	case BCMP2P_MGMT_IE_FLAG_PRBREQ:
		vndr_ie_flag = VNDR_IE_PRBREQ_FLAG;
		old_ie_buf = &saved_ie->probreq_custom_ie_buf;
		old_ie_buf_len = &saved_ie->probreq_custom_ie_len;
		break;
	case BCMP2P_MGMT_IE_FLAG_PRBRSP:
		vndr_ie_flag = VNDR_IE_PRBRSP_FLAG;
		old_ie_buf = &saved_ie->probrsp_custom_ie_buf;
		old_ie_buf_len = &saved_ie->probrsp_custom_ie_len;
		break;
	case BCMP2P_MGMT_IE_FLAG_ASSOCREQ:
		vndr_ie_flag = VNDR_IE_ASSOCREQ_FLAG;
		old_ie_buf = &saved_ie->assocreq_custom_ie_buf;
		old_ie_buf_len = &saved_ie->assocreq_custom_ie_len;
		break;
	case BCMP2P_MGMT_IE_FLAG_ASSOCRSP:
		vndr_ie_flag = VNDR_IE_ASSOCRSP_FLAG;
		old_ie_buf = &saved_ie->assocrsp_custom_ie_buf;
		old_ie_buf_len = &saved_ie->assocrsp_custom_ie_len;
		break;
	default:
		status = BCMP2P_ERROR;
		goto exit;
	};

	if (*old_ie_buf != NULL && *old_ie_buf_len > 0) {
		vndr_ie_t *old_custom_ie = (vndr_ie_t *)(*old_ie_buf);

		/* Remove custom IE */
		if (0 != p2papi_replace_and_save_ie(hdl, vndr_ie_flag,
			old_custom_ie->oui[0], old_custom_ie->oui[1], old_custom_ie->oui[2],
			old_custom_ie->id, bssidx, old_ie_buf, old_ie_buf_len, NULL, 0)) {
			status = BCMP2P_ERROR;
			goto exit;
		}
	}

	status = BCMP2P_SUCCESS;

exit:
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"p2papi_del_mgmt_custom_ie: Exiting. status %d\n", status));
	return status;
}

BCMP2P_STATUS
p2papi_del_acf_custom_ie(p2papi_instance_t *hdl, BCMP2P_ACF_IE_FLAG ie_flag)
{
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "p2papi_del_acf_custom_ie: Entered.\n"));

	if (ie_flag >= BCMP2P_ACF_IE_FLAG_TOTAL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_del_acf_custom_ie: Invalid ie_flag %d\n", ie_flag));
		return BCMP2P_INVALID_PARAMS;
	}

	if (hdl->custom_acf_ie[ie_flag].ie_buf != NULL) {
		free(hdl->custom_acf_ie[ie_flag].ie_buf);

		hdl->custom_acf_ie[ie_flag].ie_buf = NULL;
		hdl->custom_acf_ie[ie_flag].ie_buf_len = 0;
	}

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "p2papi_del_acf_custom_ie: Exiting.\n"));
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_register_gon_req_cb(p2papi_instance_t *hdl, int notificationType,
	BCMP2P_GONREQ_CALLBACK funcCallback, void *pCallbackContext,
	void *pReserved)
{
	return BCMP2P_SUCCESS;
}
