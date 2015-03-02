/*
 * P2PLib API - debug code
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_dbg.c,v 1.42 2010-07-20 17:30:04 $
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

#include <wpscli_api.h>

/* P2P Library include files */
#include <BcmP2PAPI.h>
#include <BcmP2PDbg.h>
#include <p2plib_int.h>
#include "p2pwl.h"

/* WL driver include files */
#include <proto/ethernet.h>
#include <bcmendian.h>
#include <wlioctl.h>
#include <bcmutils.h>


BCMP2P_LOG_LEVEL p2papi_log_level = BCMP2P_LOG_ERR;
BCMP2P_LOG_CALLBACK p2papi_log_cback = NULL;
void *p2papi_log_cb_param1 = NULL;
void *p2papi_log_cb_param2 = NULL;


/*
 * Format a SSID string for printing (in case it contains non-ASCII chars)
 */
int
p2papi_format_ssid(char* ssid_buf, uint8* ssid, uint8 ssid_len)
{
	int i, c;
	char *p = ssid_buf;

	if (ssid_len > 32) ssid_len = 32;

	for (i = 0; i < ssid_len; i++) {
		c = (int)ssid[i];
		if (c == '\\') {
			*p++ = '\\';
			*p++ = '\\';
		} else if (isprint((uchar)c)) {
			*p++ = (char)c;
		} else {
			p += sprintf(p, "\\x%02X", c);
		}
	}
	*p = '\0';

	return (int) (p - ssid_buf);
}


/*
 * Debug code to print detailed scan results.
 */
#if PRINT_DETAILED_SCAN_RESULTS

/* 802.11i/WPA RSN IE parsing utilities */
typedef struct {
	uint16 version;
	wpa_suite_mcast_t *mcast;
	wpa_suite_ucast_t *ucast;
	wpa_suite_auth_key_mgmt_t *akm;
	uint8 *capabilities;
} rsn_parse_info_t;

/*
 * Helper routine to print the infrastructure mode while pretty printing the
 * BSS list.
 */
static const char *
capmode2str(uint16 capability)
{
	capability &= (DOT11_CAP_ESS | DOT11_CAP_IBSS);

	if (capability == DOT11_CAP_ESS)
		return "Managed";
	else if (capability == DOT11_CAP_IBSS)
		return "Ad Hoc";
	else
		return "<unknown>";
}

/*
 * Print a set of rates.
 */
void
dump_rateset(uint8 *rates, uint count)
{
	uint i;
	uint r;
	bool b;

	DBGPRINT("[ ");
	for (i = 0; i < count; i++) {
		r = rates[i] & 0x7f;
		b = rates[i] & 0x80;
		if (r == 0)
			break;
		DBGPRINT3("%d%s%s ", (r / 2), (r % 2)?".5":"", b?"(b)":"");
	}
	DBGPRINT("]");
}

static int
p2pwlu_bcmp(const void *b1, const void *b2, int len)
{
	return (memcmp(b1, b2, len));
}

/* Is this body of this tlvs entry a WPA entry? */
static bool
p2pwlu_is_wpa_ie(uint8 ie)
{
	/* If the contents match the WPA_OUI and type=1 */
	if ((ie[1] >= 6) && !p2pwlu_bcmp(&ie[2], WPA_OUI "\x01", 4)) {
		return TRUE;
	}

	return FALSE;
}

/* Validates and parses the RSN or WPA IE contents into a rsn_parse_info_t structure
 * Returns 0 on success, or 1 if the information in the buffer is not consistant with
 * an RSN IE or WPA IE.
 * The buf pointer passed in should be pointing at the version field in either an RSN IE
 * or WPA IE.
 */
static int
p2pwlu_rsn_ie_parse_info(uint8* rsn_buf, uint len, rsn_parse_info_t *rsn)
{
	uint16 count;

	memset(rsn, 0, sizeof(rsn_parse_info_t));

	/* version */
	if (len < sizeof(uint16))
		return 1;

	rsn->version = ltoh16_ua(rsn_buf);
	len -= sizeof(uint16);
	rsn_buf += sizeof(uint16);

	/* Multicast Suite */
	if (len < sizeof(wpa_suite_mcast_t))
		return 0;

	rsn->mcast = (wpa_suite_mcast_t*)rsn_buf;
	len -= sizeof(wpa_suite_mcast_t);
	rsn_buf += sizeof(wpa_suite_mcast_t);

	/* Unicast Suite */
	if (len < sizeof(uint16))
		return 0;

	count = ltoh16_ua(rsn_buf);

	if (len < (sizeof(uint16) + count * sizeof(wpa_suite_t)))
		return 1;

	rsn->ucast = (wpa_suite_ucast_t*)rsn_buf;
	len -= (sizeof(uint16) + count * sizeof(wpa_suite_t));
	rsn_buf += (sizeof(uint16) + count * sizeof(wpa_suite_t));

	/* AKM Suite */
	if (len < sizeof(uint16))
		return 0;

	count = ltoh16_ua(rsn_buf);

	if (len < (sizeof(uint16) + count * sizeof(wpa_suite_t)))
		return 1;

	rsn->akm = (wpa_suite_auth_key_mgmt_t*)rsn_buf;
	len -= (sizeof(uint16) + count * sizeof(wpa_suite_t));
	rsn_buf += (sizeof(uint16) + count * sizeof(wpa_suite_t));

	/* Capabilites */
	if (len < sizeof(uint16))
		return 0;

	rsn->capabilities = rsn_buf;

	return 0;
}

static uint
p2pwlu_rsn_ie_decode_cntrs(uint cntr_field)
{
	uint cntrs;

	switch (cntr_field) {
	case RSN_CAP_1_REPLAY_CNTR:
		cntrs = 1;
		break;
	case RSN_CAP_2_REPLAY_CNTRS:
		cntrs = 2;
		break;
	case RSN_CAP_4_REPLAY_CNTRS:
		cntrs = 4;
		break;
	case RSN_CAP_16_REPLAY_CNTRS:
		cntrs = 16;
		break;
	default:
		cntrs = 0;
		break;
	}

	return cntrs;
}

static void
p2pwlu_rsn_ie_dump(bcm_tlv_t *ie)
{
	int i;
	int rsn;
	wpa_ie_fixed_t *wpa = NULL;
	rsn_parse_info_t rsn_info;
	wpa_suite_t *suite;
	uint8 std_oui[3];
	int unicast_count = 0;
	int akm_count = 0;
	uint16 capabilities;
	uint cntrs;
	int err;

	if (ie->id == DOT11_MNG_RSN_ID) {
		rsn = TRUE;
		memcpy(std_oui, WPA2_OUI, WPA_OUI_LEN);
		err = p2pwlu_rsn_ie_parse_info(ie->data, ie->len, &rsn_info);
	} else {
		rsn = FALSE;
		memcpy(std_oui, WPA_OUI, WPA_OUI_LEN);
		wpa = (wpa_ie_fixed_t*)ie;
		err = p2pwlu_rsn_ie_parse_info((uint8*)&wpa->version,
			wpa->length - WPA_IE_OUITYPE_LEN, &rsn_info);
	}
	if (err || rsn_info.version != WPA_VERSION)
		return;

	if (rsn)
		DBGPRINT("RSN:\n");
	else
		DBGPRINT("WPA:\n");

	/* Check for multicast suite */
	if (rsn_info.mcast) {
		DBGPRINT("\tmulticast cipher: ");
		if (!p2pwlu_bcmp(rsn_info.mcast->oui, std_oui, 3)) {
			switch (rsn_info.mcast->type) {
			case WPA_CIPHER_NONE:
				DBGPRINT("NONE\n");
				break;
			case WPA_CIPHER_WEP_40:
				DBGPRINT("WEP64\n");
				break;
			case WPA_CIPHER_WEP_104:
				DBGPRINT("WEP128\n");
				break;
			case WPA_CIPHER_TKIP:
				DBGPRINT("TKIP\n");
				break;
			case WPA_CIPHER_AES_OCB:
				DBGPRINT("AES-OCB\n");
				break;
			case WPA_CIPHER_AES_CCM:
				DBGPRINT("AES-CCMP\n");
				break;
			default:
				DBGPRINT2("Unknown-%s(#%d)\n", rsn ? "RSN" : "WPA",
				       rsn_info.mcast->type);
				break;
			}
		}
		else {
			DBGPRINT4("Unknown-%02X:%02X:%02X(#%d) ",
			       rsn_info.mcast->oui[0], rsn_info.mcast->oui[1],
			       rsn_info.mcast->oui[2], rsn_info.mcast->type);
		}
	}

	/* Check for unicast suite(s) */
	if (rsn_info.ucast) {
		unicast_count = ltoh16_ua(&rsn_info.ucast->count);
		DBGPRINT1("\tunicast ciphers(%d): ", unicast_count);
		for (i = 0; i < unicast_count; i++) {
			suite = &rsn_info.ucast->list[i];
			if (!p2pwlu_bcmp(suite->oui, std_oui, 3)) {
				switch (suite->type) {
				case WPA_CIPHER_NONE:
					DBGPRINT("NONE ");
					break;
				case WPA_CIPHER_WEP_40:
					DBGPRINT("WEP64 ");
					break;
				case WPA_CIPHER_WEP_104:
					DBGPRINT("WEP128 ");
					break;
				case WPA_CIPHER_TKIP:
					DBGPRINT("TKIP ");
					break;
				case WPA_CIPHER_AES_OCB:
					DBGPRINT("AES-OCB ");
					break;
				case WPA_CIPHER_AES_CCM:
					DBGPRINT("AES-CCMP ");
					break;
				default:
					DBGPRINT2("WPA-Unknown-%s(#%d) ", rsn ? "RSN" : "WPA",
					       suite->type);
					break;
				}
			}
			else {
				DBGPRINT4("Unknown-%02X:%02X:%02X(#%d) ",
					suite->oui[0], suite->oui[1], suite->oui[2],
					suite->type);
			}
		}
		DBGPRINT("\n");
	}
	/* Authentication Key Management */
	if (rsn_info.akm) {
		akm_count = ltoh16_ua(&rsn_info.akm->count);
		DBGPRINT1("\tAKM Suites(%d): ", akm_count);
		for (i = 0; i < akm_count; i++) {
			suite = &rsn_info.akm->list[i];
			if (!p2pwlu_bcmp(suite->oui, std_oui, 3)) {
				switch (suite->type) {
				case RSN_AKM_NONE:
					DBGPRINT("None ");
					break;
				case RSN_AKM_UNSPECIFIED:
					DBGPRINT("WPA ");
					break;
				case RSN_AKM_PSK:
					DBGPRINT("WPA-PSK ");
					break;
				default:
					DBGPRINT2("Unknown-%s(#%d)  ",
					       rsn ? "RSN" : "WPA", suite->type);
					break;
				}
			}
			else {
				DBGPRINT4("Unknown-%02X:%02X:%02X(#%d)  ",
					suite->oui[0], suite->oui[1], suite->oui[2],
					suite->type);
			}
		}
		DBGPRINT("\n");
	}

	/* Capabilities */
	if (rsn_info.capabilities) {
		capabilities = ltoh16_ua(rsn_info.capabilities);
		DBGPRINT1("\tCapabilities(0x%04x): ", capabilities);
		if (rsn)
			DBGPRINT1("%sPre-Auth, ", (capabilities & RSN_CAP_PREAUTH) ? "" : "No ");

		DBGPRINT1("%sPairwise, ", (capabilities & RSN_CAP_NOPAIRWISE) ? "No " : "");

		cntrs = p2pwlu_rsn_ie_decode_cntrs((capabilities & RSN_CAP_PTK_REPLAY_CNTR_MASK) >>
		                               RSN_CAP_PTK_REPLAY_CNTR_SHIFT);

		DBGPRINT2("%d PTK Replay Ctr%s", cntrs, (cntrs > 1)?"s":"");

		if (rsn) {
			cntrs = p2pwlu_rsn_ie_decode_cntrs(
				(capabilities & RSN_CAP_GTK_REPLAY_CNTR_MASK) >>
				RSN_CAP_GTK_REPLAY_CNTR_SHIFT);

			DBGPRINT2("%d GTK Replay Ctr%s\n", cntrs, (cntrs > 1)?"s":"");
		} else {
			DBGPRINT("\n");
		}
	} else {
		DBGPRINT1("\tNo %s Capabilities advertised\n", rsn ? "RSN" : "WPA");
	}

}

void
p2pwlu_dump_wpa_rsn_ies(uint8* cp, uint len)
{
	uint buflen;
	uint8 *ie;
	uint ielen = 0;

	ie = cp;
	buflen = len;
	while ((ie = p2pwlu_parse_tlvs(ir, &buflen, &ielen, DOT11_MNG_WPA_ID, false))) {
		if (p2pwlu_is_wpa_ie(ie))
			p2pwlu_rsn_ie_dump((bcm_tlv_t*)ie);
		ie = p2pwlu_next_tlv(ie, &buflen);
	}

	ie = cp;
	buflen = len;
	ie = p2pwlu_parse_tlvs(ie, &buflen, &ielen, DOT11_MNG_RSN_ID);
	if (ie)
		p2pwlu_rsn_ie_dump((bcm_tlv_t*)rsnie);

	return;
}

/*
 * Print the information in one BSS of a scan result.
 */
static void
dump_bss_info(wl_bss_info_t *bi)
{
	char ssidbuf[SSID_FMT_BUF_LEN];
	wl_bss_info_107_t *old_bi;
	int mcs_idx = 0;
	char etoa_buf[ETHER_ADDR_LEN * 3];

	/* Convert version 107 to 108 */
	if (dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION) {
		old_bi = (wl_bss_info_107_t *)bi;
		bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel);
		bi->ie_length = old_bi->ie_length;
		bi->ie_offset = sizeof(wl_bss_info_107_t);
	}

	p2papi_format_ssid(ssidbuf, bi->SSID, bi->SSID_len);

	DBGPRINT1("SSID: \"%s\"\n", ssidbuf);

	DBGPRINT1("Mode: %s\t", capmode2str(dtoh16(bi->capability)));
	DBGPRINT1("RSSI: %d dBm\t", (int16)(dtoh16(bi->RSSI)));
	DBGPRINT1("noise: %d dBm\t", bi->phy_noise);
	if (bi->flags) {
		bi->flags = dtoh16(bi->flags);
		DBGPRINT("Flags: ");
		if (bi->flags & WL_BSS_FLAGS_FROM_BEACON) DBGPRINT("FromBcn ");
		DBGPRINT("\t");
	}
	DBGPRINT1("Channel: %d\n", CHSPEC_CHANNEL(dtohchanspec(bi->chanspec)));

	DBGPRINT1("BSSID: %s\t", p2pwl_ether_etoa(&bi->BSSID, etoa_buf));

	DBGPRINT("Capability: ");
	bi->capability = dtoh16(bi->capability);
	if (bi->capability & DOT11_CAP_ESS) DBGPRINT("ESS ");
	if (bi->capability & DOT11_CAP_IBSS) DBGPRINT("IBSS ");
	if (bi->capability & DOT11_CAP_POLLABLE) DBGPRINT("Pollable ");
	if (bi->capability & DOT11_CAP_POLL_RQ) DBGPRINT("PollReq ");
	if (bi->capability & DOT11_CAP_PRIVACY) DBGPRINT("WEP ");
	if (bi->capability & DOT11_CAP_SHORT) DBGPRINT("ShortPre ");
	if (bi->capability & DOT11_CAP_PBCC) DBGPRINT("PBCC ");
	if (bi->capability & DOT11_CAP_AGILITY) DBGPRINT("Agility ");
	if (bi->capability & DOT11_CAP_SHORTSLOT) DBGPRINT("ShortSlot ");
	if (bi->capability & DOT11_CAP_CCK_OFDM) DBGPRINT("CCK-OFDM ");
	DBGPRINT("\n");

	DBGPRINT("Supported Rates: ");
	dump_rateset(bi->rateset.rates, dtoh32(bi->rateset.count));
	DBGPRINT("\n");
	if (dtoh32(bi->ie_length))
		p2pwlu_dump_wpa_rsn_ies((uint8 *)(((uint8 *)bi) + dtoh16(bi->ie_offset)),
		                    dtoh32(bi->ie_length));

	if (dtoh32(bi->version) != LEGACY_WL_BSS_INFO_VERSION && bi->n_cap) {
		DBGPRINT("802.11N Capable:\n");
		bi->chanspec = dtohchanspec(bi->chanspec);
		DBGPRINT4("\tChanspec: %sGHz channel %d %dMHz (0x%x)\n",
			CHSPEC_IS2G(bi->chanspec)?"2.4":"5", CHSPEC_CHANNEL(bi->chanspec),
			CHSPEC_IS40(bi->chanspec) ? 40 : (CHSPEC_IS20(bi->chanspec) ? 20 : 10),
			bi->chanspec);
		DBGPRINT1("\tControl channel: %d\n", bi->ctl_ch);
		DBGPRINT("\t802.11N Capabilities: ");
		if (dtoh32(bi->nbss_cap) & HT_CAP_40MHZ)
			DBGPRINT("40Mhz ");
		DBGPRINT("\n\tSupported MCS : [ ");
		for (mcs_idx = 0; mcs_idx < (MCSSET_LEN * 8); mcs_idx++)
			if (isset(bi->basic_mcs, mcs_idx))
				DBGPRINT1("%d ", mcs_idx);
		DBGPRINT("]\n");
	}
}
#endif /* PRINT_DETAILED_SCAN_RESULTS */


/* Show the association status - call this only on the STA peer */
int
p2papi_wl_status(void* p2pHdl, int logLevel)
{
	BCMP2P_LOG_LEVEL log_level = (BCMP2P_LOG_LEVEL) logLevel;
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHdl;
	struct ether_addr bssid;
	bool ret;

	ret = p2papi_osl_is_associated(hdl, &bssid);
	if (ret) {
		BCMP2PLOG((log_level, TRUE,
			"Associated to bssid %02x:%02x:%02x:%02x:%02x:%02x\n",
			bssid.octet[0], bssid.octet[1], bssid.octet[2],
			bssid.octet[3], bssid.octet[4], bssid.octet[5]));
	} else {
		BCMP2PLOG((log_level, TRUE, "Not associated\n"));
	}
	return 0;
}

/* Show the associated STAs - call this only on the AP peer */
int
p2papi_wl_assoclist(void *p2pHdl)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHdl;
	uint8 *ioctl_buf = P2PAPI_IOCTL_BUF(hdl);
	struct maclist *maclist = (struct maclist *) ioctl_buf;
	int ret;
	struct ether_addr *ea;
	uint i, max = (P2PAPI_IOCTL_BUF_SIZE - sizeof(int)) / ETHER_ADDR_LEN;
#if P2PLOGGING
	char etoa_buf[ETHER_ADDR_LEN * 3];
#endif

	P2PAPI_CHECK_P2PHDL(p2pHdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);

	/* Lock the P2P instance data access mutex since we will be writing
	 * to the instance data's ioctl buffer.
	 */
	P2PAPI_DATA_LOCK(hdl);

	maclist->count = htod32(max);
	ret = p2papi_osl_wl_ioctl(hdl, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION],
		WLC_GET_MACLIST, maclist, P2PAPI_IOCTL_BUF_SIZE, FALSE);
	if (ret < 0) {
		P2PAPI_DATA_UNLOCK(hdl);
		return ret;
	}
	maclist->count = dtoh32(maclist->count);
	for (i = 0, ea = maclist->ea; i < maclist->count && i < max; i++, ea++)
		P2PLOG1("Associated STA: %s\n", p2pwl_ether_etoa(ea, etoa_buf));

	P2PAPI_DATA_UNLOCK(hdl);

	return 0;
}




int
p2papi_get_mac_addr(void *p2pHdl, struct ether_addr *out_mac_addr)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHdl;

	P2PAPI_CHECK_P2PHDL(p2pHdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	return p2pwlu_get_mac_addr(hdl, out_mac_addr);
}

bool
p2papi_chk_p2phdl(void* p2pHdl, const char *file, int line)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHdl;
	if (hdl == NULL || hdl->magic != P2PAPI_HDL_MAGIC_NUMBER) {
		P2PERR("Bad p2pHdl %p\n");
		P2PERR2("at %s:%d\n", file, line);
		return FALSE;
	}
	return TRUE;
}

/* Print bytes formatted as hex to the debug log.
 * Output all lines using a single log statement to suit the Windows logging
 * mechanism.
 */
void
p2papi_log_hexdata(BCMP2P_LOG_LEVEL logLevel, char *heading,
	unsigned char *data, int dataLen)
{
	#define P2PAPI_DISPBUF_SIZE 512
	char dispBuf[P2PAPI_DISPBUF_SIZE];
	char *dispBufPrefix = "          ";
	int i;

	if (strlen(heading) >= P2PAPI_DISPBUF_SIZE)
		return;

	sprintf(dispBuf, "%s: %d", heading, dataLen);
	BCMP2PLOG((logLevel, TRUE, "%s\n", dispBuf));

	for (i = 0; i < dataLen; i++) {
		/* show 16-byte in one row */
		if (i % 16 == 0) {
			if (i > 0)
				BCMP2PLOG((logLevel, TRUE, "%s\n", dispBuf));
			strcpy(dispBuf, dispBufPrefix);
		}
		sprintf(&dispBuf[strlen(dispBuf)], "%02x ", data[i]);
	}
	if (strlen(dispBuf) > strlen(dispBufPrefix))
		BCMP2PLOG((logLevel, TRUE, "%s\n", dispBuf));
}

/* Set the current log level */
void
BCMP2PLogEnable(BCMP2P_LOG_LEVEL logLevel)
{
#if P2PLOGGING
	p2papi_log_level = logLevel;
#else /* P2PLOGGING */
	p2papi_log_level = BCMP2P_LOG_OFF;
#endif /* P2PLOGGING */
}

/* Get the current log level */
BCMP2P_LOG_LEVEL
BCMP2PGetLogEnable(void)
{
	return p2papi_log_level;
}

/* Register an application-specific log output handler. */
void
BCMP2PLogRegisterLogHandler(BCMP2P_LOG_CALLBACK funcCallback,
	void *pCallbackContext, void *pReserved)
{
	p2papi_log_cback = funcCallback;
	p2papi_log_cb_param1 = pCallbackContext;
	p2papi_log_cb_param2 = pReserved;
}



/* Output a timestamped debug log at the given log level */
void
p2papi_log(BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp,
	const char *fmt, ...)
{
	va_list argp;
	char logstr[2048];

	if (level == BCMP2P_LOG_OFF)
		return;

	if (p2papi_log_level < level)
		return;

	va_start(argp, fmt);
	vsnprintf(logstr, sizeof(logstr), fmt, argp);
	va_end(argp);

	if (p2papi_log_cback) {
		p2papi_log_cback(p2papi_log_cb_param1, p2papi_log_cb_param2, level,
			print_timestamp, logstr);
	} else {
		p2papi_osl_log(level, print_timestamp, logstr);
/*		syslog(LOG_INFO, logstr); */
	}
}

void
p2papi_log_mac(const char *heading, struct ether_addr* src_mac)
{
	char mac_str[20] = { 0 };

	if (src_mac != NULL)
		sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", src_mac->octet[0],
			src_mac->octet[1], src_mac->octet[2], src_mac->octet[3],
			src_mac->octet[4], src_mac->octet[5]);

	if (heading)
		P2PLOG2("%s %s\n", heading, mac_str);
	else
		P2PLOG1("%s\n", mac_str);
}

/* Redirect debug logs to a file */
void
p2papi_set_log_file(const char *filename)
{
	p2papi_osl_set_log_file(filename);
}
