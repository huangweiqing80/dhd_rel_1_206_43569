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
 * $Id: bwl_utils.c,v 1.5 2010-08-05 22:54:37 $
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

/* wps includes */
#ifdef INCLUDE_WPS
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

#include "bwl.h"

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

/* buffer length needed for wl_format_ssid
 * 32 SSID chars, max of 4 chars for each SSID char "\xFF", plus NULL
 */
#define SSID_FMT_BUF_LEN ((32 * 4) + 1)
#define USAGE_ERROR  -1		/* Error code for Usage */

/* 802.11i/WPA RSN IE parsing utilities */
typedef struct {
	uint16 version;
	wpa_suite_mcast_t *mcast;
	wpa_suite_ucast_t *ucast;
	wpa_suite_auth_key_mgmt_t *akm;
	uint8 *capabilities;
} rsn_parse_info_t;

extern int
wl_get(void *wl, int cmd, void *buf, int len);
extern int
wl_set(void *wl, int cmd, void *buf, int len);


/* now IOCTL GET commands shall call wlu_get() instead of wl_get() so that the commands
 * can be batched when needed
 */
int
wlu_get(void *wl, int cmd, void *cmdbuf, int len)
{
	return wl_get(wl, cmd, cmdbuf, len);
}
/* now IOCTL SET commands shall call wlu_set() instead of wl_set() so that the commands
 * can be batched when needed
 */
int
wlu_set(void *wl, int cmd, void *cmdbuf, int len)
{
		return wl_set(wl, cmd, cmdbuf, len);
}
/*
 * format an iovar buffer
 * iovar name is converted to lower case
 */
static uint
wl_iovar_mkbuf(const char *name, char *data, uint datalen, char *iovar_buf, uint buflen, int *perr)
{
	uint iovar_len;
	char *p;

	iovar_len = strlen(name) + 1;

	/* check for overflow */
	if ((iovar_len + datalen) > buflen) {
		*perr = BCME_BUFTOOSHORT;
		return 0;
	}

	/* copy data to the buffer past the end of the iovar name string */
	if (datalen > 0)
		memmove(&iovar_buf[iovar_len], data, datalen);

	/* copy the name to the beginning of the buffer */
	strcpy(iovar_buf, name);

	/* wl command line automatically converts iovar names to lower case for
	 * ease of use
	 */
	p = iovar_buf;
	while (*p != '\0') {
		*p = tolower((int)*p);
		p++;
	}

	*perr = 0;
	return (iovar_len + datalen);
}
/*
 * get named iovar providing both parameter and i/o buffers
 * iovar name is converted to lower case
 */
static int
wlu_iovar_getbuf(void* wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen)
{
	int err;

	wl_iovar_mkbuf(iovar, param, paramlen, bufptr, buflen, &err);
	if (err)
		return err;

	return wlu_get(wl, WLC_GET_VAR, bufptr, buflen);
}
/*
 * set named iovar providing both parameter and i/o buffers
 * iovar name is converted to lower case
 */
static int
wlu_iovar_setbuf(void* wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen)
{
	int err;
	int iolen;

	iolen = wl_iovar_mkbuf(iovar, param, paramlen, bufptr, buflen, &err);
	if (err)
		return err;

	return wlu_set(wl, WLC_SET_VAR, bufptr, iolen);
}

/*
 * get named iovar without parameters into a given buffer
 * iovar name is converted to lower case
 */
int
wlu_iovar_get(void *wl, const char *iovar, void *outbuf, int len)
{
	char smbuf[WLC_IOCTL_SMLEN];
	int err;

	/* use the return buffer if it is bigger than what we have on the stack */
	if (len > (int)sizeof(smbuf)) {
		err = wlu_iovar_getbuf(wl, iovar, NULL, 0, outbuf, len);
	} else {
		memset(smbuf, 0, sizeof(smbuf));
		err = wlu_iovar_getbuf(wl, iovar, NULL, 0, smbuf, sizeof(smbuf));
		if (err == 0)
			memcpy(outbuf, smbuf, len);
	}

	return err;
}
/*
 * set named iovar given the parameter buffer
 * iovar name is converted to lower case
 */
int
wlu_iovar_set(void *wl, const char *iovar, void *param, int paramlen)
{
	char smbuf[WLC_IOCTL_SMLEN*2];

	memset(smbuf, 0, sizeof(smbuf));

	return wlu_iovar_setbuf(wl, iovar, param, paramlen, smbuf, sizeof(smbuf));
}
/*
 * get named iovar as an integer value
 * iovar name is converted to lower case
 */
int
wlu_iovar_getint(void *wl, const char *iovar, int *pval)
{
	int ret;

	ret = wlu_iovar_get(wl, iovar, pval, sizeof(int));
	if (ret >= 0)
	{
		*pval = dtoh32(*pval);
	}
	return ret;
}
/*
 * set named iovar given an integer parameter
 * iovar name is converted to lower case
 */
int
wlu_iovar_setint(void *wl, const char *iovar, int val)
{
	val = htod32(val);
	return wlu_iovar_set(wl, iovar, &val, sizeof(int));
}
/*
 * format a bsscfg indexed iovar buffer
 */

/* Helper routine to print the infrastructure mode while pretty printing the BSS list */
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
char *
wl_ether_etoa(const struct ether_addr *n)
{
	static char etoa_buf[ETHER_ADDR_LEN * 3];
	char *c = etoa_buf;
	int i;

	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		if (i)
			*c++ = ':';
		c += sprintf(c, "%02X", n->octet[i] & 0xff);
	}
	return etoa_buf;
}
/*
 * Traverse a string of 1-byte tag/1-byte length/variable-length value
 * triples, returning a pointer to the substring whose first element
 * matches tag
 */
uint8 *
wlu_parse_tlvs(uint8 *tlv_buf, int buflen, uint key)
{
	uint8 *cp;
	int totlen;

	cp = tlv_buf;
	totlen = buflen;

	/* find tagged parameter */
	while (totlen >= 2) {
		uint tag;
		int len;

		tag = *cp;
		len = *(cp +1);

		/* validate remaining totlen */
		if ((tag == key) && (totlen >= (len + 2)))
			return (cp);

		cp += (len + 2);
		totlen -= (len + 2);
	}

	return NULL;
}
int
wl_format_ssid(char* ssid_buf, uint8* ssid, int ssid_len)
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

	return p - ssid_buf;
}
/* Validates and parses the RSN or WPA IE contents into a rsn_parse_info_t structure
 * Returns 0 on success, or 1 if the information in the buffer is not consistant with
 * an RSN IE or WPA IE.
 * The buf pointer passed in should be pointing at the version field in either an RSN IE
 * or WPA IE.
 */
static int
wl_rsn_ie_parse_info(uint8* rsn_buf, uint len, rsn_parse_info_t *rsn)
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
wl_rsn_ie_decode_cntrs(uint cntr_field)
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
static int
wlu_bcmp(const void *b1, const void *b2, int len)
{
	return (memcmp(b1, b2, len));
}
/* Is this body of this tlvs entry a WPA entry? If */
/* not update the tlvs buffer pointer/length */
bool
wlu_is_wpa_ie(uint8 **wpaie, uint8 **tlvs, uint *tlvs_len)
{
	uint8 *ie = *wpaie;

	/* If the contents match the WPA_OUI and type=1 */
	if ((ie[1] >= 6) && !wlu_bcmp(&ie[2], WPA_OUI "\x01", 4)) {
		return TRUE;
	}

	/* point to the next ie */
	ie += ie[1] + 2;
	/* calculate the length of the rest of the buffer */
	*tlvs_len -= (int)(ie - *tlvs);
	/* update the pointer to the start of the buffer */
	*tlvs = ie;

	return FALSE;
}

void
wl_rsn_ie_dump(bcm_tlv_t *ie, WpaInfo_t *info)
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
        err = wl_rsn_ie_parse_info(ie->data, ie->len, &rsn_info);
    } else {
        rsn = FALSE;
        memcpy(std_oui, WPA_OUI, WPA_OUI_LEN);
        wpa = (wpa_ie_fixed_t*)ie;
        err = wl_rsn_ie_parse_info((uint8*)&wpa->version, wpa->length - WPA_IE_OUITYPE_LEN,
                                   &rsn_info);
    }
    if (err || rsn_info.version != WPA_VERSION)
        return;

    if (rsn)
    {
        PRINTF(("RSN:\n"));
    }
    else
    {
        PRINTF(("WPA:\n"));
    }

    /* Check for multicast suite */
    if (rsn_info.mcast) {
        PRINTF(("\tmulticast cipher: "));
        if (!wlu_bcmp(rsn_info.mcast->oui, std_oui, 3)) {
            switch (rsn_info.mcast->type) {
            case WPA_CIPHER_NONE:
                PRINTF(("NONE\n"));
                info->Cipher |= eWSecNone;
                break;
            case WPA_CIPHER_WEP_40:
                PRINTF(("WEP64\n"));
                info->Cipher |= eWSecWep;
                break;
            case WPA_CIPHER_WEP_104:
                PRINTF(("WEP128\n"));
                info->Cipher |= eWSecWep;
                break;
            case WPA_CIPHER_TKIP:
                PRINTF(("TKIP\n"));
                info->Cipher |= eWSecTkip;
                break;
            case WPA_CIPHER_AES_OCB:
                PRINTF(("AES-OCB\n"));
                info->Cipher |= eWSecAes;
                break;
            case WPA_CIPHER_AES_CCM:
                PRINTF(("AES-CCMP\n"));
                info->Cipher |= eWSecAes;
                break;
            default:
                PRINTF(("Unknown-%s(#%d)\n", rsn ? "RSN" : "WPA",
                       rsn_info.mcast->type));
                break;
            }
        }
        else {
            PRINTF(("Unknown-%02X:%02X:%02X(#%d) ",
                   rsn_info.mcast->oui[0], rsn_info.mcast->oui[1],
                   rsn_info.mcast->oui[2], rsn_info.mcast->type));
        }
    }

    /* Check for unicast suite(s) */
    if (rsn_info.ucast) {
        unicast_count = ltoh16_ua(&rsn_info.ucast->count);
        PRINTF(("\tunicast ciphers(%d): ", unicast_count));
        for (i = 0; i < unicast_count; i++) {
            suite = &rsn_info.ucast->list[i];
            if (!wlu_bcmp(suite->oui, std_oui, 3)) {
                switch (suite->type) {
                case WPA_CIPHER_NONE:
                    PRINTF(("NONE "));
                    info->Cipher |= eWSecNone;
                    break;
                case WPA_CIPHER_WEP_40:
                    PRINTF(("WEP64 "));
                    info->Cipher |= eWSecWep;
                    break;
                case WPA_CIPHER_WEP_104:
                    PRINTF(("WEP128 "));
                    info->Cipher |= eWSecWep;
                    break;
                case WPA_CIPHER_TKIP:
                    PRINTF(("TKIP "));
                    info->Cipher |= eWSecTkip;
                    break;
                case WPA_CIPHER_AES_OCB:
                    PRINTF(("AES-OCB "));
                    info->Cipher |= eWSecAes;
                    break;
                case WPA_CIPHER_AES_CCM:
                    PRINTF(("AES-CCMP "));
                    info->Cipher |= eWSecAes;
                    break;
                default:
                    PRINTF(("WPA-Unknown-%s(#%d) ", rsn ? "RSN" : "WPA",
                           suite->type));
                    break;
                }
            }
            else {
                PRINTF(("Unknown-%02X:%02X:%02X(#%d) ",
                    suite->oui[0], suite->oui[1], suite->oui[2],
                    suite->type));
            }
        }
        PRINTF(("\n"));
    }
    /* Authentication Key Management */
    if (rsn_info.akm) {
        akm_count = ltoh16_ua(&rsn_info.akm->count);
        PRINTF(("\tAKM Suites(%d): ", akm_count));
        for (i = 0; i < akm_count; i++) {
            suite = &rsn_info.akm->list[i];
            if (!wlu_bcmp(suite->oui, std_oui, 3)) {
                switch (suite->type) {
                case RSN_AKM_NONE:
                    PRINTF(("None "));
                    info->Akm |= RSN_AKM_NONE;
                    break;
                case RSN_AKM_UNSPECIFIED:
                    PRINTF(("WPA "));
                    info->Akm |= RSN_AKM_UNSPECIFIED;
                    break;
                case RSN_AKM_PSK:
                    PRINTF(("WPA-PSK "));
                    info->Akm |= RSN_AKM_PSK;
                    break;
                default:
                    PRINTF(("Unknown-%s(#%d)  ",
                           rsn ? "RSN" : "WPA", suite->type));
                    break;
                }
            }
            else {
                PRINTF(("Unknown-%02X:%02X:%02X(#%d)  ",
                    suite->oui[0], suite->oui[1], suite->oui[2],
                    suite->type));
            }
        }
        PRINTF(("\n"));
    }

    /* Capabilities */
    if (rsn_info.capabilities) {
        capabilities = ltoh16_ua(rsn_info.capabilities);
        PRINTF(("\tCapabilities(0x%04x): ", capabilities));
        if (rsn)
            PRINTF(("%sPre-Auth, ", (capabilities & RSN_CAP_PREAUTH) ? "" : "No "));

        PRINTF(("%sPairwise, ", (capabilities & RSN_CAP_NOPAIRWISE) ? "No " : ""));

        cntrs = wl_rsn_ie_decode_cntrs((capabilities & RSN_CAP_PTK_REPLAY_CNTR_MASK) >>
                                       RSN_CAP_PTK_REPLAY_CNTR_SHIFT);

        PRINTF(("%d PTK Replay Ctr%s", cntrs, (cntrs > 1)?"s":""));

        if (rsn) {
            cntrs = wl_rsn_ie_decode_cntrs(
                (capabilities & RSN_CAP_GTK_REPLAY_CNTR_MASK) >>
                RSN_CAP_GTK_REPLAY_CNTR_SHIFT);

            PRINTF(("%d GTK Replay Ctr%s\n", cntrs, (cntrs > 1)?"s":""));
        } else {
            PRINTF(("\n"));
        }
    } else {
        PRINTF(("\tNo %s Capabilities advertised\n", rsn ? "RSN" : "WPA"));
    }

}

void
wl_dump_wpa_rsn_ies(uint8* cp, uint len)
{
	uint8 *parse = cp;
	uint parse_len = len;
	uint8 *wpaie;
	uint8 *rsnie;
	WpaInfo_t info;

	while ((wpaie = wlu_parse_tlvs(parse, parse_len, DOT11_MNG_WPA_ID)))
		if (wlu_is_wpa_ie(&wpaie, &parse, &parse_len))
			break;
	if (wpaie)
		wl_rsn_ie_dump((bcm_tlv_t*)wpaie, &info);

	rsnie = wlu_parse_tlvs(cp, len, DOT11_MNG_RSN_ID);
	if (rsnie)
		wl_rsn_ie_dump((bcm_tlv_t*)rsnie, &info);

	return;
}
static void
dump_rateset(uint8 *rates, uint count)
{
	uint i;
	uint r;
	bool b;

	printf("[ ");
	for (i = 0; i < count; i++) {
		r = rates[i] & 0x7f;
		b = rates[i] & 0x80;
		if (r == 0)
			break;
		printf("%d%s%s ", (r / 2), (r % 2)?".5":"", b?"(b)":"");
	}
	printf("]");
}
void
dump_bss_info(wl_bss_info_t *bi)
{
	char ssidbuf[SSID_FMT_BUF_LEN];
	char chspec_str[CHANSPEC_STR_LEN];
	wl_bss_info_107_t *old_bi;
	int mcs_idx = 0;

	/* Convert version 107 to 109 */
	if (dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION) {
		old_bi = (wl_bss_info_107_t *)bi;
		bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel);
		bi->ie_length = old_bi->ie_length;
		bi->ie_offset = sizeof(wl_bss_info_107_t);
	}

	wl_format_ssid(ssidbuf, bi->SSID, bi->SSID_len);

	printf("SSID: \"%s\"\n", ssidbuf);

	printf("Mode: %s\t", capmode2str(dtoh16(bi->capability)));
	printf("RSSI: %d dBm\t", (int16)(dtoh16(bi->RSSI)));

	/*
	 * SNR has valid value in only 109 version.
	 * So print SNR for 109 version only.
	 */
	if (dtoh32(bi->version) == WL_BSS_INFO_VERSION) {
		printf("SNR: %d dB\t", (int16)(dtoh16(bi->SNR)));
	}

	printf("noise: %d dBm\t", bi->phy_noise);
	if (bi->flags) {
		bi->flags = dtoh16(bi->flags);
		printf("Flags: ");
		if (bi->flags & WL_BSS_FLAGS_FROM_BEACON) printf("FromBcn ");
		if (bi->flags & WL_BSS_FLAGS_FROM_CACHE) printf("Cached ");
		printf("\t");
	}
	printf("Channel: %s\n", wf_chspec_ntoa(dtohchanspec(bi->chanspec), chspec_str));

	printf("BSSID: %s\t", wl_ether_etoa(&bi->BSSID));

	printf("Capability: ");
	bi->capability = dtoh16(bi->capability);
	if (bi->capability & DOT11_CAP_ESS) printf("ESS ");
	if (bi->capability & DOT11_CAP_IBSS) printf("IBSS ");
	if (bi->capability & DOT11_CAP_POLLABLE) printf("Pollable ");
	if (bi->capability & DOT11_CAP_POLL_RQ) printf("PollReq ");
	if (bi->capability & DOT11_CAP_PRIVACY) printf("WEP ");
	if (bi->capability & DOT11_CAP_SHORT) printf("ShortPre ");
	if (bi->capability & DOT11_CAP_PBCC) printf("PBCC ");
	if (bi->capability & DOT11_CAP_AGILITY) printf("Agility ");
	if (bi->capability & DOT11_CAP_SHORTSLOT) printf("ShortSlot ");
	if (bi->capability & DOT11_CAP_CCK_OFDM) printf("CCK-OFDM ");
	printf("\n");

	printf("Supported Rates: ");
	dump_rateset(bi->rateset.rates, dtoh32(bi->rateset.count));
	printf("\n");
	if (dtoh32(bi->ie_length))
		wl_dump_wpa_rsn_ies((uint8 *)(((uint8 *)bi) + dtoh16(bi->ie_offset)),
		                    dtoh32(bi->ie_length));

	if (dtoh32(bi->version) != LEGACY_WL_BSS_INFO_VERSION && bi->n_cap) {
		printf("802.11N Capable:\n");
		bi->chanspec = dtohchanspec(bi->chanspec);
		printf("\tChanspec: %sGHz channel %d %dMHz (0x%x)\n",
			CHSPEC_IS2G(bi->chanspec)?"2.4":"5", CHSPEC_CHANNEL(bi->chanspec),
			CHSPEC_IS40(bi->chanspec) ? 40 : (CHSPEC_IS20(bi->chanspec) ? 20 : 10),
			bi->chanspec);
		printf("\tControl channel: %d\n", bi->ctl_ch);
		printf("\t802.11N Capabilities: ");
		if (dtoh32(bi->nbss_cap) & HT_CAP_40MHZ)
			printf("40Mhz ");
		if (dtoh32(bi->nbss_cap) & HT_CAP_SHORT_GI_20)
			printf("SGI20 ");
		if (dtoh32(bi->nbss_cap) & HT_CAP_SHORT_GI_40)
			printf("SGI40 ");
		printf("\n\tSupported MCS : [ ");
		for (mcs_idx = 0; mcs_idx < (MCSSET_LEN * 8); mcs_idx++)
			if (isset(bi->basic_mcs, mcs_idx))
				printf("%d ", mcs_idx);
		printf("]\n");
	}

	printf("\n");
}
/* Pretty print the BSS list */
void
dump_networks(char *network_buf)
{
	wl_scan_results_t *list = (wl_scan_results_t*)network_buf;
	wl_bss_info_t *bi;
	uint i;

	if (list->count == 0)
		return;
	else if (list->version != WL_BSS_INFO_VERSION &&
	         list->version != LEGACY2_WL_BSS_INFO_VERSION &&
	         list->version != LEGACY_WL_BSS_INFO_VERSION) {
		fprintf(stderr, "Sorry, your driver has bss_info_version %d "
			"but this program supports only version %d.\n",
			list->version, WL_BSS_INFO_VERSION);
		return;
	}

	bi = list->bss_info;
	for (i = 0; i < list->count; i++, bi = (wl_bss_info_t*)((int8*)bi + dtoh32(bi->length))) {
		dump_bss_info(bi);
	}
}
/* The below macros handle endian mis-matches between wl utility and wl driver. */
static bool g_swap = FALSE;

int
wl_check(void *wl)
{
	int ret;
	int val;

	if ((ret = wlu_get(wl, WLC_GET_MAGIC, &val, sizeof(int)) < 0))
		return ret;

	/* Detect if IOCTL swapping is necessary */
	if (val == (int)bcmswap32(WLC_IOCTL_MAGIC))
	{
		val = bcmswap32(val);
		g_swap = TRUE;
	}
	if (val != WLC_IOCTL_MAGIC)
		return -1;
	if ((ret = wlu_get(wl, WLC_GET_VERSION, &val, sizeof(int)) < 0))
		return ret;
	val = dtoh32(val);
	if (val > WLC_IOCTL_VERSION) {
		fprintf(stderr, "Version mismatch, please upgrade\n");
		return -1;
	}
	return 0;
}

int
wl_ether_atoe(const char *a, struct ether_addr *n)
{
	char *c = NULL;
	int i = 0;

	memset(n, 0, ETHER_ADDR_LEN);
	for (;;) {
		n->octet[i++] = (uint8)strtoul(a, &c, 16);
		if (!*c++ || i == ETHER_ADDR_LEN)
			break;
		a = c;
	}
	return (i == ETHER_ADDR_LEN);
}

/* Is this body of this tlvs entry a WPS entry? If */
/* not update the tlvs buffer pointer/length */
bool
bcm_is_wps_ie(uint8_t *ie, uint8_t **tlvs, uint32_t *tlvs_len)
{
    /* If the contents match the WPA_OUI and type=1 */
    if ((ie[TLV_LEN_OFF] > (WPA_OUI_LEN+1)) &&
        !bcmp(&ie[TLV_BODY_OFF], WPA_OUI "\x04", WPA_OUI_LEN + 1)) {
        return TRUE;
    }

    /* point to the next ie */
    ie += ie[TLV_LEN_OFF] + TLV_HDR_LEN;
    /* calculate the length of the rest of the buffer */
    *tlvs_len -= (int)(ie - *tlvs);
    /* update the pointer to the start of the buffer */
    *tlvs = ie;

    return FALSE;
}
