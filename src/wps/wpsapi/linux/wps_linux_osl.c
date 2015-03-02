/*
 * Broadcom WPS Enrollee linux OSL function
 *
 * This file is the linux specific implementation of the OS hooks necessary
 * for implementing the WPS API for WPS enrollee code.
 * It is mainly the implementation of eap transport but also add basic OS
 * layer interface
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_linux_osl.c 458775 2014-02-27 20:22:19Z $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <typedefs.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <asm/types.h>
#ifdef ASYNC_MODE
#include <pthread.h>
#endif

#include <wlioctl.h>
#include <wps_sdk.h>
#include <wps_api_osl.h>
#include <wpscommon.h>

extern void RAND_linux_init();

#define WPS_SCAN_MAX_WAIT_SEC 10

/*
* Do not define this value too short,
* because AP/Router may reboot after got new
* credential and apply it.
*/
#define WPS_JOIN_MAX_WAIT_SEC 60

#ifndef WL_SCAN_PARAMS_SSID_MAX
#define WL_SCAN_PARAMS_SSID_MAX         10
#endif

/*
 * Wireless Extension support is needed to read the
 * Wi-Fi interface name dynamically.
 */
#define ETHTOOL_GDRVINFO	0x00000003 /* Get driver info. */
#define ETHTOOL_BUSINFO_LEN	32
struct ethtool_drvinfo {
	__u32	cmd;
	char	driver[32];		/* driver short name, "tulip", "eepro100" */
	char	version[32];	/* driver version string */
	char	fw_version[32];	/* firmware version string, if applicable */
	char	bus_info[ETHTOOL_BUSINFO_LEN];	/* Bus info for this IF. */
						/* For PCI devices, use pci_dev->slot_name. */
	char	reserved1[32];
	char	reserved2[16];
	__u32	n_stats;		/* number of u64's from ETHTOOL_GSTATS */
	__u32	testinfo_len;
	__u32	eedump_len;		/* Size of data from ETHTOOL_GEEPROM (bytes) */
	__u32	regdump_len;	/* Size of data from ETHTOOL_GREGS (bytes) */
};

#define DEV_TYPE_LEN		4
#define ETH_8021X_PROT 0x888e

typedef struct WPS_OSL_S
{
	void *cb_ctx;			/* Client call back context */
	fnWpsProcessCB cb;		/* Client call back function for status update */
	wps_credentials *cred;

	char *run_ip;
	char run_cmd[256];
	char def_dhclient_pf[256];

	bool b_abort;
} WPS_OSL_T;
WPS_OSL_T *wps_osl_wksp = NULL;

static char ifname_lx[IFNAMSIZ] = "";
static uint8 peer_mac[6] = {0};
static int eap_fd = -1; /* descriptor to raw socket  */
static int ifindex = -1; /* interface index */
#ifdef ASYNC_MODE
static pthread_t g_pthread;
#endif

extern char* ether_ntoa(const struct ether_addr *addr);


#ifdef _TUDEBUGTRACE
void
wps_osl_print_buf(unsigned char *buff, int buflen)
{
	int i;

	WPS_PRINT(("\n print buf %d: \n", buflen));
	for (i = 0; i < buflen; i++) {
		WPS_PRINT(("%02X ", buff[i]));
		if (!((i+1)%16))
			WPS_PRINT(("\n"));
	}
	WPS_PRINT(("\n"));
}
#endif /* _TUDEBUGTRACE */

static int
_wps_osl_get_dev_type(char *name, void *buf, int len)
{
	int s;
	int ret = 0;
	struct ifreq ifr;
	struct ethtool_drvinfo info;

	/* Open socket to kernel */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
		/* Get device type */
		memset(&info, 0, sizeof(info));
		info.cmd = ETHTOOL_GDRVINFO;
		ifr.ifr_data = (caddr_t)&info;
		wps_strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
		if ((ret = ioctl(s, SIOCETHTOOL, &ifr)) < 0) {
			*(char *)buf = '\0';
		}
		else
			strncpy(buf, info.driver, len);

		close(s);
	}

	return ret;
}

static int
_wps_osl_get_interface_name(char *ifname, int ifname_len)
{
	struct ifreq ifr;
	char proc_net_dev[] = "/proc/net/dev";
	FILE *fp;
	char buf[1000], *c, *name;
	char dev_type[DEV_TYPE_LEN];
	int ret = -1;

	ifr.ifr_name[0] = '\0';

	if (!(fp = fopen(proc_net_dev, "r")))
		return ret;

	/* Eat first two lines */
	if (!fgets(buf, sizeof(buf), fp) ||
	    !fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return ret;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		c = buf;
		while (isspace(*c))
			c++;
		if (!(name = strsep(&c, ":")))
			continue;
		strncpy(ifr.ifr_name, name, IFNAMSIZ);
		if (_wps_osl_get_dev_type(name, dev_type, DEV_TYPE_LEN) >= 0 &&
		    (!strncmp(dev_type, "wl", 2) || !strncmp(dev_type, "dhd", 3))) {
			ret = 0;
			break;
		}

		ifr.ifr_name[0] = '\0';
	}

	fclose(fp);

	/* Copy back */
	if (ret == 0)
		strncpy(ifname, ifr.ifr_name, ifname_len);

	return ret;
}

/*
 * format an iovar buffer
 * iovar name is converted to lower case
 */
static uint
_wps_osl_iovar_mkbuf(const char *name, char *data, uint datalen, char *iovar_buf,
	uint buflen, int *perr)
{
	uint iovar_len;
	char *p;

	iovar_len = (uint)strlen(name) + 1;

	/* check for overflow */
	if ((iovar_len + datalen) > buflen) {
		*perr = -1;
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
 * set named iovar given the parameter buffer
 * iovar name is converted to lower case
 */
static int
_wps_osl_iovar_set(const char *iovar, void *param, int paramlen)
{
	int err;
	int iolen;
	char smbuf[WLC_IOCTL_SMLEN];

	memset(smbuf, 0, sizeof(smbuf));

	iolen = _wps_osl_iovar_mkbuf(iovar, param, paramlen, smbuf, sizeof(smbuf), &err);
	if (err)
		return err;

	return wps_osl_wl_ioctl(WLC_SET_VAR, smbuf, iolen, TRUE);
}

int
_wps_osl_do_wpa_psk(wps_credentials* credential)
{
	int ret = 0, retry;
	wlc_ssid_t ssid_t;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	char bssid[6];
	uint8 wsec = 0;
	int sup_wpa;
	wl_wsec_key_t wlkey;
	wsec_pmk_t pmk;
	unsigned char *data = wlkey.data;
	char hex[] = "XX";
	char *keystr, keystr_buf[SIZE_64_BYTES+1];
	int nwKeyLen;
	int i;


	ssid_t.SSID_len = strlen(credential->ssid);
	strncpy((char *)ssid_t.SSID, credential->ssid, ssid_t.SSID_len);

	/* get auth */
	auth = (strstr(credential->keyMgmt, "SHARED")) ? 1 : 0;

	/* get wpa_auth */
	if (strstr(credential->keyMgmt, "WPA-PSK"))
		wpa_auth |= WPA_AUTH_PSK;

	if (strstr(credential->keyMgmt, "WPA2-PSK")) {
		/* Always use WPA2PSK when both WPAPSK and WPA2PSK enabled */
		if (wpa_auth & WPA_AUTH_PSK)
			wpa_auth &= ~WPA_AUTH_PSK;

		wpa_auth |= WPA2_AUTH_PSK;
	}

	/* get wsec */
	if (credential->encrType & ENCRYPT_WEP)
		wsec |= WEP_ENABLED;
	if (credential->encrType & ENCRYPT_TKIP)
		wsec |= TKIP_ENABLED;
	if (credential->encrType & ENCRYPT_AES)
		wsec |= AES_ENABLED;

	/* Add in PF#3, use AES when encryptoin type in mixed-mode */
	if (wsec == (TKIP_ENABLED | AES_ENABLED))
		wsec &= ~TKIP_ENABLED;

	/* set infrastructure mode */
	infra = htod32(infra);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_INFRA, &infra, sizeof(int), TRUE)) < 0) {
		WPS_DEBUG(("Set INFRA %d failed\n", infra));
		return ret;
	}

	/* set mac-layer auth */
	auth = htod32(auth);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_AUTH, &auth, sizeof(int), TRUE)) < 0) {
		WPS_DEBUG(("Set AUTH %d failed\n", auth));
		return ret;
	}

	/* set wsec */
	if ((ret = wps_osl_wl_ioctl(WLC_SET_WSEC, &wsec, sizeof(int), TRUE)) < 0) {
		WPS_DEBUG(("Set WSEC %d failed\n", wsec));
		return ret;
	}

	/* set upper-layer auth */
	wpa_auth = htod32(wpa_auth);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth), TRUE)) < 0) {
		WPS_DEBUG(("Set WPA AUTH %d failed\n", wpa_auth));
		return ret;
	}

	/* set in-driver supplicant */
	sup_wpa = ((dtoh32(wpa_auth) & WPA_AUTH_PSK) == 0)? 0: 1;
	sup_wpa |= ((dtoh32(wpa_auth) & WPA2_AUTH_PSK) == 0)? 0: 1;

	sup_wpa = htod32(sup_wpa);
	if ((ret = _wps_osl_iovar_set("sup_wpa", &sup_wpa, sizeof(sup_wpa))) < 0) {
		WPS_DEBUG(("Set in-driver supplicant %d failed\n", sup_wpa));
		return ret;
	}

	/* set the key if wsec */
	if (wsec == WEP_ENABLED) {
		memset(&wlkey, 0, sizeof(wl_wsec_key_t));
		if (credential->wepIndex)
			wlkey.index = credential->wepIndex - 1;
		nwKeyLen = strlen(credential->nwKey);

		switch (nwKeyLen) {
		/* ASIC */
		case 5:
		case 13:
		case 16:
			wlkey.len = nwKeyLen;
			memcpy(data, credential->nwKey, wlkey.len + 1);
			break;
		case 10:
		case 26:
		case 32:
		case 64:
			wlkey.len = nwKeyLen / 2;
			memcpy(keystr_buf, credential->nwKey, nwKeyLen);
			keystr_buf[nwKeyLen] = '\0';
			keystr = keystr_buf;
			while (*keystr) {
				strncpy(hex, keystr, 2);
				*data++ = (char) strtoul(hex, NULL, 16);
				keystr += 2;
			}
			break;
		default:
			return -1;
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
			return -1;
		}

		/* Set as primary key by default */
		wlkey.flags |= WL_PRIMARY_KEY;

		wlkey.algo = htod32(wlkey.algo);
		wlkey.flags = htod32(wlkey.flags);
		wlkey.index = htod32(wlkey.index);
		wlkey.iv_initialized = htod32(wlkey.iv_initialized);
		wlkey.len = htod32(wlkey.len);
		for (i=0;i<18;i++) {
			wlkey.pad_1[i] = htod32(wlkey.pad_1[i]);
		}
		for (i=0;i<2;i++) {
			wlkey.pad_2[i] = htod32(wlkey.pad_2[i]);
		}
		wlkey.pad_3 = htod32(wlkey.pad_3);
		wlkey.pad_4 = htod32(wlkey.pad_4);
		for (i=0;i<2;i++) {
			wlkey.pad_5[i] = htod32(wlkey.pad_5[i]);
		}
		wlkey.rxiv.hi = htod32(wlkey.rxiv.hi);
		wlkey.rxiv.lo = htod32(wlkey.rxiv.lo);

		if ((ret = wps_osl_wl_ioctl(WLC_SET_KEY, &wlkey, sizeof(wlkey), TRUE)) < 0) {
			WPS_DEBUG(("Set KEY failed\n"));
			return ret;
		}
	}
	else if (wsec != 0) {
		memset(&pmk, 0, sizeof(wsec_pmk_t));
		nwKeyLen = strlen(credential->nwKey);
		if (nwKeyLen < WSEC_MIN_PSK_LEN || nwKeyLen > WSEC_MAX_PSK_LEN) {
			WPS_DEBUG(("passphrase must be between %d and %d"
				" characters long\n", WSEC_MIN_PSK_LEN, WSEC_MAX_PSK_LEN));
			return -1;
		}
		pmk.key_len = nwKeyLen;
		pmk.flags = WSEC_PASSPHRASE;
		strncpy((char *)pmk.key, credential->nwKey, nwKeyLen);
		pmk.flags = htod16(pmk.flags);
		pmk.key_len = htod16(pmk.key_len);
		if ((ret = wps_osl_wl_ioctl(WLC_SET_WSEC_PMK, &pmk, sizeof(pmk), TRUE)) < 0) {
			WPS_DEBUG(("Set WSEC PMK failed\n"));
			return ret;
		}
	}

	/* set ssid */
	ssid_t.SSID_len = htod32(ssid_t.SSID_len);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_SSID, &ssid_t, sizeof(wlc_ssid_t), TRUE)) == 0) {
		/* Poll for the results once a second until we got BSSID */
		for (retry = 0; retry < WPS_JOIN_MAX_WAIT_SEC; retry++) {
			/* User abort */
			if (wps_osl_wksp && wps_osl_wksp->b_abort) {
				ret = -1;
				goto abort;
			}

			wps_osl_sleep(1000); /* one second */

			ret = wps_osl_wl_ioctl(WLC_GET_BSSID, bssid, 6, FALSE);

			/* break out if the scan result is ready */
			if (ret == 0)
				break;

			if (retry != 0 && retry % 10 == 0) {
				if ((ret = wps_osl_wl_ioctl(WLC_SET_SSID, &ssid_t,
					sizeof(wlc_ssid_t), TRUE)) < 0)
					return ret;
			}
		}
	}

abort:
	return ret;

}

static int
_wps_osl_kill_def_dhclient(char *pf)
{
	FILE *fp = NULL;
	char tmp[128];
	int pid = -1;
	int ret;

	fp = fopen(pf, "r");
	if (!fp) {
		printf("Open %s failed\n", pf);
		goto error;
	}

	if (!fgets(tmp, sizeof(tmp), fp)) {
		printf("Get line failed\n");
		goto error;
	}

	sscanf(tmp, "%d", &pid);
	if (pid == -1) {
		printf("Get pid failed\n");
		goto error;
	}

	fclose(fp);

	/* Kill default dhclient */
	snprintf(tmp, sizeof(tmp), "kill -9 %d", pid);
	ret = system(tmp);
	sleep(1);

	return ret;

error:
	if (fp)
		fclose(fp);

	return -1;
}


#ifdef ASYNC_MODE
void *
wps_osl_thread_create(fnAsyncThread start_routine, void *arg)
{
	int retVal;

	if (start_routine == NULL) {
		WPS_DEBUG(("Thread create failed\n"));
		return NULL;
	}

	retVal = pthread_create(&g_pthread, NULL, start_routine, arg);

	if (retVal == 0) {
		WPS_DEBUG(("Thread created\n"));
		return (void *)&g_pthread;
	}

	WPS_DEBUG(("Thread create failed\n"));
	return NULL;
}

int
wps_osl_thread_join(void *thread, void **value_ptr)
{
	int retVal;

	if (thread == NULL) {
		WPS_DEBUG(("Thread join failed\n"));
		return -1;
	}

	retVal = pthread_join(*((pthread_t *)thread), value_ptr);
	if (retVal != 0) {
		WPS_DEBUG(("Thread join error\n"));
	} else {
		WPS_DEBUG(("Thread join successful\n"));
	}

	return retVal;
}
#endif /* ASYNC_MODE */

bool
wps_osl_create_profile(const struct _wps_credentials *credentials)
{
	WPS_DEBUG(("wps_osl_create_profile: Save credentials\n"));

	if (credentials == NULL) {
		if (wps_osl_wksp->cred != NULL) {
			free(wps_osl_wksp->cred);
			wps_osl_wksp->cred = NULL;
		}

		return FALSE;
	}

	if (wps_osl_wksp->cred == NULL &&
	    (wps_osl_wksp->cred = (wps_credentials *)malloc(sizeof(wps_credentials))) == NULL)
		return FALSE;

	*wps_osl_wksp->cred = *credentials;

	return TRUE;
}

int
wps_osl_get_mac(uint8 *mac)
{
	struct ifreq ifr;
	int ret = 0;
	int s;

	if (!ifname_lx[0]) {
		WPS_DEBUG(("Wireless Interface not specified.\n"));
		return WPS_OSL_ERROR;
	}

	/* Open a raw socket */
	if ((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
		WPS_DEBUG(("socket open failed\n"));
		return WPS_OSL_ERROR;
	}

	memset(&ifr, 0, sizeof(ifr));
	wps_strncpy(ifr.ifr_name, ifname_lx, sizeof(ifr.ifr_name));
	if ((ret = ioctl(s, SIOCGIFHWADDR, &ifr)) < 0) {
		WPS_DEBUG(("ioctl to get hwaddr failed, ret %x\n", ret));
		close(s);
		return WPS_OSL_ERROR;
	}

	/* Copy the result back */
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	close(s);
	return WPS_OSL_SUCCESS;
}

uint32
wps_osl_setup_802_1x(uint8 *bssid)
{
	struct ifreq ifr;
	struct sockaddr_ll ll;
	int err;

	if (!ifname_lx[0]) {
		WPS_DEBUG(("Wireless Interface not specified.\n"));
		return WPS_OSL_ERROR;
	}

	eap_fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_8021X_PROT));
	if (eap_fd == -1) {
		WPS_DEBUG(("UDP Open failed.\n"));
		return WPS_OSL_ERROR;
	}

	if (bssid)
		memcpy(peer_mac, bssid, 6);

	memset(&ifr, 0, sizeof(ifr));
	wps_strncpy(ifr.ifr_name, ifname_lx, sizeof(ifr.ifr_name));

	err = ioctl(eap_fd, SIOCGIFINDEX, &ifr);
	if (err < 0) {
		WPS_DEBUG(("Get interface index failed\n"));
		close(eap_fd);
		eap_fd = -1;
		return WPS_OSL_ERROR;
	}

	memset(&ll, 0, sizeof(ll));

	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ifindex  = ifr.ifr_ifindex;
	ll.sll_protocol = htons(ETH_8021X_PROT);
	if (bind(eap_fd, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
		WPS_DEBUG(("Bind interface failed\n"));
		close(eap_fd);
		eap_fd = -1;
		return WPS_OSL_ERROR;
	}

	return WPS_OSL_SUCCESS;
}

uint32
wps_osl_eap_read_data(char *dataBuffer, uint32 *dataLen, uint32 timeout_val)
{
	int recvBytes = 0;
	int fromlen;
	struct sockaddr_ll ll;
	fd_set fdvar;
	struct timeval timeout;


	if (!dataBuffer || !dataLen) {
		return WPS_OSL_ERROR;
	}

	timeout.tv_sec = timeout_val;
	timeout.tv_usec = 0;

	FD_ZERO(&fdvar);
	FD_SET(eap_fd, &fdvar);
	if (select(eap_fd + 1, &fdvar, NULL, NULL, &timeout) < 0) {
		WPS_DEBUG(("l2 select recv failed\n"));
		return WPS_OSL_ERROR;
	}

	if (FD_ISSET(eap_fd, &fdvar)) {
		memset(&ll, 0, sizeof(ll));
		fromlen = sizeof(ll);
		recvBytes = recvfrom(eap_fd, dataBuffer, *dataLen, 0, (struct sockaddr *) &ll,
			(socklen_t *)&fromlen);
		if (recvBytes == -1) {
			WPS_DEBUG(("UDP recv failed; recvBytes = %d\n", recvBytes));
			return WPS_OSL_ERROR;
		}
		/* make sure we received from our bssid */
		if (memcmp(peer_mac, &(ll.sll_addr), 6)) {
			WPS_DEBUG(("received frame from wrong AP %s\n",
				(char *)ether_ntoa((struct ether_addr *)(&ll.sll_addr))));
			return WPS_OSL_ERROR;
		}
		*dataLen = recvBytes;

#ifdef _TUDEBUGTRACE
		wps_osl_print_buf((unsigned char*)dataBuffer, *dataLen);
#endif
		return WPS_OSL_SUCCESS;
	}

	return WPS_OSL_TIMEOUT;
}

uint32
wps_osl_eap_send_data(char *dataBuffer, uint32 dataLen)
{
	int sentBytes = 0;
	struct sockaddr_ll ll;

#ifdef _TUDEBUGTRACE
	WPS_DEBUG(("L2 send buffer Length = %d\n", dataLen));
#endif

	if (!dataBuffer || !dataLen) {
		WPS_DEBUG(("Invalid Parameters\n"));
		return WPS_OSL_ERROR;
	}

#ifdef _TUDEBUGTRACE
	wps_osl_print_buf((unsigned char*)dataBuffer, dataLen);
#endif

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifindex;
	ll.sll_protocol = htons(ETH_8021X_PROT);
	ll.sll_halen = 6;
	memcpy(ll.sll_addr, peer_mac, 6);
	sentBytes = sendto(eap_fd, dataBuffer, dataLen, 0, (struct sockaddr *) &ll,
		sizeof(ll));

	if (sentBytes != (int32) dataLen) {
		WPS_DEBUG(("L2 send failed; sentBytes = %d\n", sentBytes));
		return WPS_OSL_ERROR;
	}

	return WPS_OSL_SUCCESS;
}

uint32
wps_osl_htonl(uint32 intlong)
{
	return htonl(intlong);
}

uint16
wps_osl_htons(uint16 intshort)
{
	return htons(intshort);
}

/* in MS */
void
wps_osl_sleep(uint32 ms)
{
	usleep(1000*ms);
}

unsigned long
wps_osl_get_current_time()
{
	struct timeval now;

	gettimeofday(&now, NULL);

	return now.tv_sec;
}

/* Link to wl driver. */
int
wps_osl_wl_ioctl(int cmd, void *buf, int len, bool set)
{
	struct ifreq ifr;
	wl_ioctl_t ioc;
	int ret = 0;
	int s;

	if (!ifname_lx[0]) {
		WPS_DEBUG(("Wireless Interface not specified.\n"));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	wps_strncpy(ifr.ifr_name, ifname_lx, sizeof(ifr.ifr_name));

	/* open socket to kernel */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	/* do it */
	ioc.cmd = cmd;
	ioc.buf = buf;
	ioc.len = len;
	ioc.set = set;
	ifr.ifr_data = (caddr_t) &ioc;
	if ((ret = ioctl(s, SIOCDEVPRIVATE, &ifr)) < 0) {
		if (cmd != WLC_GET_MAGIC) {
			ret = -2;
		}
	}

	/* cleanup */
	close(s);
	return ret;
}

void
wps_osl_update_led(unsigned int uiStatus, bool _b_secure_nw)
{
	return;
}

/* HW Button */
bool
wps_osl_hwbutton_supported(const char *guid)
{
	return FALSE;
}

bool
wps_osl_hwbutton_open(const char *guid)
{
	return FALSE;
}

void
wps_osl_hwbutton_close()
{
}

bool
wps_osl_hwbutton_state()
{
	return FALSE;
}

uint32
wps_osl_init(void *cb_ctx, void *cb, const char *adapter_id)
{
	char *ifname = (char*) adapter_id;
	char dyn_name[IFNAMSIZ];

	/* Duplicate wps_osl_init detection */
	if (wps_osl_wksp)
		return WPS_OSL_ERROR;

	/* Allocate wps_osl_init */
	if ((wps_osl_wksp = (WPS_OSL_T *)malloc(sizeof(WPS_OSL_T))) == NULL)
		return WPS_OSL_ERROR;
	memset(wps_osl_wksp, 0, sizeof(WPS_OSL_T));

	wps_osl_wksp->cb = (fnWpsProcessCB)cb;
	wps_osl_wksp->cb_ctx = cb_ctx;

	/* 1. RAND */
	RAND_linux_init();

	/* 2. Adapter, adapter_id is a interface name for Linux */
	if (adapter_id == NULL) {
		if (_wps_osl_get_interface_name(dyn_name, sizeof(dyn_name)) != WPS_OSL_SUCCESS) {
				WPS_DEBUG(("wps_osl_init : Failed to discover Wi-Fi interface.\n"));
				return WPS_OSL_ERROR;
		}
		ifname = dyn_name;
	}

	/* Save this specific interface for further use */
	wps_strncpy(ifname_lx, ifname, sizeof(ifname_lx));

	/* 3. WPS Led */

	/* 4. Disable wpa_supplicant */

	return WPS_OSL_SUCCESS;
}

void
wps_osl_deinit()
{
	if (eap_fd != -1)
		close(eap_fd);

	/* Enable wpa_supplicant */

	wps_osl_leave_network();
	wps_osl_sleep(1000); /* one second */

	if (wps_osl_wksp->cred != NULL) {
		/* Apply to driver */
		WPS_PRINT(("\nApply security to driver ... "));
		fflush(stdout);
		if (_wps_osl_do_wpa_psk(wps_osl_wksp->cred)) {
			WPS_PRINT(("Fail !!\n\n"));
		} else {
			WPS_PRINT(("Success !!\n\n"));

			/* Run IP */
			if (wps_osl_wksp->run_ip) {
				WPS_PRINT(("Set IP Address: run \"%s\"\n\n",
					wps_osl_wksp->run_cmd));

				/* Kill default dhclient */
				if (strcmp(wps_osl_wksp->run_ip, "def_dhcp") == 0 &&
				    _wps_osl_kill_def_dhclient(wps_osl_wksp->def_dhclient_pf) < 0)
					WPS_PRINT(("Cannot kill dhclient\n"));

				/* Launch run ip cmd */
				if (system(wps_osl_wksp->run_cmd) < 0)
					WPS_PRINT(("Cannot run %s\n", wps_osl_wksp->run_cmd));
			}
		}
	}

	if (wps_osl_wksp) {
		if (wps_osl_wksp->cred) {
			free(wps_osl_wksp->cred);
			wps_osl_wksp->cred = NULL;
		}

		free(wps_osl_wksp);
		wps_osl_wksp = NULL;
	}
}

void
wps_osl_abort()
{
	if (wps_osl_wksp == NULL)
		return;

	wps_osl_wksp->b_abort = TRUE;
}

#ifdef ESCAN_REQ_VERSION
/*
 * set named iovar given the parameter buffer
 * iovar name is converted to lower case
 */
static int
_wps_osl_iovar_setbuf(const char *iovar, void *param, int paramlen, void *smbuf, int buflen)
{
	int err;
	int iolen;

	memset(smbuf, 0, buflen);

	iolen = _wps_osl_iovar_mkbuf(iovar, param, paramlen, smbuf, buflen, &err);
	if (err)
		return err;

	return wps_osl_wl_ioctl(WLC_SET_VAR, smbuf, iolen, TRUE);
}

char *
wps_osl_get_escan_results(char *buf, int buf_len)
{
	#define ESCAN_EVENTS_BUFFER_SIZE     2048
	struct escan_bss {
		struct escan_bss *next;
		wl_bss_info_t bss[1];
	};
	#define ESCAN_BSS_FIXED_SIZE      sizeof(struct escan_bss *)
	int params_size = (WL_SCAN_PARAMS_FIXED_SIZE +
		(uint)(uintptr)&((wl_escan_params_t *)0)->params) +
		(WL_NUMCHANNELS * sizeof(uint16));
	wl_escan_params_t *params;
	int fd, err, octets;
	struct sockaddr_ll sll;
	struct ifreq ifr;
	char if_name[IFNAMSIZ] = {"eth0"};
	bcm_event_t *event;
	uint32 reason, status;
	char *data;
	int event_type;
	struct ether_addr *addr;
	uint8 event_inds_mask[WL_EVENTING_MASK_LEN];    /* 128-bit mask */
	wl_escan_result_t *escan_data;
	struct escan_bss *escan_bss_head = NULL;
	struct escan_bss *escan_bss_tail = NULL;
	struct escan_bss *result;

	wl_scan_results_t *list = (wl_scan_results_t*)buf;
	wl_bss_info_t *scan_bss;
	params_size += WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t);
	params = (wl_escan_params_t*)malloc(params_size);
	if (params == NULL) {
		fprintf(stderr, "Error allocating %d bytes for scan params\n", params_size);
		return NULL;
	}
	memset(params, 0, params_size);
	params->params.bss_type = DOT11_BSSTYPE_ANY;
	memcpy(&params->params.bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->params.scan_type = 0;
	params->params.nprobes = -1;
	params->params.active_time = -1;
	params->params.passive_time = -1;
	params->params.home_time = -1;
	params->params.channel_num = 0;

	memset(&ifr, 0, sizeof(ifr));
	_wps_osl_get_interface_name (if_name, sizeof(if_name));
	strncpy(ifr.ifr_name, if_name, (IFNAMSIZ - 1));

	memset(event_inds_mask, '\0', WL_EVENTING_MASK_LEN);
	event_inds_mask[WLC_E_ESCAN_RESULT / 8] |= 1 << (WLC_E_ESCAN_RESULT % 8);
	if ((err = _wps_osl_iovar_set("event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN)))
		goto exit2;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_BRCM));
	if (fd < 0) {
		printf("Cannot create socket %d\n", fd);
		err = -1;
		goto exit2;
	}

	err = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (err < 0) {
		printf("Cannot get index %d\n", err);
		close(fd);
		goto exit2;
	}

	/* bind the socket first before starting escan so we won't miss any event */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETHER_TYPE_BRCM);
	sll.sll_ifindex = ifr.ifr_ifindex;
	err = bind(fd, (struct sockaddr *)&sll, sizeof(sll));
	if (err < 0) {
		printf("Cannot bind %d\n", err);
		close(fd);
		goto exit2;
	}

	params->version = htod32(ESCAN_REQ_VERSION);
	params->action = htod16(WL_SCAN_ACTION_START);
#ifdef __linux__
	srand((unsigned)time(NULL));
	params->sync_id = rand() & 0xffff;
#else
	params->sync_id = 4321;
#endif /* __linux__ */
	params->sync_id = htod16(params->sync_id);

	params_size += (uint)(uintptr)&((wl_escan_params_t *)0)->params;

	if ((err = _wps_osl_iovar_setbuf("escan", params, params_size, buf, buf_len))<0)
	{
		WPS_DEBUG(( "escan does not work. Go to scan process (%d).\n", err));
		close(fd);
		goto exit2;
	}
	data = (char*)malloc(ESCAN_EVENTS_BUFFER_SIZE);

	if (data == NULL) {
		printf("Cannot not allocate %d bytes for events receive buffer\n",
			ESCAN_EVENTS_BUFFER_SIZE);
		err = -1;
		close(fd);
		goto exit2;
	}

	list->count = 0;
	list->version = WL_BSS_INFO_VERSION;
	scan_bss = list->bss_info;

	/* receive scan result */
	while (1) {
		octets = recv(fd, data, ESCAN_EVENTS_BUFFER_SIZE, 0);
		if (octets < 0) {
			WPS_DEBUG(("escan result recv failed; recvBytes = %d\n", octets));
			goto exit1;
		}
		event = (bcm_event_t *)data;
		addr = (struct ether_addr *)&(event->event.addr);
		event_type = ntohl(event->event.event_type);

		if ((event_type == WLC_E_ESCAN_RESULT) && (octets > 0)) {
			escan_data = (wl_escan_result_t*)&data[sizeof(bcm_event_t)];
			reason = ntohl(event->event.reason);
			status = ntohl(event->event.status);

			if (status == WLC_E_STATUS_PARTIAL) {
				wl_bss_info_t *bi = &escan_data->bss_info[0];
				wl_bss_info_t *bss;

				/* check if we've received info of same BSSID */
				for (result = escan_bss_head; result; result = result->next) {
					bss = result->bss;

#define WLC_BSS_RSSI_ON_CHANNEL 0x0002 /* Copied from wlc.h. Is there a better way to do this? */

					if (!memcmp(&bi->BSSID, &bss->BSSID, ETHER_ADDR_LEN) &&
						CHSPEC_BAND(bi->chanspec) ==
						CHSPEC_BAND(bss->chanspec) &&
						bi->SSID_len == bss->SSID_len &&
						!memcmp(bi->SSID, bss->SSID, bi->SSID_len))
						break;
				}

				if (!result) {
					/* New BSS. Allocate memory and save it */
#ifdef _TUDEBUGTRACE
					printf("bi->length = %d\n", dtoh32(bi->length));
#endif
					struct escan_bss *ebss = malloc(ESCAN_BSS_FIXED_SIZE
						+ dtoh32(bi->length));

					if (!ebss) {
						perror("can't allocate memory for bss");
						goto exit1;
					}

					ebss->next = NULL;
					memcpy(&ebss->bss, bi, dtoh32(bi->length));
					if (escan_bss_tail) {
						escan_bss_tail->next = ebss;
					} else {
						escan_bss_head = ebss;
					}
					escan_bss_tail = ebss;

					/* Copy bss info to scan buffer. */
					memcpy((int8*)scan_bss, (int8*)bi, dtoh32(bi->length));
					scan_bss = (wl_bss_info_t*)((int8*)scan_bss + dtoh32(bi->length));
					list->count++;
				} else {
					/* We've got this BSS. Update rssi if necessary */
					if ((bss->flags & WLC_BSS_RSSI_ON_CHANNEL) ==
						(bi->flags & WLC_BSS_RSSI_ON_CHANNEL)) {
						/* preserve max RSSI if the measurements are
						 * both on-channel or both off-channel
						 */
						bss->RSSI = (dtoh16(bss->RSSI) > dtoh16(bi->RSSI)) ? bss->RSSI : bi->RSSI;
					} else if ((bss->flags & WLC_BSS_RSSI_ON_CHANNEL) &&
						(bi->flags & WLC_BSS_RSSI_ON_CHANNEL) == 0) {
						/* preserve the on-channel rssi measurement
						 * if the new measurement is off channel
						*/
						bss->RSSI = bi->RSSI;
						bss->flags |= WLC_BSS_RSSI_ON_CHANNEL;
					}
				}
			} else if (status == WLC_E_STATUS_SUCCESS) {
				/* Escan finished. Let's go dump the results. */
				break;
			} else {
				printf("sync_id: %d, status:%d, misc. error/abort\n",
					dtoh16(escan_data->sync_id), status);
				goto exit1;
			}
		}
	}

	/* Revert back to match the results directly from WLC_SCAN */
	list->version = htod32(list->version);
	list->count = htod32(list->count);
	list->buflen = htod32(list->buflen);

exit1:
	/* free scan results */
	result = escan_bss_head;
	while (result) {
		struct escan_bss *tmp = result->next;
		free(result);
		result = tmp;
	}
	free(data);
	close(fd);

exit2:
	free(params);
	if (err < 0)
		return NULL;
	return buf;
}
#endif /* ESCAN_REQ_VERSION */

char *
wps_osl_get_scan_results(char *buf, int buf_len)
{
	int ret, retry;
	wl_scan_params_t* params;
	wl_scan_results_t *list = (wl_scan_results_t *)buf;
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(uint16);

#ifdef ESCAN_REQ_VERSION
	/* Use Escan */
	if (wps_osl_get_escan_results(buf, buf_len) != NULL)
		return buf;
#endif /* ESCAN_REQ_VERSION */

	/* Try scan process instead */
	params = (wl_scan_params_t*)malloc(params_size);
	if (params == NULL) {
		WPS_DEBUG(("Error allocating %d bytes for scan params\n", params_size));
		return NULL;
	}

	memset(params, 0, params_size);
	params->bss_type = DOT11_BSSTYPE_ANY;
	memcpy(&params->bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->scan_type = -1;
	params->nprobes = -1;
	params->active_time = -1;
	params->passive_time = -1;
	params->home_time = -1;
	params->channel_num = 0;

	if (wps_osl_wl_ioctl(WLC_SCAN, params, params_size, TRUE) < 0)
		return NULL;

	/* Poll for the results once a second until the scan is done */
	for (retry = 0; retry < WPS_SCAN_MAX_WAIT_SEC; retry++) {
		/* User abort */
		if (wps_osl_wksp && wps_osl_wksp->b_abort) {
			ret = -1;
			goto abort;
		}

		wps_osl_sleep(1000); /* one second */

		list->buflen = htod32(buf_len);
		ret = wps_osl_wl_ioctl(WLC_SCAN_RESULTS, buf, buf_len, FALSE);

		/* break out if the scan result is ready */
		if (ret == 0)
			break;
	}

abort:
	free(params);
	if (ret < 0)
		return NULL;

	return buf;
}

int
wps_osl_join_network(char* ssid, uint32 wsec)
{
	int ret = 0, retry;
	wlc_ssid_t ssid_t;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	char bssid[6];

	WPS_DEBUG(("Joining network %s - %d\n", ssid, wsec));

	/*
	 * If wep bit is on,
	 * pick any WPA encryption type to allow association.
	 * Registration traffic itself will be done in clear (eapol).
	*/
	if (wsec)
		wsec = 4; /* AES */
	ssid_t.SSID_len = strlen(ssid);
	strncpy((char *)ssid_t.SSID, ssid, ssid_t.SSID_len);

	/* set infrastructure mode */
	infra = htod32(infra);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_INFRA, &infra, sizeof(int), TRUE)) < 0)
		return ret;

	/* set authentication mode */
	auth = htod32(auth);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_AUTH, &auth, sizeof(int), TRUE)) < 0)
		return ret;

	/* set wsec mode */
	if ((ret = wps_osl_wl_ioctl(WLC_SET_WSEC, &wsec, sizeof(int), TRUE)) < 0)
		return ret;

	/* set WPA_auth mode */
	wpa_auth = htod32(wpa_auth);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth), TRUE)) < 0)
		return ret;

	/* set ssid */
	ssid_t.SSID_len = htod32(ssid_t.SSID_len);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_SSID, &ssid_t, sizeof(wlc_ssid_t), TRUE)) == 0) {
		/* Poll for the results once a second until we got BSSID */
		for (retry = 0; retry < WPS_JOIN_MAX_WAIT_SEC; retry++) {
			/* User abort */
			if (wps_osl_wksp && wps_osl_wksp->b_abort) {
				ret = -1;
				goto abort;
			}

			wps_osl_sleep(1000);

			ret = wps_osl_wl_ioctl(WLC_GET_BSSID, bssid, 6, FALSE);

			/* break out if the scan result is ready */
			if (ret == 0)
				break;

			if (retry != 0 && retry % 10 == 0) {
				if ((ret = wps_osl_wl_ioctl(WLC_SET_SSID, &ssid_t,
					sizeof(wlc_ssid_t), TRUE)) < 0)
					return ret;
			}
		}
	}

abort:
	return ret;
}

int
wps_osl_join_network_with_bssid(char* ssid, uint32 wsec, char *bssid)
{
#if !defined(WL_ASSOC_PARAMS_FIXED_SIZE) || !defined(WL_JOIN_PARAMS_FIXED_SIZE)
	return (wps_osl_join_network(ssid, wsec));
#else
	int ret = 0, retry;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	char associated_bssid[6];
	wl_join_params_t join_params;
	wlc_ssid_t *ssid_t = &join_params.ssid;
	wl_assoc_params_t *params_t = &join_params.params;

	WPS_DEBUG(("Joining network %s - %d\n", ssid, wsec));

	memset(&join_params, 0, sizeof(join_params));

	/*
	 * If wep bit is on,
	 * pick any WPA encryption type to allow association.
	 * Registration traffic itself will be done in clear (eapol).
	*/
	if (wsec)
		wsec = 4; /* AES */

	/* ssid */
	ssid_t->SSID_len = strlen(ssid);
	strncpy((char *)ssid_t->SSID, ssid, ssid_t->SSID_len);

	/* bssid (if any) */
	if (bssid)
		memcpy(&params_t->bssid, bssid, ETHER_ADDR_LEN);
	else
		memcpy(&params_t->bssid, &ether_bcast, ETHER_ADDR_LEN);

	/* set infrastructure mode */
	infra = htod32(infra);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_INFRA, &infra, sizeof(int), TRUE)) < 0)
		return ret;

	/* set authentication mode */
	auth = htod32(auth);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_AUTH, &auth, sizeof(int), TRUE)) < 0)
		return ret;

	/* set wsec mode */
	if ((ret = wps_osl_wl_ioctl(WLC_SET_WSEC, &wsec, sizeof(int), TRUE)) < 0)
		return ret;

	/* set WPA_auth mode */
	wpa_auth = htod32(wpa_auth);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth), TRUE)) < 0)
		return ret;

	/* set ssid */
	join_params.params.chanspec_num = htod32(join_params.params.chanspec_num);
	/* if chanspec_num ==0, use all available channels,
		otherwise count of chanspecs in chanspec_list.
	 */
	if (join_params.params.chanspec_num) {
		join_params.params.chanspec_list[0] = 
			htodchanspec(WPS_WL_CHSPEC_IOTYPE_HTOD(join_params.params.chanspec_list[0]));
	}
	join_params.ssid.SSID_len = htod32(join_params.ssid.SSID_len);
	if ((ret = wps_osl_wl_ioctl(WLC_SET_SSID, &join_params, sizeof(wl_join_params_t), TRUE))
		== 0) {
		/* Poll for the results once a second until we got BSSID */
		for (retry = 0; retry < WPS_JOIN_MAX_WAIT_SEC; retry++) {
			/* User abort */
			if (wps_osl_wksp && wps_osl_wksp->b_abort) {
				ret = -1;
				goto abort;
			}

			wps_osl_sleep(1000);

			ret = wps_osl_wl_ioctl(WLC_GET_BSSID, associated_bssid, 6, FALSE);

			/* break out if the scan result is ready */
			if (ret == 0)
				break;

			if (retry != 0 && retry % 10 == 0) {
				if ((ret = wps_osl_wl_ioctl(WLC_SET_SSID, &join_params,
					sizeof(wl_join_params_t), TRUE)) < 0)
					return ret;
			}
		}
	}

abort:
	return ret;
#endif /* !defined(WL_ASSOC_PARAMS_FIXED_SIZE) || !defined(WL_JOIN_PARAMS_FIXED_SIZE) */
}

int
wps_osl_leave_network()
{
	return wps_osl_wl_ioctl(WLC_DISASSOC, NULL, 0, TRUE);
}

void
wps_osl_set_run_ip(char *run_ip, char *ip_addr, char *user_dhcp)
{
	/* Clear run_ip first */
	wps_osl_wksp->run_ip = NULL;

	if (run_ip == NULL)
		return;

	if (strcmp(run_ip, "ip") == 0) {
		wps_osl_wksp->run_ip = "ip";
		snprintf(wps_osl_wksp->run_cmd, sizeof(wps_osl_wksp->run_cmd),
			"ifconfig %s %s", ifname_lx, ip_addr);
	} else {
		wps_osl_wksp->run_ip = "dhcp";
		if (user_dhcp) {
			/* Use user specified cmd */
			wps_osl_wksp->run_ip = "user_dhcp";
			wps_strncpy(wps_osl_wksp->run_cmd, user_dhcp,
				sizeof(wps_osl_wksp->run_cmd));
		} else {
			/* Use default dhclient cmd */
			wps_osl_wksp->run_ip = "def_dhcp";
			snprintf(wps_osl_wksp->def_dhclient_pf,
				sizeof(wps_osl_wksp->def_dhclient_pf),
				"/var/run/dhclient-%s.pid", ifname_lx);
			snprintf(wps_osl_wksp->run_cmd, sizeof(wps_osl_wksp->run_cmd),
				"/sbin/dhclient -pf %s", wps_osl_wksp->def_dhclient_pf);
		}
	}
}
