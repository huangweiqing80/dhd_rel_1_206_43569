/*
 * Broadcom WPS Enrollee
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_api.c 343243 2012-07-06 03:55:48Z $
 */

#include <stdio.h>
#include <signal.h>

#include <unistd.h>
#include <wpserror.h>
#include <wpsheaders.h>
#include <portability.h>
#include <reg_prototlv.h>
#include <wps_enrapi.h>
#include <wps_sta.h>
#include <wps_enr_osl.h>
#include <wps_staeapsm.h>
#include <wps_enr.h>
#include <wps_sdk.h>
#include <wpscommon.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/ioctl.h> 
#include <asm/types.h>
#ifdef TARGETENV_android
#include <sys/types.h>
#include <sys/socket.h>
#else
#include <linux/types.h>
#include <linux/sockios.h>
#endif
#include <net/if.h>
#include <wlioctl.h>

#ifdef DEBUG
#define DBGPRINT(x)	printf x
#else
#define DBGPRINT(x) do {} while(0)
#endif

#ifdef _TUDEBUGTRACE
void print_buf(unsigned char *buff, int buflen);
#endif

/* Wireless Extension support is needed to read the 
 * Wi-Fi interface name dynamically.
 */
#ifndef __user
#define __user
#endif

#define ETHTOOL_GDRVINFO	0x00000003 /* Get driver info. */
#define ETHTOOL_BUSINFO_LEN     32

struct ethtool_drvinfo {
	__u32	cmd;
	char	driver[32];	/* driver short name, "tulip", "eepro100" */
	char	version[32];	/* driver version string */
	char	fw_version[32];	/* firmware version string, if applicable */
	char	bus_info[ETHTOOL_BUSINFO_LEN];	/* Bus info for this IF. */
				/* For PCI devices, use pci_dev->slot_name. */
	char	reserved1[32];
	char	reserved2[16];
	__u32	n_stats;	/* number of u64's from ETHTOOL_GSTATS */
	__u32	testinfo_len;
	__u32	eedump_len;	/* Size of data from ETHTOOL_GEEPROM (bytes) */
	__u32	regdump_len;	/* Size of data from ETHTOOL_GREGS (bytes) */
};
#define DEV_TYPE_LEN	4

#define WPS_VERSION_STRING				"1000"
#define WPS_EAP_DATA_MAX_LENGTH         2048
#define WPS_EAP_READ_DATA_TIMEOUT         3
#define ARRAYSIZE(a)  (sizeof(a)/sizeof(a[0]))
#define WPS_DUMP_BUF_LEN (16 * 1024)

extern char *ether_ntoa(const struct ether_addr *addr);
extern void RAND_bytes(unsigned char *buf, int num);
bool CallClientCallback(unsigned int uiStatus, void *data);
extern wps_ap_list_info_t *wps_get_ap_list();
extern uint32 wps_generatePin(char c_devPwd[8], int buf_len, IN bool b_display);

typedef struct _ClientInfo
{
	char *bssid;
	char *ssid;
	char *pin;
	int mode;
	int retries;
	wps_credentials *credentials;
} ClientInfo;


bool b_wps_version2 = TRUE;
uint8 version2_number = WPS_VERSION2;

extern int wps_wl_check();

bool compare_mac(const uint8 *mac1, const uint8 *mac2)
{
	int i;

	if (mac1 && mac2) {
		for (i = 0; i < 6; i++)
			if (mac1[i] != mac2[i])
				return false;
		return true;
	}
	else {
		return false;
	}
}

static uint8 get_wep(const uint8 *bssid)
{
	wps_ap_list_info_t *ap_list = wps_get_ap_list();
	int i = 0;

	for (i = 0; i < WPS_MAX_AP_SCAN_LIST_LEN; i++) {
		// Find the ap according by comparing the mac address
		if (compare_mac(bssid, ap_list[i].BSSID))
			return ap_list[i].wep;
	}

	return 0;
}

int
get_dev_type(char *name, void *buf, int len)
{
	int s;
	int ret = 0;
	struct ifreq ifr;
	struct ethtool_drvinfo info;

	/* open socket to kernel */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
		/* get device type */
		memset(&info, 0, sizeof(info));
		info.cmd = ETHTOOL_GDRVINFO;
		ifr.ifr_data = (caddr_t)&info;
		wps_strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
		if ((ret = ioctl(s, SIOCETHTOOL, &ifr)) < 0) {
			*(char *)buf = '\0';
		}
		else
			wps_strncpy(buf, info.driver, len);

		close(s);
	}

	return ret;
}

int
get_interface_name(struct ifreq* ifr)
{
	char proc_net_dev[] = "/proc/net/dev";
	FILE *fp;
	char buf[1000], *c, *name;
	char dev_type[DEV_TYPE_LEN];
	int ret = -1;

	ifr->ifr_name[0] = '\0';

	if (!(fp = fopen(proc_net_dev, "r")))
		return ret;

	/* eat first two lines */
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
		wps_strncpy(ifr->ifr_name, name, sizeof(ifr->ifr_name));
		if (get_dev_type(name, dev_type, DEV_TYPE_LEN) >= 0 &&
		    (!strncmp(dev_type, "wl", 2) || !strncmp(dev_type, "dhd", 3))) {
			ret = 0;
			break;
		}

		ifr->ifr_name[0] = '\0';
	}

	fclose(fp);
	return ret;
}

/*
 * Fill up the device info and pass it to WPS.
 * This will need to be tailored to specific platforms (read from a file,
 * nvram ...)
 */
static void
config_init()
{
	DevInfo info;
	unsigned char mac[6];
	char uuid[16] = {0x22, 0x21, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0xa, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	/* fill in device specific info. The way this information is stored is app specific */
	/* Would be good to document all of these ...  */

	memset((char *)(&info), 0, sizeof(info));
	info.version = WPS_VERSION;

	/* MAC addr */
	wps_osl_get_mac(mac);
	memcpy(info.macAddr, mac, 6);

	/* generate UUID base on the MAC addr */
	memcpy(info.uuid, uuid, 16);
	memcpy(info.uuid + 10, mac, 6);

	strcpy(info.deviceName, "Broadcom Client");
	info.primDeviceCategory = 1;
	info.primDeviceOui = 0x0050F204;
	info.primDeviceSubCategory = 1;
	strcpy(info.manufacturer, "Broadcom");
	strcpy(info.modelName, "WPS Wireless Client");
	strcpy(info.modelNumber, "1234");
	strcpy(info.serialNumber, "5678");

	/*
	 * WSC 2.0, Default standalone STA.
	 * 0x0004 Label | 0x0280 Virtual Push Button | 
	 * 0x2008 Virtual Display PIN
	 */
	if (b_wps_version2) {
		info.configMethods = (WPS_CONFMET_LABEL | WPS_CONFMET_VIRT_PBC |
			WPS_CONFMET_VIRT_DISPLAY);
	} else {
		info.configMethods = WPS_CONFMET_LABEL | WPS_CONFMET_DISPLAY | WPS_CONFMET_PBC;
	}

	/* WSC 2.0, WPS-PSK and SHARED are deprecated.
	 * When both the Registrar and the Enrollee are using protocol version 2.0
	 * or newer, this variable can use the value 0x0022 to indicate mixed mode
	 * operation (both WPA-Personal and WPA2-Personal enabled)
	 */
	if (b_wps_version2) {
		info.authTypeFlags = (uint16)(WPS_AUTHTYPE_OPEN | WPS_AUTHTYPE_WPAPSK |
			WPS_AUTHTYPE_WPA | WPS_AUTHTYPE_WPA2 | WPS_AUTHTYPE_WPA2PSK);
	} else {
		info.authTypeFlags = (uint16)(WPS_AUTHTYPE_OPEN | WPS_AUTHTYPE_WPAPSK |
			WPS_AUTHTYPE_SHARED | WPS_AUTHTYPE_WPA | WPS_AUTHTYPE_WPA2 |
			WPS_AUTHTYPE_WPA2PSK);
	}

	/* ENCR_TYPE_FLAGS */
	/*
	 * WSC 2.0, deprecated WEP. TKIP can only be advertised on the AP when
	 * Mixed Mode is enabled (Encryption Type is 0x000c)
	 */
	if (b_wps_version2) {
		info.encrTypeFlags = (uint16)(WPS_ENCRTYPE_NONE | WPS_ENCRTYPE_TKIP |
			WPS_ENCRTYPE_AES);
	} else {
		info.encrTypeFlags = (uint16)(WPS_ENCRTYPE_NONE | WPS_ENCRTYPE_WEP |
			WPS_ENCRTYPE_TKIP | WPS_ENCRTYPE_AES);
	}

	info.connTypeFlags = WPS_CONNTYPE_ESS;

	/* rfBand will update again later */
	info.rfBand = WPS_RFBAND_24GHZ | WPS_RFBAND_50GHZ;

	info.osVersion = 0x80000000;
	info.featureId = 0x80000000;

	/* WSC 2.0 */
	if (b_wps_version2) {
		info.version2 = version2_number;
		info.settingsDelayTime = WPS_SETTING_DELAY_TIME_LINUX;
		info.b_reqToEnroll = TRUE;
		info.b_nwKeyShareable = FALSE;
	}

#ifdef WFA_WPS_20_TESTBED
	/* For internal testing purpose, do zero padding */
	info.b_zpadding = b_zpadding;
	info.b_mca = false;
	memcpy(info.nattr_tlv, nattr_tlv, nattr_len);
	info.nattr_len = nattr_len;
#endif /* WFA_WPS_20_TESTBED */

	wpssta_enr_init(&info);
}

/* Main loop. */
static int
registration_loop(unsigned long start_time)
{
	uint32 retVal;
	char buf[WPS_EAP_DATA_MAX_LENGTH];
	uint32 len;
	char *sendBuf;
	unsigned long now;
	int last_recv_msg, last_sent_msg;
	int state;
	char msg_type;

	now = get_current_time();

	/*
	 * start the process by sending the eapol start . Created from the
	 * Enrollee SM Initialize.
	 */
	len = wps_get_msg_to_send(&sendBuf, (uint32)now);

#ifdef _TUDEBUGTRACE
	print_buf((unsigned char*)sendBuf, len);
#endif

	if (sendBuf) {
		send_eapol_packet(sendBuf, len);
		DBGPRINT(("Send EAPOL-Start\n"));
	}
	else {
		/* this means the system is not initialized */
		return WPS_ERR_NOT_INITIALIZED;
	}

	/* loop till we are done or failed */
	while (1) {
		len = WPS_EAP_DATA_MAX_LENGTH;

		now = get_current_time();

		if (now > start_time + 120) {
			DBGPRINT(("Overall protocol timeout \n"));
			return REG_FAILURE;
		}

		if ((retVal = wait_for_eapol_packet(buf, &len, WPS_EAP_READ_DATA_TIMEOUT))
			== WPS_SUCCESS) {

			/* Show receive message */
			msg_type = wps_get_msg_type(buf, len);
			DBGPRINT(("Receive EAP-Request%s\n", wps_get_msg_string((int)msg_type)));

			/* process ap message */
			retVal = wps_process_ap_msg(buf, len);

			/* check return code to do more things */
			if (retVal == WPS_SEND_MSG_CONT ||
				retVal == WPS_SEND_MSG_SUCCESS ||
				retVal == WPS_SEND_MSG_ERROR ||
				retVal == WPS_ERR_ENROLLMENT_PINFAIL) {
				len = wps_get_eapol_msg_to_send(&sendBuf, now);
				if (sendBuf) {
					msg_type = wps_get_msg_type(sendBuf, len);

					send_eapol_packet(sendBuf, len);
					DBGPRINT(("Send EAP-Response%s\n",
						wps_get_msg_string((int)msg_type)));
				}

				if (retVal == WPS_ERR_ENROLLMENT_PINFAIL)
					retVal = WPS_SEND_MSG_ERROR;

				/*
				 * sleep a short time for driver to send last WPS DONE message,
				 * otherwise doing leave_network before do_wpa_psk in
				 * enroll_device() may cause driver to drop the last WPS DONE
				 * message if it not transmit.
				 */
				if (retVal == WPS_SEND_MSG_SUCCESS ||
				    retVal == WPS_SEND_MSG_ERROR)
					WpsSleepMs(2);

				/* over-write retVal */
				if (retVal == WPS_SEND_MSG_SUCCESS)
					retVal = WPS_SUCCESS;
				else if (retVal == WPS_SEND_MSG_ERROR)
					retVal = REG_FAILURE;
				else
					retVal = WPS_CONT;
			}
			else if (retVal == EAP_FAILURE) {
				/* we received an eap failure from registrar */
				/*
				 * check if this is coming AFTER the protocol passed the M2
				 * mark or is the end of the discovery after M2D.
				 */
				last_recv_msg = wps_get_recv_msg_id();
				DBGPRINT(("Received eap failure, last recv msg EAP-Request%s\n",
					wps_get_msg_string(last_recv_msg)));
				if (last_recv_msg > WPS_ID_MESSAGE_M2D)
					return REG_FAILURE;
				else
					return WPS_CONT;
			}
			/* special case, without doing wps_eap_create_pkt */
			else if (retVal == WPS_SEND_MSG_IDRESP) {
				len = wps_get_msg_to_send(&sendBuf, now);
				if (sendBuf) {
					send_eapol_packet(sendBuf, len);
					DBGPRINT(("Send EAP-Response / Identity\n"));
				}
			}
			/* Re-transmit last sent message, because we receive a re-transmit packet */
			else if (retVal == WPS_SEND_RET_MSG_CONT) {
				len = wps_get_retrans_msg_to_send(&sendBuf, now, &msg_type);
				if (sendBuf) {
					state = wps_get_eap_state();

					if (state == EAPOL_START_SENT)
						DBGPRINT(("Re-Send EAPOL-Start\n"));
					else if (state == EAP_IDENTITY_SENT)
						DBGPRINT(("Re-Send EAP-Response / Identity\n"));
					else
						DBGPRINT(("Re-Send EAP-Response%s\n",
							wps_get_msg_string((int)msg_type)));

					send_eapol_packet(sendBuf, len);
				}
			}
			else if (retVal == WPS_SEND_FRAG_CONT ||
				retVal == WPS_SEND_FRAG_ACK_CONT) {
				len = wps_get_frag_msg_to_send(&sendBuf, now);
				if (sendBuf) {
					if (retVal == WPS_SEND_FRAG_CONT)
						DBGPRINT(("Send EAP-Response(FRAG)\n"));
					else
						DBGPRINT(("Send EAP-Response(FRAG_ACK)\n"));

					send_eapol_packet(sendBuf, len);
				}
			}

			/* SUCCESS or FAILURE or PROCESSING ERROR */
			if (retVal == WPS_SUCCESS || retVal == REG_FAILURE ||
				retVal == WPS_MESSAGE_PROCESSING_ERROR) {
				return retVal;
			}
		}
		/* timeout with no data, should we re-transmit ? */
		else if (retVal == EAP_TIMEOUT) {
			/* check eap receive timer. It might be time to re-transmit */
			/*
			 * Do we need this API ? We could just count how many
			 * times we re-transmit right here.
			 */
			if ((retVal = wps_eap_check_timer(now)) == WPS_SEND_RET_MSG_CONT) {
				len = wps_get_retrans_msg_to_send(&sendBuf, now, &msg_type);
				if (sendBuf) {
					state = wps_get_eap_state();

					if (state == EAPOL_START_SENT)
						DBGPRINT(("Re-Send EAPOL-Start\n"));
					else if (state == EAP_IDENTITY_SENT)
						DBGPRINT(("Re-Send EAP-Response / Identity\n"));
					else
						DBGPRINT(("Re-Send EAP-Response%s\n",
							wps_get_msg_string((int)msg_type)));

					send_eapol_packet(sendBuf, len);
				}
			}
			/* re-transmission count exceeded, give up */
			else if (retVal == EAP_TIMEOUT) {
				last_recv_msg = wps_get_recv_msg_id();

				if (last_recv_msg == WPS_ID_MESSAGE_M2D) {
					DBGPRINT(("M2D Wait timeout, again.\n"));
				}
				else if (last_recv_msg > WPS_ID_MESSAGE_M2D) {
					last_sent_msg = wps_get_sent_msg_id();
					DBGPRINT(("Timeout, last recv/sent msg "
						"[EAP-Response%s/EAP-Request%s], again.\n",
						wps_get_msg_string(last_recv_msg),
						wps_get_msg_string(last_sent_msg)));
				}
				else {
					DBGPRINT(("Re-transmission count exceeded, again\n"));
				}

				return WPS_CONT;
			}
		}
	}

	return WPS_SUCCESS;
}

static bool
enroll_device(int mode, uint8 *bssid, char *ssid, char *pin)
{
	int ret = WPS_SUCCESS;
	bool bRet = false;
	unsigned long start_time;
	uint band_num, active_band;
	uint8 *bssid_ptr = bssid;
	uint8 cur_bssid[6];
	int nRegAttempts = 0;

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
	if (!bssid_ptr) {
		if (wps_get_bssid((char *)cur_bssid)) {
			DBGPRINT(("Can not get [%s] BSSID, Quit....\n", ssid));
			goto done;
		}
		bssid_ptr = cur_bssid;
	}

	/* setup raw 802.1X socket with "bssid" destination  */
	if (wps_osl_init((char *)bssid_ptr) != WPS_SUCCESS) {
		DBGPRINT(("Initializing 802.1x raw socket failed. \n"));
		DBGPRINT(("Check PF PACKET support in kernel. \n"));
		CallClientCallback(WPS_STATUS_ERROR,NULL);
		wps_osl_deinit();
		goto done;
	}

	start_time = get_current_time();
	DBGPRINT(("Starting WPS enrollment.\n"));

	while (1) {

		nRegAttempts++;  // Calculate total protocol registration attempts

		if ((ret = wpssta_start_enrollment(pin, get_current_time())) != WPS_SUCCESS)
			break;

		/* registration loop */
		/*
		 * exits with either success, failure or indication that
		 * the registrar has not started its end of the protocol yet.
		*/
		if ((ret = registration_loop(start_time)) == WPS_SUCCESS) {
			bRet = true;
			break;
		}
		/* the registrar is not started, maybe the user is walking or entering 
		   the PIN. Try again.
		 */
		else if (ret == WPS_CONT) {
			int i = 10;

			// We allow 3 attemps of protocol registration, so the maximum process time is 6 minutes as 
			// each protocol timeout is 2 minutes 
			if (nRegAttempts > 3) {
				DBGPRINT(("Overall WPS negotiation timeout \n"));
				CallClientCallback(WPS_STATUS_OVERALL_PROCESS_TIMOUT, NULL);
				break;
			}

			DBGPRINT(("Waiting for Registrar\n"));
			while (CallClientCallback(WPS_STATUS_IDLE, NULL) && i--)
				WpsSleepMs(100);

			if (!CallClientCallback(WPS_STATUS_IDLE, NULL))
				goto done;
			
			// Re-join/re-associate network. This is required to work with (be compatible to) old broadcom AP firmware
			join_network(ssid, get_wep(bssid));
		}
		else {
			DBGPRINT(("WPS Protocol FAILED \n"));
			CallClientCallback(WPS_STATUS_ERROR, NULL);
			break;
		}
	}

done:
	if (!CallClientCallback(WPS_STATUS_DISCONNECTING, NULL))
		bRet = false;

	leave_network();

	return bRet;
}

int
set_mac_address(char *mac_string, char *mac_bin)
{
	int i = 0;
	char *endptr, *nptr;
	long val;

	nptr = mac_string;

	do {
		val = strtol(nptr, &endptr, 16);
		if (val > 255) {
			DBGPRINT(("invalid MAC address\n"));
			return -1;
		}

		if (endptr == nptr) {
			/* no more digits. */
			if (i != 6) {
				DBGPRINT(("invalid MAC address\n"));
				return -1;
			}
			return 0;
		}

		if (i >= 6) {
			DBGPRINT(("invalid MAC address\n"));
			return -1;
		}

		mac_bin[i++] = val;
		nptr = endptr+1;
	} while (nptr[0]);

	if (i != 6) {
		DBGPRINT(("invalid MAC address\n"));
		return -1;
	}

	return 0;
}

#ifdef _TUDEBUGTRACE
void
print_buf(unsigned char *buff, int buflen)
{
	int i;
	DBGPRINT(("\n print buf : \n"));
	for (i = 0; i < buflen; i++) {
		DBGPRINT(("%02X ", buff[i]));
		if (!((i+1)%16))
			printf("\n");
	}
	printf("\n");
}
#endif

void
hup_hdlr(int sig)
{
	/*
	 * In case we are in find_pbc_ap loop,
	 * force to remove probe request pbc ie
	 */
	rem_wps_ie(NULL, 0, VNDR_IE_PRBREQ_FLAG);
	if (b_wps_version2)
		rem_wps_ie(NULL, 0, VNDR_IE_ASSOCREQ_FLAG);
	
	wps_osl_deinit();
	exit(0);
}

/**********************************************************************************************/
/* WPS SDK global declarations                                                               */
/**********************************************************************************************/

bool gIsOpened = false;
void *gContext = NULL;
fnWpsProcessCB g_wps_join_callback = NULL;

/**********************************************************************************************/
/* WPS SDK supporting functions                                                               */
/**********************************************************************************************/
static void reg_config_init(WpsEnrCred *credential, char *bssid)
{
	DevInfo info;
	char uuid[16] = {0x22, 0x21, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0xa, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	char nwKey[SIZE_64_BYTES+1], *Key = NULL;
	uint8 mac[6];

	/* fill in device default info */
	memset((char *)(&info), 0, sizeof(info));
	info.version = WPS_VERSION;

	/* MAC addr */
	wps_osl_get_mac(mac);
	memcpy(info.macAddr, mac, 6);  // Fill mac address

	/* generate UUID base on the MAC addr */
	memcpy(info.uuid, uuid, 16);
	memcpy(info.uuid + 10, mac, 6);

	strcpy(info.deviceName, "Broadcom Registrar");
	info.primDeviceCategory = 1;
	info.primDeviceOui = 0x0050F204;
	info.primDeviceSubCategory = 1;
	strcpy(info.manufacturer, "Broadcom");
	strcpy(info.modelName, "WPS Wireless Registrar");
	strcpy(info.modelNumber, "1234");
	strcpy(info.serialNumber, "5678");
	/*
	 * WSC 2.0, Default standalone STA.
	 * 0x0004 Label | 0x0280 Virtual Push Button | 
	 * 0x2008 Virtual Display PIN
	 */
	if (b_wps_version2) {
		info.configMethods = (WPS_CONFMET_LABEL | WPS_CONFMET_VIRT_PBC |
			WPS_CONFMET_VIRT_DISPLAY);
	} else {
		info.configMethods = WPS_CONFMET_LABEL | WPS_CONFMET_DISPLAY | WPS_CONFMET_PBC;
	}

	/* WSC 2.0, WPS-PSK and SHARED are deprecated.
	 * When both the Registrar and the Enrollee are using protocol version 2.0
	 * or newer, this variable can use the value 0x0022 to indicate mixed mode
	 * operation (both WPA-Personal and WPA2-Personal enabled)
	 */
	if (b_wps_version2) {
		info.authTypeFlags = (uint16)(WPS_AUTHTYPE_OPEN | WPS_AUTHTYPE_WPAPSK |
			WPS_AUTHTYPE_WPA | WPS_AUTHTYPE_WPA2 | WPS_AUTHTYPE_WPA2PSK);
	} else {
		info.authTypeFlags = (uint16)(WPS_AUTHTYPE_OPEN | WPS_AUTHTYPE_WPAPSK |
			WPS_AUTHTYPE_SHARED | WPS_AUTHTYPE_WPA | WPS_AUTHTYPE_WPA2 |
			WPS_AUTHTYPE_WPA2PSK);
	}

	/* ENCR_TYPE_FLAGS */
	/*
	 * WSC 2.0, deprecated WEP. TKIP can only be advertised on the AP when
	 * Mixed Mode is enabled (Encryption Type is 0x000c)
	 */
	if (b_wps_version2) {
		info.encrTypeFlags = (uint16)(WPS_ENCRTYPE_NONE | WPS_ENCRTYPE_TKIP |
			WPS_ENCRTYPE_AES);
	} else {
		info.encrTypeFlags = (uint16)(WPS_ENCRTYPE_NONE | WPS_ENCRTYPE_WEP |
			WPS_ENCRTYPE_TKIP | WPS_ENCRTYPE_AES);
	}

	info.connTypeFlags = WPS_CONNTYPE_ESS;

	/* rfBand will update again later */
	info.rfBand = WPS_RFBAND_24GHZ;

	info.osVersion = 0x80000000;
	info.featureId = 0x80000000;

	/* WSC 2.0 */
	if (b_wps_version2) {
		info.version2 = version2_number;
		info.settingsDelayTime = WPS_SETTING_DELAY_TIME_LINUX;
		info.b_reqToEnroll = FALSE;
		info.b_nwKeyShareable = FALSE;
	}

	/* replease if need */
	if (credential) {
		/* SSID */
		wps_strncpy(info.ssid, credential->ssid, sizeof(info.ssid));

		/* keyMgmt */
		wps_strncpy(info.keyMgmt, credential->keyMgmt, sizeof(info.keyMgmt));
		/* crypto */
		info.crypto = credential->encrType;
		if(credential->encrType & WPS_ENCRTYPE_WEP)
			info.wep = 1;
		else
			info.wep = 0;

		/* nwKey */
		wps_strncpy(nwKey, credential->nwKey, sizeof(nwKey));
		Key = nwKey;
	}

#ifdef WFA_WPS_20_TESTBED
	/* For internal testing purpose, do zero padding */
	info.b_zpadding = b_zpadding;
	info.b_mca = b_mca;
	strcpy(info.dummy_ssid, "DUMMY SSID");
	memcpy(info.nattr_tlv, nattr_tlv, nattr_len);
	info.nattr_len = nattr_len;
#endif /* WFA_WPS_20_TESTBED */

	wpssta_reg_init(&info, Key, bssid);
}

static void get_random_credential(WpsEnrCred *credential)
{
	/* ssid */
	uint8 mac[6];
	unsigned short ssid_length, key_length;
	unsigned char random_ssid[33] = {0};
	unsigned char random_key[65] = {0};
	char macString[18];
	int i;

	wps_osl_get_mac(mac);
	sprintf(macString, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	RAND_bytes((unsigned char *)&ssid_length, sizeof(ssid_length));
	ssid_length = ((((long)ssid_length + 56791)*13579)%23) + 1;

	RAND_bytes(random_ssid, ssid_length);

	for (i = 0; i < ssid_length; i++) 
	{
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

	memset(credential, 0, sizeof(WpsEnrCred));

	strcpy(credential->ssid, (char *)random_ssid);

	/* WSC 2.0, WPA2-PSK/AES is compatible in V1 and V2 */
	/* keyMgmt */
	strcpy(credential->keyMgmt, "WPA2-PSK");

	/* network key */
	RAND_bytes((unsigned char *)&key_length, sizeof(key_length));
	key_length = ((((long)key_length + 56791)*13579)%8) + 8;
	i = 0;
	while (i < key_length) {
		RAND_bytes(&random_key[i], 1);
		if ((islower(random_key[i]) || isdigit(random_key[i])) && (random_key[i] < 0x7f)) {
			i++;
		}
	}
	wps_strncpy(credential->nwKey, (char *)random_key, sizeof(credential->nwKey));
	credential->nwKeyLen = strlen(credential->nwKey);

	/* Crypto */
	credential->encrType = ENCRYPT_AES;
}

// Given a list of wps aps, find the pbc ap and set it to the first one in the given ap list
static int get_pbc_ap(wps_ap_list_info_t *list_inout, int count, int *nAP)
{
	char bssid[6];  // bssid is a 48-bit identifier
	char ssid[32] = { 0 };
	uint8 wep = 1;
	int nRet = PBC_NOT_FOUND;
	int i = 0;

	*nAP = 0;
	nRet = wps_get_pbc_ap(&list_inout[0], bssid, ssid, &wep, get_current_time(), (char)1);
	if (nRet == PBC_FOUND_OK) {
		// Search the wps ap list and set the pbc ap (only one is allowed currently) to the first 
		// one in this given ap list
		while (i < count) {
			if (strcasecmp((char*)list_inout[i].ssid, ssid) == 0) {
				// if i=0, the list one in the ap list is pbc ap, no need to copy
				if (i > 0)
					memcpy(&list_inout[0], &list_inout[i],
						sizeof(wps_ap_list_info_t));
				*nAP = 1;
				break;
			}
			i++;
		}
	}

	return nRet;
}
bool CallClientCallback(unsigned int uiStatus, void *data)
{
	if (!gIsOpened)
		return false;

	if (g_wps_join_callback != NULL) {
		if (!g_wps_join_callback(gContext, uiStatus, data)) {
			g_wps_join_callback(gContext, WPS_STATUS_CANCELED, NULL);
			g_wps_join_callback = NULL; // Disable any more notification to the client at this point
			return FALSE;
		}

		if (uiStatus == WPS_STATUS_SUCCESS || uiStatus == WPS_STATUS_CANCELED ||
		    uiStatus == WPS_STATUS_ERROR) {
			g_wps_join_callback = NULL; // Disable any more notification to the client at this point
		}
	}

	return TRUE;

}

/**********************************************************************************************/
/* WPS SDK APIs                                                                               */
/**********************************************************************************************/
/*
 wps_open function must be called first, before any other wps api call
*/
bool wps_open(void *context, fnWpsProcessCB callback, char if_name[], bool v2)
{
	struct ifreq ifr;

	DBGPRINT(("Entered : wps_open\n"));

	if(gIsOpened)
		return false;

	gContext = NULL;
	g_wps_join_callback = NULL;

	if (NULL == if_name) {
		if( 0 != get_interface_name(&ifr)) {
			DBGPRINT(("wps_open : Failed to discover Wi-Fi interface.\n"));
			return false;
		}
		wps_osl_set_ifname(ifr.ifr_name);
	} else
		wps_osl_set_ifname(if_name);

	gContext = context;
	g_wps_join_callback = callback;
	gIsOpened = true;
	b_wps_version2 = v2;

	/* Setup endian swap*/
	if (wps_wl_check())
		return false;

	CallClientCallback(WPS_STATUS_INIT, NULL);

	/* 
	setup device configuration for WPS 
	needs to be done before eventual scan for PBC.
	*/ 

	config_init();
	DBGPRINT(("Exit : wps_open\n"));
	return true;
}

/*
 wps_close function must be called once you are done using the wps api
*/
bool wps_close(void)
{
	DBGPRINT(("Entered : wps_close\n"));

	if (!gIsOpened)
		return false;
	
	gContext = NULL;
	g_wps_join_callback = NULL;
	gIsOpened = false;

	wps_cleanup();
	wps_osl_deinit();

	DBGPRINT(("Exit : wps_close\n"));
	return true;
}

/*
 wps_findAP scans for WPS PBC APs and returns the one with the strongest RSSI
 Returns true if it finds an AP within the specified time. This function is designed to
 be called repeatidly with small timeouts in seconds (say 4 or 5 secs) to allow for UI updates and user
 cancelation. If multiple PBC APs are found, this is an error condition and FALSE is returned. nAP will
 contain the number of PBC APs found (will be greater than 1).

 The value of *nAP is updated with the number of APs found. For PBC APs, it will be always 1 on success (or
 if more than 1 is returned, the UI should warn the user to try again later).
 For PIN APs, it will varie from 0 to the max numbers of the list.

 Call wps_getAP to get the APs found
*/
bool wps_findAP(int *nAP, int mode, int timeout)
{
	int wps_ap_total = 0;
	wps_ap_list_info_t *wpsaplist;
	uint32 start_time;

	DBGPRINT(("Entered : wps_findAP\n"));
	if (!gIsOpened)
		return false;

	// add wps ie to probe
	add_wps_ie(NULL, 0, (mode == STA_ENR_JOIN_NW_PBC) ? TRUE : FALSE, b_wps_version2);
	*nAP = 0;
	start_time = get_current_time();
	while ((start_time+timeout) > get_current_time()) {

		if (!CallClientCallback(WPS_STATUS_SCANNING, NULL)) 
			return false;

		wpsaplist = create_aplist();  // Get the pointer of ap_list (global)
		if (wpsaplist) {
			// After this call, the first wps_ap_total elements in the ap_list are wps ones
			wps_ap_total = wps_get_aplist(wpsaplist, wpsaplist);  
			if (wps_ap_total > 0) {
				if (mode == STA_ENR_JOIN_NW_PBC) {
					// pbc mode, if no pbc ap is scanned, continue to scan
					if(get_pbc_ap(wpsaplist, wps_ap_total, nAP) != PBC_NOT_FOUND)
						break;
				}
				else {
					// pin mode, simply return all wps aps
					*nAP = wps_ap_total;
					break;
				}
			}
		}
		WpsSleepMs(100);
	}

	rem_wps_ie(NULL, 0, VNDR_IE_PRBREQ_FLAG);
	if (b_wps_version2)
		rem_wps_ie(NULL, 0, VNDR_IE_ASSOCREQ_FLAG);

	CallClientCallback(WPS_STATUS_SCANNING_OVER, NULL);

	return (*nAP > 0);
}

/*
 wps_getAP returns the AP #nAP from the list of WPS APs found by wps_findAP.
*/
bool wps_getAP(int nAP, unsigned char *bssid, char *ssid, uint8 *wep, uint16 *band,
	uint8 *channel, uint8 *version2, uint8 *authorizedMACs)
{
	int i = 0;
	wps_ap_list_info_t *ap;

	DBGPRINT(("Entered : wps_getAP\n"));
	if (!gIsOpened)
		return false;

	ap = wps_get_ap_list();

	if (nAP < (WPS_DUMP_BUF_LEN / sizeof(wps_ap_list_info_t))) {
		if (ap[nAP].used == TRUE) {
			for (i = 0; i < 6; i++)
				bssid[i] = ap[nAP].BSSID[i];

			memcpy(ssid,ap[nAP].ssid,ap[nAP].ssidLen);
			ssid[ap[nAP].ssidLen] = '\0';
			*wep = ap[nAP].wep;
			*band = ap[nAP].band;
			*channel = ap[nAP].channel;

			if (b_wps_version2 && ap[nAP].version2 >= WPS_VERSION2) {
				*version2 = ap[nAP].version2;
				memcpy(authorizedMACs, ap[nAP].authorizedMACs,
					sizeof(ap[nAP].authorizedMACs));
			}
			else
				*version2 = 0;
			return true;
		}
	}

	return false;
}

/*
 wps_join function is used to connect to a WPS AP. Usualy, this function is called after
 wps_findAP returns successfully
*/
bool wps_join(uint8 * bssid, char *ssid, uint8 wep)
{
	DBGPRINT(("Entered : wps_join\n"));

	if (!gIsOpened)
		return false;
	if (!CallClientCallback(WPS_STATUS_ASSOCIATING, ssid))
		return false;

	DBGPRINT(("Connecting to WPS AP %s\n",ssid));

	leave_network();

	if (join_network_with_bssid(ssid, wep, (char *)bssid)) {
		DBGPRINT(("Join failed\n"));
		return false;
	}

	if (!CallClientCallback(WPS_STATUS_ASSOCIATED,ssid))
		return false;

	return true;
}

/*
 This function starts the WPS exchange protocol and gathers the credentials
 of the AP. Call this function once wps_join is successful. 

 This function will return only once the WPS exchange is finished or an
 error occurred. 

 The calling process provides a callback function in wps_open() that will be called periodically by the WPS API. When called, this
 callback function will be provided with the current status. If the calling process wants to cancel the WPS protocol, it
 should return FALSE (upon the user pressing a Cancel button, for example). 
 
 If the calling process does not want to be called back, it should send NULL as a function pointer.

 GUI applications should use the asynchronous version of this function so as not to block or slow down a UI's message loop.
*/

bool wps_get_AP_info(int wps_mode, uint8 *bssid, char *ssid, char *pin, wps_credentials *credentials)
{
	bool bRet = false;
	WpsEnrCred cred;
	DBGPRINT(("Entered : wps_get_AP_info\n"));

	if (!gIsOpened)
		return false;
	if (!CallClientCallback(WPS_STATUS_STARTING_WPS_EXCHANGE, NULL))
		return false;
	else {
		if (enroll_device(wps_mode, bssid, ssid, pin)) {
			// Get credentials
			wpssta_get_credentials(&cred, ssid, strlen(ssid));
			bRet = true;
		}
	}

	if (bRet) {
		// Output Wi-Fi credential
		memset(credentials, 0, sizeof(wps_credentials));
		wps_strncpy(credentials->ssid, cred.ssid, sizeof(credentials->ssid));
		wps_strncpy(credentials->nwKey, cred.nwKey, sizeof(credentials->nwKey));
		wps_strncpy(credentials->keyMgmt, cred.keyMgmt, sizeof(credentials->keyMgmt));
		credentials->encrType = cred.encrType;
		credentials->wepIndex = 1; /* cred.wepIndex */
		if (b_wps_version2)
			credentials->nwKeyShareable = cred.nwKeyShareable;

		CallClientCallback(WPS_STATUS_SUCCESS, NULL);
	}
	else {
		CallClientCallback(WPS_STATUS_ERROR, NULL);
	}

	return bRet;
}

pthread_t g_thread;

void * StartThreadGetInfo(void *lpParam) 
{
	ClientInfo *info = (ClientInfo*)lpParam;

	if (lpParam == NULL)
		return ((void *) -1);

	if (!gIsOpened)
		return ((void *)-1);

	wps_get_AP_info(info->mode,(uint8 *)info->bssid, info->ssid, info->pin, info->credentials);
	free(info);

	return NULL;
}

/*
 Asynchronous version of wps_get_AP_info(). This function returns immediately and starts the WPS protocol in a separate thread
 The calling process uses the status callback to determine the state of the WPS protocol.

 The calling process will get a WPS_STATUS_SUCCESS once the WPS protocol completed successfully
 The calling process will get a WPS_STATUS_ERROR if the WPS protocol completed unsuccessfully
 The calling process will get a WPS_STATUS_CANCELED if the WPS protocol was canceled by the calling thread

 The calling process must wait for any one of these 3 status notifications or any error notification
 before calling wps_close() or terminating.

 Unlike the synchronous version of this API call, the callback parameter in wps_open()CANNOT be NULL. 
 A callback is required for this function to work correctly.

 Before this function returns, it will call the calling process' callback with a status of WPS_STATUS_START_WPS_EXCHANGE

*/
bool wps_get_AP_infoEx(int wps_mode, uint8 * bssid, char *ssid, char *pin, int retries, wps_credentials *credentials)
{
	ClientInfo *info;

	DBGPRINT(("Entered : wps_get_AP_infoEx\n"));
	if (!gIsOpened)
		return false;
	if (g_wps_join_callback == NULL)
		return FALSE;

	info = (ClientInfo*)malloc(sizeof(ClientInfo));

	if (info) {
		info->bssid = (char *)bssid;
		info->ssid = ssid;
		info->pin = pin;
		info->credentials = credentials;
		info->mode = wps_mode;
		info->retries = retries;

		if(!pthread_create(&g_thread, NULL, StartThreadGetInfo, (void *)info)) {
			return TRUE;
		}
	}

	return FALSE;
}

/*
 This function creates a preferred network profile that can be used by Windows Zero Config (WZC)
 to connect to the network. Call this function with the results of the last WPS exchange. 

 This function will return WPS_STATUS_ERROR if WZC does not control the adapter or if the creation 
 of profile failed. 

*/

bool wps_create_profile(const wps_credentials *credentials)
{
	DBGPRINT(("wps_create_profile API not supported on Linux.\n"));
	return false;
}

bool wps_configureAP(uint8 *bssid, const char *pin, const wps_credentials *credentials)
{
	bool bRet = false;
	WpsEnrCred credNew;

	CallClientCallback(WPS_STATUS_CONFIGURING_ACCESS_POINT,NULL);

	if (!credentials)
		get_random_credential(&credNew);
	else {
		memset(&credNew, 0, sizeof(credNew));
		strcpy(credNew.ssid, credentials->ssid);
		credNew.ssidLen = strlen(credentials->ssid);
		credNew.encrType = credentials->encrType;
		strcpy(credNew.keyMgmt, credentials->keyMgmt);
		strcpy(credNew.nwKey, credentials->nwKey);
		credNew.nwKeyLen = strlen(credentials->nwKey);
		credNew.wepIndex = credentials->wepIndex;
	}

	// wps_cleanup is required here as we have done preliminary config_init to search WPS AP
	// we need to get back to clean state so that reg_config_init can succeed
	wps_cleanup();

	reg_config_init(&credNew, (char *)bssid);
	if (wps_osl_init((char *)bssid)) {
		wpssta_start_registration((char *)pin, get_current_time());
		if (registration_loop(get_current_time()) == WPS_SUCCESS) {
			//wps_get_reg_M8credentials((wps_credentials*)credentials);
			bRet = true;
		}
	}
	else {
		leave_network();
	}

	if (bRet) {
		CallClientCallback(WPS_STATUS_SUCCESS,NULL);
	}
	else {
		CallClientCallback(WPS_STATUS_ERROR,NULL);
	}

	return bRet;
}


bool wps_generate_pin(char *pin, int buf_len)
{
	return (wps_generatePin(pin, buf_len, false) == WPS_SUCCESS);
}

bool wps_generate_cred(wps_credentials *credentials)
{
	bool bRet = false;
	WpsEnrCred credNew;

	if(!credentials)
		return bRet;

	get_random_credential(&credNew);
	credentials->encrType = credNew.encrType;
	strcpy(credentials->keyMgmt, credNew.keyMgmt);
	strcpy(credentials->nwKey, credNew.nwKey);
	strcpy(credentials->ssid, credNew.ssid);
	credentials->wepIndex = 1;
	credentials->nwKeyShareable = credNew.nwKeyShareable;

	return true;
}

bool wps_is_reg_activated(const uint8 *bssid)
{
	wps_ap_list_info_t *ap_list = wps_get_ap_list();
	int i = 0;

	for (i = 0; i < WPS_MAX_AP_SCAN_LIST_LEN; i++) {
		// Find the ap according by comparing the mac address
		if (compare_mac(bssid, ap_list[i].BSSID))
			return wps_get_select_reg(&ap_list[i]);
	}
	return false;
}

bool wps_validate_checksum(const unsigned long pin)
{
	return wps_validateChecksum(pin);
}

uint8 wps_get_AP_scstate(const uint8 *bssid)
{
	wps_ap_list_info_t *ap_list = wps_get_ap_list();
	int i = 0;

	for (i = 0; i < WPS_MAX_AP_SCAN_LIST_LEN; i++) {
		// Find the ap according by comparing the mac address
		if(compare_mac(bssid, ap_list[i].BSSID))
			return ap_list[i].scstate;
	}
	return WPS_SCSTATE_UNKNOWN;
}

/**********************************************************************************************/
/* End WPS SDK APIs                                                                           */
/**********************************************************************************************/
