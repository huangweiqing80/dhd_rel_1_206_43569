/*
 * Broadcom WPS Enrollee
 *
 * Copyright (C) 2010, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bwl_wps_enr.c,v 1.4 2010-11-20 00:40:39 $
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
#include <wps_version.h>
#include <wps_staeapsm.h>
#include <wlioctl.h>

#include "bwl.h"

#if !defined(MOD_VERSION_STR)
#error "wps_version.h doesn't exist !"
#endif

#ifdef _TUDEBUGTRACE
void print_buf(unsigned char *buff, int buflen);
#endif

extern char *ether_ntoa(const struct ether_addr *addr);

#define WPS_VERSION_STRING
#define WPS_EAP_DATA_MAX_LENGTH         2048
#define WPS_EAP_READ_DATA_TIMEOUT         3

static char def_pin[9] = "12345670\0";
static bool b_wps_version2 = true;
static uint8 version2_number = WPS_VERSION2;
static uint8 empty_mac[SIZE_MAC_ADDR] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static char *run_ip = NULL;
static char def_dhclient = false;
static char def_dhclient_pf[256];

#ifdef WFA_WPS_20_TESTBED
static bool b_zpadding = false; /* do zero padding */
static int nattr_len = 0; /* new attribute len */
static char nattr_tlv[SIZE_128_BYTES]; /* new attribute tlv */
#endif /* WFA_WPS_20_TESTBED */


#define ARGC_CHECK()	\
	if (argc <= 0) { \
		printf("Need argument for %s\n", cmd); \
		print_usage(); \
		return 0; \
	}

int
kill_def_dhclient(char *pf)
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

int
display_aplist(wps_ap_list_info_t *ap)
{
	int i = 0, j;
	uint8 *mac;

	if (!ap)
		return 0;

	printf("-------------------------------------\n");
	while (ap->used == TRUE) {
		printf(" %-2d :  ", i);
		printf("SSID:%-16s  ", ap->ssid);
		mac = ap->BSSID;
		printf("BSSID:%02x:%02x:%02x:%02x:%02x:%02x  ", mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
		printf("Channel:%-3d  ", ap->channel);
		if (ap->wep)
			printf("WEP  ");
		if (b_wps_version2 && ap->version2 >= WPS_VERSION2) {
			printf("V2(0x%02X)  ", ap->version2);

			mac = ap->authorizedMACs;
			printf("AuthorizedMACs:");
			for (j = 0; j < 5; j++) {
				if (memcmp(mac, empty_mac, SIZE_MAC_ADDR) == 0)
					break;

				printf(" %02x:%02x:%02x:%02x:%02x:%02x",
					mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
				mac += SIZE_MAC_ADDR;
			}
		}
		printf("\n");
		ap++;
		i++;
	}

	printf("-------------------------------------\n");
	return 0;
}

/*
 * find an AP with PBC active or timeout.
 * Returns SSID and BSSID.
 * Note : when we join the SSID, the bssid of the AP might be different
 * than this bssid, in case of multiple AP in the ESS ...
 * Don't know what to do in that case if roaming is enabled ...
 */
int
find_pbc_ap(char * bssid, char *ssid, uint8 *wsec)
{
	int pbc_ret = PBC_NOT_FOUND;
	char start = true;
	wps_ap_list_info_t *wpsaplist;

	/* add wps ie to probe  */
	add_wps_ie(NULL, 0, TRUE, b_wps_version2);

	while (PBC_NOT_FOUND == pbc_ret) {
		wpsaplist = create_aplist();
		if (wpsaplist) {
			wps_get_aplist(wpsaplist, wpsaplist);
			display_aplist(wpsaplist);
			pbc_ret = wps_get_pbc_ap(wpsaplist, bssid, ssid,
				wsec, get_current_time(), start);
			start = false;
		}
		sleep(1);
	}

	if (pbc_ret != PBC_FOUND_OK) {
		printf("Could not find a PBC enabled AP, %s\n",
			(pbc_ret == PBC_OVERLAP) ?
			"OVERLAP" : "TIMEOUT");
		return 0;
	}

	return 1;
}

/* find all APs which has PIN my MAC in AuthorizedMACs */
int
find_pin_aps(char *bssid, char *ssid, uint8 *wsec)
{
	int wps_apcount = 0;
	wps_ap_list_info_t *wpsaplist;

	/* add wps ie to probe  */
	add_wps_ie(NULL, 0, FALSE, b_wps_version2);

	wpsaplist = create_aplist();
	if (wpsaplist) {
		/* filter with PIN */
		wps_apcount = wps_get_pin_aplist(wpsaplist, wpsaplist);
		display_aplist(wpsaplist);
	}

	/* return first AP info. */
	if (wps_apcount) {
		memcpy(bssid, wpsaplist->BSSID, 6);
		strcpy(ssid, (char *)wpsaplist->ssid);
		*wsec = wpsaplist->wep;
	}

	return wps_apcount;
}

int
get_pin_ap_info(int index, char *bssid, char *ssid, uint8 *wsec)
{
	wps_ap_list_info_t *ap, *wpsaplist;

	wpsaplist = wps_get_ap_list();

	if (!wpsaplist || index <= 0)
		return false;

	ap = &wpsaplist[index-1];

	/* return first AP info. */
	memcpy(bssid, ap->BSSID, 6);
	strcpy(ssid, (char *)ap->ssid);
	*wsec = ap->wep;

	return true;
}

/* find an AP which has my MAC in AuthorizedMACs */
int
find_amac_ap(char *bssid, char *ssid, uint8 *wsec, char wildcard, char *pbc)
{

	bool amac_found = false;
	char start = true;
	uint8 mac[SIZE_MAC_ADDR];
	wps_ap_list_info_t *wpsaplist;

	*pbc = false;

	/* Get my MAC */
	wps_osl_get_mac(mac);

	/* add wps ie to probe  */
	add_wps_ie(NULL, 0, FALSE, b_wps_version2);

	while (amac_found == AUTHO_MAC_NOT_FOUND) {
		wpsaplist = create_aplist();
		if (wpsaplist) {
			wps_get_aplist(wpsaplist, wpsaplist);
			display_aplist(wpsaplist);
			amac_found = wps_get_amac_ap(wpsaplist, mac, wildcard, bssid, ssid,
				wsec, get_current_time(), start);
			start = false;
		}
		sleep(1);
	}

	/* Not found */
	if (amac_found == AUTHO_MAC_NOT_FOUND || amac_found == AUTHO_MAC_TIMEOUT) {
		printf("No any APs have my MAC in AuthorizedMACs list\n");
		return 0;
	}

	/* Found */
	if (amac_found == AUTHO_MAC_PBC_FOUND || amac_found == AUTHO_MAC_WC_PBC_FOUND) {
		/* In PBC */
		printf("Found AP \"%s\" has %s MAC in PBC method\n", ssid,
			amac_found == AUTHO_MAC_PBC_FOUND ? "my" : "wildcard");
		*pbc = true;
	}
	else {
		/* In PIN */
		printf("Found AP \"%s\" has %s MAC in PIN method\n", ssid,
			amac_found == AUTHO_MAC_PIN_FOUND ? "my" : "wildcard");
	}

	return 1;
}

int
find_wsec(wps_ap_list_info_t *ap, char *bssid, char *ssid, uint8 *wsec)
{
	if (!ap || !ssid || !wsec)
		return 0;

	while (ap->used == TRUE) {
		if (strcmp(ssid, (char *)ap->ssid) == 0 &&
		    (!bssid || memcmp(bssid, ap->BSSID, 6) == 0)) {
			*wsec = ap->wep;
			return 1;
		}

		ap++;
	}

	return 0;
}

int
find_ap_wsec(char *bssid, char *ssid, uint8 *wsec)
{
	int found = 0;
	int retry = 5;
	wps_ap_list_info_t *wpsaplist;

	while (!found && retry--) {
		wpsaplist = create_aplist();
		if (wpsaplist) {
			wps_get_aplist(wpsaplist, wpsaplist);
			display_aplist(wpsaplist);
			found = find_wsec(wpsaplist, bssid, ssid, wsec);
		}
		sleep(1);
	}

	if (!found) {
		printf("Could not find a specified AP \"%s\"\n", ssid);
		return 0;
	}

	return 1;
}

/*
 * Fill up the device info and pass it to WPS.
 * This will need to be tailored to specific platforms (read from a file,
 * nvram ...)
 */
void
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
	 * NOTE: BCMWPA2 compile option MUST enabled
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

	wps_enr_config_init(&info);
}

/* Main loop. */
int
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
		printf("Send EAPOL-Start\n");
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
			printf("Overall protocol timeout \n");
			return REG_FAILURE;
		}

		if ((retVal = wait_for_eapol_packet(buf, &len, WPS_EAP_READ_DATA_TIMEOUT))
			== WPS_SUCCESS) {

			/* Show receive message */
			msg_type = wps_get_msg_type(buf, len);
			printf("Receive EAP-Request%s\n", wps_get_msg_string((int)msg_type));

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
					printf("Send EAP-Response%s\n",
						wps_get_msg_string((int)msg_type));
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
				printf("Received eap failure, last recv msg EAP-Request%s\n",
					wps_get_msg_string(last_recv_msg));
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
					printf("Send EAP-Response / Identity\n");
				}
			}
			/* Re-transmit last sent message, because we receive a re-transmit packet */
			else if (retVal == WPS_SEND_RET_MSG_CONT) {
				len = wps_get_retrans_msg_to_send(&sendBuf, now, &msg_type);
				if (sendBuf) {
					state = wps_get_eap_state();

					if (state == EAPOL_START_SENT)
						printf("Re-Send EAPOL-Start\n");
					else if (state == EAP_IDENTITY_SENT)
						printf("Re-Send EAP-Response / Identity\n");
					else
						printf("Re-Send EAP-Response%s\n",
							wps_get_msg_string((int)msg_type));

					send_eapol_packet(sendBuf, len);
				}
			}
			else if (retVal == WPS_SEND_FRAG_CONT ||
				retVal == WPS_SEND_FRAG_ACK_CONT) {
				len = wps_get_frag_msg_to_send(&sendBuf, now);
				if (sendBuf) {
					if (retVal == WPS_SEND_FRAG_CONT)
						printf("Send EAP-Response(FRAG)\n");
					else
						printf("Send EAP-Response(FRAG_ACK)\n");

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
						printf("Re-Send EAPOL-Start\n");
					else if (state == EAP_IDENTITY_SENT)
						printf("Re-Send EAP-Response / Identity\n");
					else
						printf("Re-Send EAP-Response%s\n",
							wps_get_msg_string((int)msg_type));

					send_eapol_packet(sendBuf, len);
				}
			}
			/* re-transmission count exceeded, give up */
			else if (retVal == EAP_TIMEOUT) {
				last_recv_msg = wps_get_recv_msg_id();

				if (last_recv_msg == WPS_ID_MESSAGE_M2D) {
					printf("M2D Wait timeout, again.\n");
				}
				else if (last_recv_msg > WPS_ID_MESSAGE_M2D) {
					last_sent_msg = wps_get_sent_msg_id();
					printf("Timeout, last recv/sent msg "
						"[EAP-Response%s/EAP-Request%s], again.\n",
						wps_get_msg_string(last_recv_msg),
						wps_get_msg_string(last_sent_msg));
				}
				else {
					printf("Re-transmission count exceeded, again\n");
				}

				return WPS_CONT;
			}
		}
	}

	return WPS_SUCCESS;
}

int
interactive_start(char *bssid, char *ssid, uint8 *wsec, char **pin)
{
	char inp[8], inp2[8];
	bool b_tryAgain = true;
	wps_ap_list_info_t *wpsaplist;
	int start_ok = false;
	int i, valc, valc1;

	while (b_tryAgain) {
		printf("\nOptions:\n");
		printf("0. Quit\n");
		printf("1. Get configured\n");
		printf("2. Get configured via push-button\n");
		printf("Enter selection: ");
		fgets(inp, sizeof(inp), stdin);
		fflush(stdin);

		if (0 == strlen(inp)-1) {
			/* We got no input */
			printf("Error: Invalid input.\n");
			continue;
		}

		switch (inp[0]) {
		case '0':
			printf("\nShutting down...\n");
			b_tryAgain = false;
			break;

		case '1': /* Get configured */

			if (b_wps_version2) {
				/* WSC 2.0,  must add wps ie to probe request */
				add_wps_ie(NULL, 0, FALSE, b_wps_version2);
			}

			/* Not doing PBC */
			wpsaplist = create_aplist();
			if (wpsaplist) {
				wps_get_aplist(wpsaplist, wpsaplist);
				printf("--------- WPS Enabled AP list -----------\n");
				display_aplist(wpsaplist);
			}
		scan_retry:
			printf("Choose one AP to start!!\n");
			printf("Enter selection: ('a' for scan again, 'q' for quit)");
			fgets(inp2, 3, stdin);
			fflush(stdin);
			if ('a' == inp2[0]) {
				wpsaplist = create_aplist();
				if (wpsaplist) {
					wps_get_aplist(wpsaplist, wpsaplist);
					printf("--------- WPS Enabled AP list -----------\n");
					display_aplist(wpsaplist);
				}
				goto scan_retry;
			}
			else if ('q' == inp2[0]) {
				printf("\nShutting down...\n");
				b_tryAgain = false;
				break;
			}
			else if ('0' <= inp2[0] && '9' >= inp2[0]) {
				valc = inp2[0]-48;
				if ('0' <= inp2[1] && '9' >= inp2[1]) {
					valc1 = inp2[1]-48;
					valc = valc * 10;
					valc += valc1;
				}

				if (wpsaplist[valc].used == TRUE) {
					for (i = 0; i < 6; i++)
						bssid[i] = wpsaplist[valc].BSSID[i];
					memcpy(ssid, wpsaplist[valc].ssid,
						wpsaplist[valc].ssidLen);
					ssid[wpsaplist[valc].ssidLen] = '\0';
					*wsec = wpsaplist[valc].wep;
					start_ok = true;
					b_tryAgain = false;
				}
				else {
					printf("Type error, incorrect number !\n");
					goto scan_retry;
				}
			}
			else {
				printf("Type error!\n");
				goto scan_retry;
			}

			/*  if pin unset, use default */
			if (!*pin) {
				*pin = def_pin;
				printf("\n\nStation Pin not specified, use default Pin %s\n\n",
					def_pin);
			}

			break;
		case '2': /*  Get configured via push-button */
			start_ok = find_pbc_ap((char *)bssid, (char *)ssid, wsec);
			if (start_ok) {
				b_tryAgain = false;
				*pin = NULL;
			}
			break;

		default:
			printf("ERROR: Invalid input.\n");
			break;
		}
	}

	return start_ok;
}

int
enroll_device(char *pin, char *ssid, uint8 wsec, char *bssid, char* key, uint32 key_len)
{
	int ret = WPS_SUCCESS;
	unsigned long start_time;

	start_time = get_current_time();

	while (1) {

		if ((ret = wps_start_enrollment(pin, get_current_time())) != WPS_SUCCESS)
			break;

		/* registration loop */
		/*
		 * exits with either success, failure or indication that
		 * the registrar has not started its end of the protocol yet.
		*/
		if ((ret = registration_loop(start_time)) == WPS_SUCCESS) {
			char keystr[65];
			int len = 0;
			char ssid[SIZE_SSID_LENGTH];
			WpsEnrCred credential;


			printf("WPS Protocol SUCCEEDED !!\n");

			/* get credentials */
			memset((char *)(&credential), 0, sizeof(credential));
			wps_get_ssid(ssid, &len);
			wps_get_credentials(&credential, ssid, len);
			printf("SSID = %s\n", credential.ssid);
			printf("Key Mgmt type is %s\n", credential.keyMgmt);
			strncpy(keystr, credential.nwKey, credential.nwKeyLen);
			keystr[credential.nwKeyLen] = 0;
			if (key != NULL)
			{
			    strncpy(key, keystr, key_len);
			}
			printf("Key : %s\n", keystr);
			if (credential.encrType == ENCRYPT_NONE) {
				printf("Encryption : NONE\n");
			}
			else {
				if (credential.encrType & ENCRYPT_WEP)
					printf("Encryption :  WEP\n");
				if (credential.encrType & ENCRYPT_TKIP)
					printf("Encryption :  TKIP\n");
				if (credential.encrType & ENCRYPT_AES)
					printf("Encryption :  AES\n");
			}

			if (b_wps_version2)
				printf("Network Key Shareable :  %s\n",
					credential.nwKeyShareable ? "TRUE" : "FALSE");

			/* Remove WPS IE before doing 4-way handshake */
			rem_wps_ie(NULL, 0, VNDR_IE_PRBREQ_FLAG);
			if (b_wps_version2)
				rem_wps_ie(NULL, 0, VNDR_IE_ASSOCREQ_FLAG);

			leave_network();
			sleep(1);

			/* Apply to driver */
			printf("\nApply security to driver ... ");
			fflush(stdout);
			if (do_wpa_psk(&credential)) {
				printf("Fail !!\n\n");
			}
			else {
				printf("Success !!\n\n");

				/* Run IP */
				if (run_ip) {
					printf("Set IP Address: run \"%s\"\n\n", run_ip);

					/* Kill default dhclient */
					if (def_dhclient &&
					    kill_def_dhclient(def_dhclient_pf) < 0)
						printf("Cannot kill dhclient\n");

					/* Launch run ip cmd */
					if (system(run_ip) < 0)
						printf("Cannot run %s\n", run_ip);
				}
			}
			break;
		}
		else if (ret == WPS_CONT) {
			/* Do enrollement again */
			/* leave network before join again */
			leave_network();
			sleep(1);

			/* Do join again */
			join_network_with_bssid(ssid, wsec, bssid);
		}
		else {
			printf("WPS Protocol FAILED \n");
			break;
		}
	}

	wps_cleanup();

	return ret;
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
			printf("invalid MAC address\n");
			return -1;
		}

		if (endptr == nptr) {
			/* no more digits. */
			if (i != 6) {
				printf("invalid MAC address\n");
				return -1;
			}
			return 0;
		}

		if (i >= 6) {
			printf("invalid MAC address\n");
			return -1;
		}

		mac_bin[i++] = val;
		nptr = endptr+1;
	} while (nptr[0]);

	if (i != 6) {
		printf("invalid MAC address\n");
		return -1;
	}

	return 0;
}

#ifdef WFA_WPS_20_TESTBED
static int
new_tlv_convert(uint8 *new_tlv_str)
{
	uchar *src, *dest;
	uchar val;
	int idx, len;
	char hexstr[3];

	/* reset first */
	nattr_len = 0;

	if (!new_tlv_str)
		return 0;

	/* Ensure in 2 characters long */
	len = strlen((char*)new_tlv_str);
	if (len % 2) {
		printf("Please specify all the data bytes for this TLV\n");
		return -1;
	}
	nattr_len = (uint8) (len / 2);

	/* string to hex */
	src = new_tlv_str;
	dest = (uchar*)nattr_tlv;
	for (idx = 0; idx < len; idx++) {
		hexstr[0] = src[0];
		hexstr[1] = src[1];
		hexstr[2] = '\0';

		val = (uchar) strtoul(hexstr, NULL, 16);

		*dest++ = val;
		src += 2;
	}

	/* TODO, can add TLV parsing here */
	return 0;
}
#endif /* WFA_WPS_20_TESTBED */


#ifdef _TUDEBUGTRACE
void
print_buf(unsigned char *buff, int buflen)
{
	int i;
	printf("\n print buf : \n");
	for (i = 0; i < buflen; i++) {
		printf("%02X ", buff[i]);
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
	wps_osl_deinit();
	exit(0);
}

int32 WPS_Init(void)
{
	char if_name[10] = "eth1";

	/* we need to specify the if name before anything else */
	wps_osl_set_ifname( if_name );

	/* establish a handler to handle SIGTERM. */
	signal(SIGINT, hup_hdlr);


    return 0;
}


void WPS_Uninit(void)
{
    wps_osl_deinit();
}
