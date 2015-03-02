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
 * $Id: wps_enr.c 475022 2014-05-02 23:21:49Z $
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
#include <wlioctl.h>
#include <wpscommon.h>


#ifdef _TUDEBUGTRACE
void print_buf(unsigned char *buff, int buflen);
#endif

extern char *ether_ntoa(const struct ether_addr *addr);
extern void RAND_linux_init();
extern int wps_wl_check();


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
static bool b_zlength = false; /* do zero length */
static int nattr_len = 0; /* new attribute len */
static char nattr_tlv[SIZE_128_BYTES]; /* new attribute tlv */
#endif /* WFA_WPS_20_TESTBED */

#define ARGC_CHECK()	\
	if (argc <= 0) { \
		printf("Need argument for %s\n", cmd); \
		print_usage(); \
		return 0; \
	}

static int
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

static int
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
static int
find_pbc_ap(char *bssid, char *ssid, uint8 *wsec)
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
static int
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

static int
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
static int
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

static int
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

static int
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
	info.b_zlength = b_zlength;
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
	int len;
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

		retVal = wait_for_eapol_packet(buf, (uint32 *)&len, WPS_EAP_READ_DATA_TIMEOUT);
		if (retVal == WPS_SUCCESS) {
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
			else if (retVal == WPS_SUCCESS) {
				printf("EAP-Failure not received in 10 seconds, "
					"assume WPS Success!\n");
				return WPS_SUCCESS;
			}
		}
	}

	return WPS_SUCCESS;
}

static int
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

		if (strlen(inp) == 1) {
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

static int
enroll_device(char *pin, char *ssid, uint8 wsec, char *bssid)
{
	int ret = WPS_SUCCESS;
	unsigned long start_time;

	start_time = get_current_time();

	while (1) {

		if ((ret = wpssta_start_enrollment(pin, get_current_time())) != WPS_SUCCESS)
			break;

		/* registration loop */
		/*
		 * exits with either success, failure or indication that
		 * the registrar has not started its end of the protocol yet.
		*/
		if ((ret = registration_loop(start_time)) == WPS_SUCCESS) {
			char keystr[65];
			WpsEnrCred credential;


			printf("WPS Protocol SUCCEEDED !!\n");

			/* get credentials */
			memset((char *)(&credential), 0, sizeof(credential));
			wpssta_get_credentials(&credential, ssid, strlen(ssid));
			printf("SSID = %s\n", credential.ssid);
			printf("Key Mgmt type is %s\n", credential.keyMgmt);
			strncpy(keystr, credential.nwKey, credential.nwKeyLen);
			keystr[credential.nwKeyLen] = 0;
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

#ifndef WPSENR_BINARY_SINGLE
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
#endif /* WPSENR_BINARY_SINGLE */

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

static int
print_usage()
{
	printf("Usage : \n\n");
	printf("    Interactive mode : \n");
	printf("       wpsenr <-if eth_name> <-ip addr>/<-dhcp [command]> <-v1>\n\n");
	printf("    Command line mode (pin) : \n");
	printf("       wpsenr <-if eth_name> <-sec 0|1> -ssid ssid -pin pin "
		"<-ip addr>/<-dhcp [command]> <-v1>\n\n");
	printf("    Command line mode (push button) : \n");
	printf("       wpsenr <-if eth_name> -pb <-ip addr>/<-dhcp [command]> <-v1>\n\n");
	printf("    Command line mode (Authorized MAC) : \n");
	printf("       wpsenr <-if eth_name> -amac [wc] <-pin pin> "
		"<-ip addr>/<-dhcp [command]>\n\n");
	printf("    Command line mode (Automatically WPS in PIN mode) : \n");
	printf("       wpsenr <-if eth_name> -auto <-pin pin>\n\n");
	printf("    Scan only :\n");
	printf("       wpsenr -scan <-v1>\n\n");
	printf("    Default values :\n");
	printf("       eth_name :  eth0\n");
	printf("       sec : 1 \n");
	printf("       pin : 12345670\n");
	printf("       v1 (version 1 only) : false\n\n");
#ifdef WFA_WPS_20_TESTBED
	printf("    Internal testing arguments :\n");
	printf("       <-v2 number>: Version2 Number\n");
	printf("       <-ifrag threshold>: WPS IE fragment threshold\n");
	printf("       <-efrag threshold>: EAP fragment threshold\n");
	printf("       <-zpadding>: Do zero padding\n");
	printf("       <-zlength>: Zero length in mandatory string attributes\n");
	printf("       <-nattr tlv>: Add new attribute\n");
	printf("                   ex. <-nattr 2001000411223344> add type 0x2001 length is 4\n");
	printf("       <-prbreq ie>: Update partial embedded WPS probe request IE\n");
	printf("                   ex. <-prbreq 104a000111> replace version value with 0x11\n");
	printf("       <-assocreq ie>: Update partial embedded WPS associate request IE\n");
	printf("                   ex. <-assocreq 104a000111> replace version value with 0x11\n");
#endif /* WFA_WPS_20_TESTBED */
	return 0;
}

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

static void
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

/*
 * Name        : main
 * Description : Main entry point for the WPS stack
 * Arguments   : int argc, char *argv[] - command line parameters
 * Return type : int
 */
int
main(int argc, char* argv[])
{
	/* set pin to default */
	char *pin = NULL;
	char start_ok = 0;
	char bssid[6];
	char ssid[SIZE_SSID_LENGTH] = "broadcom\0";
	char if_name[16] = "eth0";
	char user_ssid = false;
	char user_bssid = false;
	char pbc_requested = false;
	char user_pin = false;
	char user_wsec = false;
	char user_amac = false; /* Authorized MAC */
	char user_amac_wc = false; /* include wildcard Authorized MAC  */
	char user_auto = false; /* Automatically WPS each PIN mode APs */
	int index;
	char scan = false;
	char *cmd, *val;
	wps_ap_list_info_t *wpsaplist;
	/* by default, assume wep is ON */
	uint8 wsec = 1;
	unsigned long pin_num;
	uint band_num, active_band;
	char *bssid_ptr = NULL;
	char ip_addr[16], dhcp_cmd[256];
	char run_ip_cmd[256];
	int ret = -1;
	int ap_index = 1, apcount = 1;

	printf("*********************************************\n");
	printf("WPS - Enrollee App Broadcom Corp.\n");
	printf("*********************************************\n");

	/* decount the prog name */
	argc--;
	index = 1;
	while (argc) {
		cmd = argv[index++]; argc--;
		if (!strcmp(cmd, "-help")) {
			print_usage();
			return 0;
		}
		else if (!strcmp(cmd, "-scan")) {
			scan = 1;
		}
		else if (!strcmp(cmd, "-ssid")) {
			ARGC_CHECK();
			val = argv[index++]; argc--;
			wps_strncpy((char *)ssid, val, sizeof(ssid));
			user_ssid = true;
			printf("SSID : %s", ssid);
		}
		else if (!strcmp(cmd, "-if")) {
			ARGC_CHECK();
			val = argv[index++]; argc--;
			wps_strncpy(if_name, val, sizeof(if_name));
		}
		else if (!strcmp(cmd, "-bssid")) {
			ARGC_CHECK();
			/*
			 * WARNING : this "bssid" is used only to create an 802.1X socket.
			 * Normally, it should be the bssid of the AP we will associate to.
			 * Setting this manually means that we might be proceeding to
			 * eapol exchange with a different AP than the one we are associated to,
			 * which might work ... or not.
			 *
			 * When implementing an application, one might want to enforce association
			 * with the AP with that particular BSSID. In case of multiple AP
			 * on the ESS, this might not be stable with roaming enabled.
			 */
			 val = argv[index++]; argc--;
			if (!set_mac_address(val, (char *) bssid)) {
				printf("\n*** WARNING : Setting 802.1X destination manually to:"
					"  %s ***\n\n", val);
				user_bssid = true;
				bssid_ptr = bssid;
			}
		}
		else if (!strcmp(cmd, "-pin")) {
			ARGC_CHECK();
			val = argv[index++]; argc--;
			pin = val;
			user_pin = true;
			/* Validate user entered PIN */
			pin_num = strtoul(pin, NULL, 10);
			/* Allow 4-digit PIN, we should add numeric checking for 4-digit PIN */
			if (strlen(pin) != 4 && !wps_validateChecksum(pin_num)) {
				printf("\tInvalid PIN number parameter: %s\n", pin);
				print_usage();
				return 0;
			}
		}
		else if (!strcmp(cmd, "-pb")) {
			pin = NULL;
			user_pin = true;
			pbc_requested = true;
		}
		else if (!strcmp(cmd, "-sec")) {
			ARGC_CHECK();
			val = argv[index++]; argc--;
			wsec = atoi(val);
			user_wsec = true;
		}
		else if (!strcmp(cmd, "-v1")) {
			/* WSC V1 only */
			b_wps_version2 = false;
		}
		else if (!strcmp(cmd, "-ip")) {
			ARGC_CHECK();
			/* Static IP address */
			val = argv[index++]; argc--;

			wps_strncpy(ip_addr, val, sizeof(ip_addr));
			run_ip = "ip";
		}
		else if (!strcmp(cmd, "-dhcp")) {
			def_dhclient = true;

			/* Dhcp client */
			val = argv[index];
			if (argc && val && val[0] != '-') {
				/* Use user specified */
				wps_strncpy(dhcp_cmd, val, sizeof(dhcp_cmd));
				def_dhclient = false;
				index++;
				argc--;
			}

			run_ip = "dhcp";
		}
		else if (!strcmp(cmd, "-amac")) {
			/* Connet to the AP which has my MAC in its AuthorizedMASc list */
			user_amac = true;
			val = argv[index];
			if (argc && val && val[0] != '-') {
				/* check wildcard */
				if (!strcmp(val, "wc"))
					user_amac_wc = true;
				else {
					printf("Invalid parameter for \"amac\": %s\n", val);
					print_usage();
					return 0;
				}

				index++;
				argc--;
			}
		}
		else if (!strcmp(cmd, "-auto")) {
			user_auto = true;
		}
#ifdef WFA_WPS_20_TESTBED
		else if (!strcmp(cmd, "-v2")) {
			ARGC_CHECK();
			/* version2 number */
			val = argv[index++]; argc--;

			version2_number = (uint8)strtoul(val, NULL, 16);
		}
		else if (!strcmp(cmd, "-ifrag")) {
			ARGC_CHECK();
			/* WPS IE fragment threshold */
			val = argv[index++]; argc--;

			if (set_wps_ie_frag_threshold(atoi(val)) == -1) {
				printf("\nInvalid WPS IE fragment threshold %s\n", val);
				print_usage();
				return 0;
			}
		}
		else if (!strcmp(cmd, "-efrag")) {
			ARGC_CHECK();
			/* EAP fragment threshold */
			val = argv[index++]; argc--;

			if (sta_eap_sm_set_eap_frag_threshold(atoi(val)) == -1) {
				printf("\nInvalid EAP fragment threshold %s\n", val);
				print_usage();
				return 0;
			}
		}
		else if (!strcmp(cmd, "-nattr")) {
			ARGC_CHECK();
			/* add a new attribute at the end of every messages */
			val = argv[index++]; argc--;

			/* TLV convert */
			if (new_tlv_convert((uint8*)val) == -1) {
				printf("\nInvalid new attribute TLV value\n");
				print_usage();
				return 0;
			}
		}
		else if (!strcmp(cmd, "-zpadding")) {
			/* do zero padding */
			b_zpadding = true;
		}
		else if (!strcmp(cmd, "-zlength")) {
			/* do zero length */
			b_zlength = true;
		}
		else if (!strcmp(cmd, "-prbreq")) {
			ARGC_CHECK();
			/* Update partial embedded WPS probe request IE */
			val = argv[index++]; argc--;

			if (set_update_partial_ie((uint8 *)val, VNDR_IE_PRBREQ_FLAG) == -1) {
				printf("\nInvalid updating WPS IE in probe request IE\n");
				print_usage();
				return 0;
			}
		}
		else if (!strcmp(cmd, "-assocreq")) {
			ARGC_CHECK();
			/* Update partial embedded WPS assoc request IE */
			val = argv[index++]; argc--;

			if (set_update_partial_ie((uint8 *)val, VNDR_IE_ASSOCREQ_FLAG) == -1) {
				printf("\nInvalid updating WPS IE in associate request IE\n");
				print_usage();
				return 0;
			}
		}
#endif /* WFA_WPS_20_TESTBED */
		else {
			printf("Invalid parameter : %s\n", cmd);
			print_usage();
			return 0;
		}
	}

	/* Disable auto mode when PBC and AuthorizedMAC enalbed */
	if (pbc_requested || user_amac)
		user_auto = false;

	/* Argumetns compability checking */
	if (user_amac && !b_wps_version2) {
		printf("Conflict arguments \"amac\" and \"v1\"\n");
		print_usage();
		return 0;
	}

	/* Construct run_ip_cmd */
	if (run_ip) {
		if (strcmp(run_ip, "ip") == 0) {
			snprintf(run_ip_cmd, sizeof(run_ip_cmd), "ifconfig %s %s",
				if_name, ip_addr);
		}
		else {
			if (def_dhclient) {
				/* Use default dhclient cmd */
				snprintf(def_dhclient_pf, sizeof(def_dhclient_pf),
					"/var/run/dhclient-%s.pid", if_name);
				snprintf(dhcp_cmd, sizeof(dhcp_cmd),
					"/sbin/dhclient -pf %s", def_dhclient_pf);
			}

			snprintf(run_ip_cmd, sizeof(run_ip_cmd), "%s %s", dhcp_cmd, if_name);
		}

		run_ip = run_ip_cmd;
	}

	/* we need to specify the if name before anything else */
	wps_osl_set_ifname(if_name);

	/* Setup endian swap */
	if (wps_wl_check())
		return false;


	/* if scan requested : display and exit */
	if (scan) {
		wpsaplist = create_aplist();
		if (wpsaplist) {
			display_aplist(wpsaplist);
			wps_get_aplist(wpsaplist, wpsaplist);
			printf("WPS Enabled AP list :\n");
			display_aplist(wpsaplist);
		}
		return 0;
	}

	/* establish a handler to handle SIGTERM. */
	signal(SIGINT, hup_hdlr);

	/*
	 * setup device configuration for WPS
	 * needs to be done before eventual scan for PBC.
	 */
	RAND_linux_init();
	config_init();

	/* if ssid specified, use it */
	if (user_ssid) {
		if (pbc_requested) {
			pin = NULL;
		}
		else if (!pin) {
			pin = def_pin;
			printf("\n\nStation Pin not specified, use default Pin %s\n\n", def_pin);
		}
		start_ok = true;

		/* WSC 2.0,  Test Plan 5.1.1 step 8 must add wps ie to probe request */
		if (b_wps_version2)
			add_wps_ie(NULL, 0, pbc_requested, b_wps_version2);

		/* Get wsec */
		if (user_wsec == false)
			find_ap_wsec(bssid_ptr, (char *)ssid, &wsec);
	}
	else if (pbc_requested) {
		/* find_pbc_ap will keep the WPS IE in probe request */
		start_ok = find_pbc_ap((char *)bssid, (char *)ssid, &wsec);
		pin = NULL;
		bssid_ptr = bssid;
	}
	else if (user_amac) {
		/* Try to find a AP which has my MAC in AuthorizedMACs */
		start_ok = find_amac_ap((char *)bssid, (char *)ssid, &wsec, user_amac_wc,
			&pbc_requested);
		if (pbc_requested)
			pin = NULL;
		else if (!pin)
			pin = def_pin;
		bssid_ptr = bssid;
	}
	else if (user_auto) {
		/* Try to collect all SSR is TRUE APs */
		apcount = find_pin_aps((char *)bssid, (char *)ssid, &wsec);
		if (apcount) {
			printf("WPS PIN Enabled AP list :\n");
			display_aplist(wps_get_ap_list());
			start_ok = true;
		}
		else {
			printf("No any WPS PIN Enabled AP exist\n");
			start_ok = false;
		}

		if (!pin)
			pin = def_pin;
		bssid_ptr = bssid;
	}
	else {
		/* interactive_start will keep the WPS IE in probe request */
		start_ok = interactive_start((char *)bssid, (char *)ssid, &wsec, &pin);
		bssid_ptr = bssid;
	}

	while (start_ok) {
		/*
		 * join. If user_bssid is specified, it might not
		 * match the actual associated AP.
		 * An implementation might want to make sure
		 * it associates to the same bssid.
		 * There might be problems with roaming.
		 */
		leave_network();
		if (join_network_with_bssid(ssid, wsec, bssid_ptr)) {
			printf("Can not join [%s] network, Quit...\n", ssid);
			ret = -1;
			goto err;
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

		/* if user_bssid not defined, use associated AP's */
		if (!user_bssid) {
			if (wps_get_bssid(bssid)) {
				printf("Can not get [%s] BSSID, Quit....\n", ssid);
				ret = -1;
				goto err;
			}
			bssid_ptr = bssid;
		}

		/* setup raw 802.1X socket with "bssid" destination  */
		if (wps_osl_init(bssid) != WPS_SUCCESS) {
			printf("Initializing 802.1x raw socket failed. \n");
			printf("Check PF PACKET support in kernel. \n");
			ret = -1;
			goto err;
		}

		printf("Start enrollment for BSSID:%s\n", ether_ntoa((struct ether_addr *)bssid));
		if (enroll_device(pin, ssid, wsec, bssid_ptr) == WPS_SUCCESS)
			ret = 0;

		/* done when WPS successful or no more APs */
		if (ret == 0 || ap_index == apcount)
			break;

		/* get next ap info and start WPS */
		ap_index++;
		start_ok = get_pin_ap_info(ap_index, (char *)bssid, (char *)ssid, &wsec);
		if (start_ok) {
			/* sleep one second and WPS next AP */
			printf("\nTry next AP:%s\n", ssid);
			sleep(1);

			config_init();
		}
	}

err:
	rem_wps_ie(NULL, 0, VNDR_IE_PRBREQ_FLAG);
	if (b_wps_version2)
		rem_wps_ie(NULL, 0, VNDR_IE_ASSOCREQ_FLAG);

	wps_osl_deinit();

	return ret;
}
