/*
 * P2P Library - BcmP2PAPI interface
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: BcmP2PAPI.c,v 1.130 2010-12-10 02:00:50 $
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* P2P Library include files */
#include <p2plib_api.h>
#include <BcmP2PAPI.h>
#include <p2plib_osl.h>
#include <p2plib_int.h>			// for BCMP2PSetPhysicalAdapter
#include <p2plib_sd.h>

static const char *g_status_str_table[] = BCMP2P_STATUS_STR_TABLE;

static BCMP2P_CANCEL_CREATE_GROUP_OVERRIDE cancelCreateGroupOverrideFn = NULL;
static BCMP2P_CREATE_GROUP_OVERRIDE createGroupOverrideFn = NULL;
#ifndef SOFTAP_ONLY
/* Registered API override functions */
static BCMP2P_DISCOVER_OVERRIDE discoverOverrideFn = NULL;
static BCMP2P_CANCEL_DISCOVER_OVERRIDE cancelDiscoverOverrideFn = NULL;
static BCMP2P_CREATE_LINK_OVERRIDE createLinkOverrideFn = NULL;
static BCMP2P_CREATE_LINK_DEVADDR_OVERRIDE createLinkToDevAddrOverrideFn = NULL;
static BCMP2P_CANCEL_CREATE_LINK_OVERRIDE cancelCreateLinkOverrideFn = NULL;
static BCMP2P_PROCESS_INCOMING_OVERRIDE procIncomingOverrideFn = NULL;
static BCMP2P_ACCEPT_OVERRIDE acceptOverrideFn = NULL;

/* Register an override fn for BCMP2PDiscover() */
BCMP2P_STATUS
p2papi_register_discover_override(BCMP2P_DISCOVER_OVERRIDE funcOverride)
{
	discoverOverrideFn = funcOverride;
	return BCMP2P_SUCCESS;
}

/* Register an override fn for BCMP2PCancelDiscover() */
BCMP2P_STATUS
p2papi_register_cancel_discover_override(
	BCMP2P_CANCEL_DISCOVER_OVERRIDE funcOverride)
{
	cancelDiscoverOverrideFn = funcOverride;
	return BCMP2P_SUCCESS;
}


/* Register an override fn for BCMP2PCreateLink() */
BCMP2P_STATUS
p2papi_register_create_link_override(BCMP2P_CREATE_LINK_OVERRIDE funcOverride,
	BCMP2P_CREATE_LINK_DEVADDR_OVERRIDE funcOverride2)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_register_create_link_override\n"));
	createLinkOverrideFn = funcOverride;
	createLinkToDevAddrOverrideFn = funcOverride2;
	return BCMP2P_SUCCESS;
}

/* Register an override fn for BCMP2PCancelCreateLink() */
BCMP2P_STATUS
p2papi_register_cancel_create_link_override(
	BCMP2P_CANCEL_CREATE_LINK_OVERRIDE funcOverride)
{
	cancelCreateLinkOverrideFn = funcOverride;
	return BCMP2P_SUCCESS;
}

/* Register an override fn for BCMP2PCreateLink() */
BCMP2P_STATUS
p2papi_register_process_incoming_override(
	BCMP2P_PROCESS_INCOMING_OVERRIDE funcOverride)
{
	procIncomingOverrideFn = funcOverride;
	return BCMP2P_SUCCESS;
}

/* Register an override fn for BCMP2PAcceptNegotiation() */
BCMP2P_STATUS
p2papi_register_accept_override(BCMP2P_ACCEPT_OVERRIDE funcOverride)
{
	acceptOverrideFn = funcOverride;
	return BCMP2P_SUCCESS;
}
#endif /* SOFTAP_ONLY */

/* Register an override fn for BCMP2PCreateGroup() */
BCMP2P_STATUS
p2papi_register_create_group_override(BCMP2P_CREATE_GROUP_OVERRIDE funcOverride)
{
	createGroupOverrideFn = funcOverride;
	return BCMP2P_SUCCESS;
}

/* Register an override fn for BCMP2PCancelCreateGroup() */
BCMP2P_STATUS
p2papi_register_cancel_create_group_override(
	BCMP2P_CANCEL_CREATE_GROUP_OVERRIDE funcOverride)
{
	cancelCreateGroupOverrideFn = funcOverride;
	return BCMP2P_SUCCESS;
}


/* Initialize the API */
BCMP2P_STATUS
BCMP2PInitialize(BCMP2P_UINT32 version, void* reserved)
{
	unsigned int status_table_size;

	status_table_size = sizeof(g_status_str_table)/sizeof(g_status_str_table[0]);
	if (status_table_size != BCMP2P_STATUS_LAST) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"BCMP2PInitialize: status_table_size=%d != BCMP2P_STATUS_LAST=%d\n",
			status_table_size, BCMP2P_STATUS_LAST));
		return (BCMP2P_ERROR);
	}

	return p2papi_init(version, reserved);
}

/* Uninitialize the API */
BCMP2P_STATUS
BCMP2PUninitialize(void)
{
	return p2papi_uninit();
}


/* Register for event notifications.  */
BCMP2P_STATUS
BCMP2PRegisterNotification(int notificationType,
	BCMP2P_NOTIFICATION_CALLBACK funcCallback, void *pCallbackContext,
	void *pReserved)
{
	return p2papi_register_notifications(notificationType, funcCallback,
		pCallbackContext, pReserved);
}

/* Unregister for event notifications.  */
BCMP2P_STATUS
BCMP2PUnRegisterNotification(void)
{
	return p2papi_unregister_notifications();
}


/* Open a new instance of the P2P library */
BCMP2PHandle
BCMP2POpen(char *szAdapter, char *szPrimaryAdapter)
{
	int ret;
	p2papi_instance_t* hdl = NULL;

	if (szAdapter == (char *) NULL)
		return (BCMP2PHandle) NULL;
	if (strlen(szAdapter) <= 0)
		return (BCMP2PHandle) NULL;

	ret = p2papi_open(szAdapter, szPrimaryAdapter, &hdl);
	if (ret != BCMP2P_SUCCESS) {
		return (BCMP2PHandle) NULL;
	}

	P2PAPI_CHECK_P2PHDL(hdl);
	return (BCMP2PHandle) hdl;
}

/* Close an instance of the P2P library */
BCMP2P_STATUS
BCMP2PClose(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_close(hdl);
}

#ifndef SOFTAP_ONLY
/* Discover peers */
BCMP2P_STATUS
BCMP2PDiscover(BCMP2PHandle p2pHandle, PBCMP2P_DISCOVER_PARAM params)
{
	if (discoverOverrideFn) {
		return discoverOverrideFn(p2pHandle, params);
	} else {
		return p2papi_discover((p2papi_instance_t *)p2pHandle, params);
	}
}

/* Cancel discovering peers */
BCMP2P_STATUS
BCMP2PCancelDiscover(BCMP2PHandle p2pHandle)
{
	if (cancelDiscoverOverrideFn) {
		return cancelDiscoverOverrideFn(p2pHandle);
	} else {
		return p2papi_discover_cancel((p2papi_instance_t *)p2pHandle);
	}
}

/* Suspend discovery */
BCMP2P_STATUS
BCMP2PSuspendDiscovery(BCMP2PHandle p2pHandle)
{
	int ret;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "Enter BCMP2PSuspendDiscovery()\n"));
	ret = p2papi_discover_enable_search((p2papi_instance_t *)p2pHandle, FALSE);
	return (ret == 0) ? BCMP2P_SUCCESS : BCMP2P_ERROR;
}

/* Resume discovery */
BCMP2P_STATUS
BCMP2PResumeDiscovery(BCMP2PHandle p2pHandle)
{
	int ret;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "Enter BCMP2PResumeDiscovery()\n"));
	ret = p2papi_discover_enable_search((p2papi_instance_t *)p2pHandle, TRUE);
	return (ret == 0) ? BCMP2P_SUCCESS : BCMP2P_ERROR;
}

/* Get discovery results */
BCMP2P_STATUS
BCMP2PGetDiscoverResult(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL bPrunedList, PBCMP2P_DISCOVER_ENTRY pBuffer,
	BCMP2P_UINT32 buffLength, BCMP2P_UINT32 *numEntries)
{
	return p2papi_get_discover_result((p2papi_instance_t *) p2pHandle,
		bPrunedList ? true : false, pBuffer, buffLength, numEntries, false);
}

BCMP2P_STATUS
BCMP2PGetDiscoverResult2(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL bPrunedList, PBCMP2P_DISCOVER_ENTRY pBuffer,
	BCMP2P_UINT32 buffLength, BCMP2P_UINT32 *numEntries)
{
	return p2papi_get_discover_result((p2papi_instance_t *) p2pHandle,
		bPrunedList ? true : false, pBuffer, buffLength, numEntries, true);
}

/**
 * Free the ie-data/svc-resp buffer associated with each entry in pBuffer returned via BCMP2PGetDiscoverResult2()
 * and BCMP2PGetDiscoverPeer.
 */
BCMP2P_STATUS
BCMP2PFreeDiscoverResultData(BCMP2PHandle p2pHandle,
	PBCMP2P_DISCOVER_ENTRY pBuffer, BCMP2P_UINT32 numEntries)
{
	return p2papi_free_discover_result_data((p2papi_instance_t *) p2pHandle, pBuffer, numEntries);
}

/* Get discovery results */
BCMP2P_STATUS
BCMP2PGetDiscoverPeer(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *peerAddr, PBCMP2P_DISCOVER_ENTRY pBuffer)
{
	return p2papi_get_discover_peer((p2papi_instance_t *) p2pHandle,
		(struct ether_addr *)peerAddr, pBuffer);
}

/* Do a blocking 802.11 scan to discover Group Owners.  Scan results will be
 * added to the internal discovery results which can obtained by calling
 * BCMP2PGetDiscoverResult.
 * - nprobes    : number of probe reqs per channel, use -1 for default.
 * - dwell_ms   : active dwell time per channel, use -1 for default.
 * - numChannels: Number of channels in the channel list to scan.
 *                use 0 to specify scan all driver-supported channels.
 * - channels:    Channel list to scan or NULL.
 */
BCMP2P_STATUS
BCMP2PDiscover80211Scan(BCMP2PHandle p2pHandle,
	BCMP2P_INT32 nprobes, BCMP2P_INT32 dwell_ms,
	BCMP2P_INT32 numChannels, BCMP2P_UINT16* channels)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_UINT32 time_used_ms = 0;
	BCMP2P_STATUS ret;

	ret = p2papi_discovery_scan(hdl, nprobes, dwell_ms, numChannels, channels,
		&time_used_ms);
	if (ret != BCMP2P_SUCCESS) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"BCMP2PDiscover80211Scan: scan failed\n"));
	}
	return ret;
}

/* Send provision discovery request to peer. */
BCMP2P_STATUS
BCMP2PSendProvisionDiscoveryRequest(
	BCMP2PHandle p2pHandle,	BCMP2P_UINT32 configMethod,
	BCMP2P_BOOL isPeerGo, BCMP2P_UINT8 *ssid, BCMP2P_UINT32 ssidLen,
	BCMP2P_CHANNEL *channel, BCMP2P_ETHER_ADDR *dstDevAddr)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_send_provdis_req(hdl, configMethod, isPeerGo, ssid, ssidLen,
		channel, (struct ether_addr *)dstDevAddr);
}

/* Send provision discovery response to peer. */
BCMP2P_STATUS  BCMP2PSendProvisionDiscoveryResponse(
	BCMP2PHandle p2pHandle,	BCMP2P_UINT32 configMethod)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_send_provdis_rsp(hdl, configMethod);
}


/* Send provision discovery request on invitation */
BCMP2P_STATUS
BCMP2PSendProvisionDiscoveryRequestOnInvite(
	BCMP2PHandle p2pHandle,	BCMP2P_UINT32 configMethods,
	BCMP2P_UINT8 *ssid, BCMP2P_UINT32 ssidLen,
	BCMP2P_ETHER_ADDR *dstDevAddr, BCMP2P_CHANNEL *channel)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_send_provdis_req_on_invite(hdl, configMethods, ssid, ssidLen,
		dstDevAddr,	channel);
}

/* Initiate a P2P connection to a device on the discovered peers list */
BCMP2P_STATUS
BCMP2PCreateLink(BCMP2PHandle p2pHandle,
	PBCMP2P_DISCOVER_ENTRY pPeerInfo, BCMP2P_UINT32 timeout)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	if (createLinkOverrideFn) {
		return createLinkOverrideFn(p2pHandle, pPeerInfo, timeout);
	} else {
		p2papi_peer_info_t *peer =
			p2papi_find_peer(hdl, pPeerInfo->mac_address);
		if (peer) {
			return p2papi_link_create(hdl, timeout, peer);
		} else {
			return BCMP2P_PEER_NOT_FOUND;
		}
	}
}

/* Cancel link creation or tear down a created link */
BCMP2P_STATUS
BCMP2PCancelCreateLink(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	if (cancelCreateLinkOverrideFn) {
		return cancelCreateLinkOverrideFn(p2pHandle);
	} else {
		return p2papi_teardown(hdl);
	}
}

/* Initiate a P2P connection to a device not necessarily on the discovered
 * peers list.
 */
BCMP2P_STATUS
BCMP2PCreateLinkToDevAddr(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *peerDevAddr, BCMP2P_CHANNEL *peerListenChannel,
	BCMP2P_BOOL isPeerGo, BCMP2P_ETHER_ADDR *peerIntAddr,
	BCMP2P_UINT32 timeout)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	if (createLinkToDevAddrOverrideFn) {
		return createLinkToDevAddrOverrideFn(p2pHandle,
			(BCMP2P_ETHER_ADDR*)peerDevAddr, peerListenChannel,
			isPeerGo, peerIntAddr, timeout);
	} else {
		return p2papi_link_create_to_devaddr(hdl, timeout,
			(struct ether_addr *)peerDevAddr, peerListenChannel,
			isPeerGo, (struct ether_addr *)peerIntAddr);
	}
}

BCMP2P_API BCMP2P_STATUS BCMP2PGetPeerGOClientInfo(BCMP2PHandle p2pHandle,
	BCMP2P_DISCOVER_ENTRY *peerGO,
        BCMP2P_CLIENT_LIST *peerGOClientList,
	BCMP2P_UINT32 peerGOClientListLen,
	BCMP2P_UINT32 *peerGOClientCount)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_get_peer_go_client_list(hdl, peerGO, peerGOClientList,
		peerGOClientListLen, peerGOClientCount);
}


BCMP2P_API BCMP2P_STATUS
BCMP2PGenerateGoSsid(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	p2papi_generate_go_ssid(hdl, &hdl->credentials);

	return BCMP2P_SUCCESS;
}

/* Create a P2P Group and act as a Group Owner */
BCMP2P_API BCMP2P_STATUS
BCMP2PCreateGroup(BCMP2PHandle p2pHandle, unsigned char *name,
	BCMP2P_BOOL bAutoRestartWPS)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	p2papi_enable_p2p(hdl, TRUE);

	if (createGroupOverrideFn) {
		return createGroupOverrideFn(p2pHandle, name,
			bAutoRestartWPS ? true : false);
	} else {
		return p2papi_group_create(hdl, name, bAutoRestartWPS ? true : false);
	}
}

/* Set frend name. */
BCMP2P_API BCMP2P_STATUS
BCMP2PSetFname(BCMP2PHandle p2pHandle, char *name)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (name!= NULL) {
		memcpy(hdl->fname_ssid, name, sizeof(hdl->fname_ssid));
		hdl->fname_ssid[sizeof(hdl->fname_ssid) - 1] = '\0';
		hdl->fname_ssid_len = strlen((const char *)name);
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "BCMP2PCreateGroup: init fname here=%s\n", hdl->fname_ssid));
	}
	return BCMP2P_SUCCESS;
}
#endif /* SOFTAP_ONLY */

/* Cancel P2P Group create or tear down a P2P Group that we own */
BCMP2P_API BCMP2P_STATUS
BCMP2PCancelCreateGroup(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (cancelCreateGroupOverrideFn) {
		return cancelCreateGroupOverrideFn(p2pHandle);
	} else {
		return p2papi_group_cancel(hdl);
	}
}

/* Create a Soft AP */
BCMP2P_API BCMP2P_STATUS
BCMP2PCreateSoftAP(BCMP2PHandle p2pHandle, unsigned char *ssid)
{
	BCMP2P_STATUS	status;
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	/* disable P2P functionality for a SoftAP */
	p2papi_enable_p2p(hdl, FALSE);

	if (createGroupOverrideFn) {
		status = createGroupOverrideFn(p2pHandle, ssid, TRUE);
	} else {
		status = p2papi_group_create(hdl, ssid, TRUE);
	}

	/* reset to default to enable P2P functionality */
	if (status != BCMP2P_SUCCESS)
		p2papi_enable_p2p((p2papi_instance_t*) p2pHandle, TRUE);

	return status;
}

/* Tear down a Soft AP */
BCMP2P_API BCMP2P_STATUS
BCMP2PCancelCreateSoftAP(BCMP2PHandle p2pHandle)
{
	BCMP2P_STATUS ret;

	ret = BCMP2PCancelCreateGroup(p2pHandle);

	/* reset to default to enable P2P functionality */
	p2papi_enable_p2p((p2papi_instance_t*) p2pHandle, TRUE);

	return ret;
}

/* Set or update the WPA key */
BCMP2P_STATUS
BCMP2PUpdateWPAKey(BCMP2PHandle p2pHandle, char *key, char *passphrase)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_save_wpa_key(hdl, key, passphrase);
}


/* Set or update the WPS PIN in the link configuration. */
BCMP2P_STATUS
BCMP2PSetWPSPin(BCMP2PHandle p2pHandle, char *pin)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_save_wps_pin(hdl, pin);
}

/* Get the WPS PIN */
char *
BCMP2PGetWPSPin(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return hdl->ap_config.WPSConfig.wpsPin;
}

static int ComputeChecksum(unsigned long int PIN)
{
	unsigned long int accum = 0;
	int digit;

	PIN *= 10;
	accum += 3 * ((PIN / 10000000) % 10);
	accum += 1 * ((PIN / 1000000) % 10);
	accum += 3 * ((PIN / 100000) % 10);
	accum += 1 * ((PIN / 10000) % 10);
	accum += 3 * ((PIN / 1000) % 10);
	accum += 1 * ((PIN / 100) % 10);
	accum += 3 * ((PIN / 10) % 10);
	digit = (accum % 10);
	return (10 - digit) % 10;
}

/* Generate a random WPS PIN */
BCMP2P_STATUS
BCMP2PRandomWPSPin(BCMP2PHandle p2pHandle, BCMP2P_WPS_PIN *pin)
{
	unsigned int num;
	int cksum;

	num = 0;
	/* generate 7-digit random number */
	while (num < 1000000) {
		num = p2papi_osl_random() % 10000000;
	}
	/* calculate checksum */
	cksum = ComputeChecksum(num);

	/* append checksum */
	num = num * 10 + cksum;

	sprintf((char *)pin, "%d", num);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"BCMP2PRandomWPSPin: pin=%s\n", pin));
	return BCMP2P_SUCCESS;
}

/* generate a random passphrase */
BCMP2P_STATUS BCMP2PRandomPassphrase(BCMP2PHandle p2pHandle,
	int length, BCMP2P_PASSPHRASE *passphrase)
{
	int i;
	char *out = (char *)passphrase;

	if (length < BCMP2P_PASSPHRASE_MIN_LENGTH ||
		length > BCMP2P_PASSPHRASE_MAX_LENGTH) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"BCMP2PRandomPassphrase: invalid length=%d\n", length));
		return BCMP2P_ERROR;
	}

	for (i = 0; i < length; i++) {
		out[i] = p2papi_random_char();
	}
	out[length] = 0;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "BCMP2PRandomPassphrase: passphrase=%s\n", passphrase));
	return BCMP2P_SUCCESS;
}

/* Set the link configuration security to use for incoming connections if
 * the Group Owner Negotiation determines this device will act as an AP.
 */
BCMP2P_STATUS
BCMP2PSetLinkConfig(BCMP2PHandle p2pHandle, BCMP2P_CONFIG *pConfig,
	char *ssid)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_save_link_config(hdl, pConfig, (uint8*)ssid);
}


#ifndef SOFTAP_ONLY
/* Process an incoming P2P connection */
BCMP2P_STATUS
BCMP2PProcessIncomingConnection(BCMP2PHandle p2pHandle,
	BCMP2P_UINT32 timeout_secs)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	if (procIncomingOverrideFn) {
		return procIncomingOverrideFn(p2pHandle, timeout_secs);
	} else {
		return p2papi_process_incoming_conn(hdl, timeout_secs);
	}
}

/* Generate a random link configuration */
BCMP2P_STATUS
BCMP2PGenerateRandomLinkConfig(BCMP2PHandle p2pHandle, PBCMP2P_CONFIG pConfig)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_generate_rnd_link_cfg(hdl, pConfig);
}

BCMP2P_STATUS
BCMP2PGetPeerInfo(BCMP2PHandle p2pHandle, BCMP2P_PEER_INFO * pBuffer,
	BCMP2P_UINT32 buffLength, BCMP2P_UINT32 *numEntries)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_get_peer_info(hdl, pBuffer, buffLength, numEntries);
}

BCMP2P_STATUS
BCMP2PGetPeerIPInfo(BCMP2PHandle p2pHandle,
	PBCMP2P_PEER_IPINFO pBuffer, BCMP2P_UINT32 buffLength,
	BCMP2P_UINT32 *numEntries)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_get_peer_ip_info(hdl, pBuffer, buffLength, numEntries);
}

BCMP2P_BOOL
BCMP2PIsDiscovering(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_is_discovering(hdl);
}

BCMP2P_BOOL
BCMP2PIsListenOnly(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_is_listen_only(hdl);
}

BCMP2P_BOOL
BCMP2PIsConnecting(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_is_connecting(hdl);
}

BCMP2P_BOOL
BCMP2PIsSTA(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_is_sta(hdl);
}

BCMP2P_BOOL
BCMP2PIsAP(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_is_ap(hdl);
}

BCMP2P_BOOL
BCMP2PIsGroupOwner(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return FALSE;
	return (hdl->is_p2p_group);
}
#endif /* SOFTAP_ONLY */
/* Push WPS pushbutton. */
BCMP2P_STATUS
BCMP2PPushButton(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_push_button(hdl);
}

BCMP2P_BOOL
BCMP2PIsProvision(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return FALSE;

	return p2papi_is_provision(hdl);
}


BCMP2P_API BCMP2P_STATUS
BCMP2POpenWPSWindow(BCMP2PHandle p2pHandle, BCMP2P_BOOL enable,
	BCMP2P_UINT32 autoCloseSecs)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	if (enable) {
		p2papi_open_wpsreg_window(hdl, autoCloseSecs);
	} else {
		p2papi_close_wpsreg_window(hdl);
	}

	return BCMP2P_SUCCESS;
}

/* BCMP2PSetSoftAPUseWPSVersion1 is only for SoftAP to switch the wps version */
/* P2P device should not use this function                   */
BCMP2P_API BCMP2P_STATUS  BCMP2PSetSoftAPUseWPSVersion1(BCMP2P_BOOL useWPSv1)
{
	p2papi_set_wps_use_ver_1(useWPSv1 ? true : false);
	return BCMP2P_SUCCESS;
}


BCMP2P_BOOL
BCMP2PIsWPSWindowOpen(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_is_wpsreg_window_open(hdl);
}

BCMP2P_STATUS BCMP2PSetWPSRegistrarTimeout(
	BCMP2PHandle p2pHandle, BCMP2P_UINT32 seconds)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	hdl->wps_auto_close_secs = seconds;
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS BCMP2PCancelWPSRegistrar(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	p2papi_close_wpsreg_window(hdl);
	return BCMP2P_SUCCESS;
}

/* Sets the function of the MACList: either allow or deny */
BCMP2P_STATUS
BCMP2PSetMACListMode(BCMP2PHandle p2pHandle, BCMP2P_MAC_FILTER_MODE mode)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_set_maclist_mode(hdl, mode);
}

/* Set the MAC address list to allow/deny */
BCMP2P_STATUS
BCMP2PSetMACList(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *macList, BCMP2P_UINT32 macListCount)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_set_maclist(hdl, macList, macListCount);
}

/* Get the previously set MAC address list to allow/deny */
BCMP2P_STATUS
BCMP2PGetMACList(BCMP2PHandle p2pHandle,
	BCMP2P_UINT32 macListMax, BCMP2P_ETHER_ADDR *macList,
	BCMP2P_UINT32 *macListCount, BCMP2P_MAC_FILTER_MODE *mode)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_get_maclist(hdl, macListMax, macList, macListCount, mode);
}


/* Deauthenticate a STA */
BCMP2P_STATUS
BCMP2PDeauth(BCMP2PHandle p2pHandle, BCMP2P_ETHER_ADDR *mac_address)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_deauth_sta(hdl, mac_address->octet);
}

/* Get a list of associated STAs */
BCMP2P_STATUS
BCMP2PGetAssocList(BCMP2PHandle p2pHandle,
	BCMP2P_UINT32 maclist_max, BCMP2P_ETHER_ADDR *maclist,
	BCMP2P_UINT32 *maclist_count)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_STATUS ret;

	ret = p2papi_get_assoclist(hdl, maclist_max, (struct ether_addr*) maclist,
		maclist_count);

	return ret;
}

/* Get the current operating channel number */
BCMP2P_STATUS
BCMP2PGetChannel(BCMP2PHandle p2pHandle, BCMP2P_CHANNEL *channel)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_STATUS ret;

	ret = p2papi_get_channel(hdl, channel);
	return ret;
}


BCMP2P_BOOL
BCMP2PIsSoftAPOn(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_is_softap_ready(hdl);
}

BCMP2P_BOOL
BCMP2PIsDHCPOn(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_is_dhcp_on(hdl);
}

/*
 * Ioctl/iovar functions.
 */
BCMP2P_API BCMP2P_STATUS
BCMP2PIoctlGet(BCMP2PHandle p2pHandle,
	int cmd, void *buf, int len)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_ioctl_get(hdl, cmd, buf, len, 0);
}

BCMP2P_API BCMP2P_STATUS
BCMP2PIoctlSet(BCMP2PHandle p2pHandle,
	int cmd, void *buf, int len)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_ioctl_set(hdl, cmd, buf, len, 0);
}

BCMP2P_API BCMP2P_STATUS
BCMP2PIovarGet(BCMP2PHandle p2pHandle,
	const char *iovar, void *buf, int len)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_iovar_get(hdl, iovar, buf, len);
}

BCMP2P_API BCMP2P_STATUS
BCMP2PIovarSet(BCMP2PHandle p2pHandle,
	const char *iovar, void *buf, int len)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_iovar_set(hdl, iovar, buf, len);
}

BCMP2P_API BCMP2P_STATUS
BCMP2PIovarIntegerGet(BCMP2PHandle p2pHandle,
	const char *iovar, int *val)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_iovar_integer_get(hdl, iovar, val);
}

BCMP2P_API BCMP2P_STATUS
BCMP2PIovarIntegerSet(BCMP2PHandle p2pHandle,
	const char *iovar, int val)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_iovar_integer_set(hdl, iovar, val);
}

BCMP2P_API BCMP2P_STATUS
BCMP2PIovarBufferGet(BCMP2PHandle p2pHandle,
	const char *iovar, void *param,	int paramlen, void *bufptr, int buflen)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_iovar_buffer_get(hdl, iovar, param, paramlen, bufptr, buflen);
}

BCMP2P_API BCMP2P_STATUS
BCMP2PIovarBufferSet(BCMP2PHandle p2pHandle,
	const char *iovar, void *param,	int paramlen, void *bufptr, int buflen)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_iovar_buffer_set(hdl, iovar, param, paramlen, bufptr, buflen);
}


/* Get the SoftAP's IP address */
BCMP2P_STATUS
BCMP2PGetIP(BCMP2PHandle p2pHandle, BCMP2P_IP_ADDR *ipaddr,
	BCMP2P_IP_ADDR *netmask)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_get_ip_addr(hdl, ipaddr, netmask);
}

/* Get the absolute maximum number of allowed STA clients for a soft AP */
BCMP2P_UINT32
BCMP2PGetMaxSoftAPClients(void)
{
	return BCMP2P_MAX_SOFTAP_CLIENTS;
}

/* Get the OS network interface name of the connected P2P connection. */
char*
BCMP2PGetNetifName(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_get_netif_name(hdl);
}

/* Get our randomly generated P2P Group Owner name */
char*
BCMP2PGetGOName(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_get_go_name(hdl);
}

/* Get credentials currently in use.
 * Copies values to buffers supplied by the caller.
 *
 * outSSID - not null terminated    TODO: CHANGE TO BE NUL TERMINATED?
 *         - must have room for BCMP2P_MAX_SSID_LEN bytes
 *
 * outKeyWPA - null terminated
 *           - must have room for BCMP2P_MAX_WPA_KEY_LEN + 1 bytes
 *             (WSEC_MAX_PSK_LEN + 1)
 */
BCMP2P_STATUS
BCMP2PGetGOCredentials(BCMP2PHandle p2pHandle,
	BCMP2P_UINT8* outSSID,
	BCMP2P_UINT8* outKeyWPA,
	BCMP2P_UINT8* outPassphrase)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return p2papi_get_go_credentials(hdl, outSSID, outKeyWPA, outPassphrase);
}

/* Get our P2P Device Address */
BCMP2P_STATUS
BCMP2PGetDevAddr(BCMP2PHandle p2pHandle, BCMP2P_ETHER_ADDR *outDevAddr)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	struct ether_addr* dev_addr;

	dev_addr = p2papi_get_p2p_dev_addr(hdl);
	memcpy(outDevAddr, dev_addr, sizeof(*outDevAddr));

	return BCMP2P_SUCCESS;
}

/* Get our P2P Interface Address */
BCMP2P_STATUS
BCMP2PGetIntAddr(BCMP2PHandle p2pHandle, BCMP2P_ETHER_ADDR *outIntAddr)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	struct ether_addr* int_addr;

	int_addr = p2papi_get_p2p_int_addr(hdl);
	memcpy(outIntAddr, int_addr, sizeof(*outIntAddr));

	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
BCMP2PGetGODevAddr(BCMP2PHandle p2pHandle, BCMP2P_ETHER_ADDR *outGODevAddr)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	struct ether_addr* dev_addr;

	dev_addr = p2papi_get_go_dev_addr(hdl);
	memcpy(outGODevAddr, dev_addr, sizeof(*outGODevAddr));

	return BCMP2P_SUCCESS;
}

#ifndef SOFTAP_ONLY
/* Enable persistent group capability */
BCMP2P_STATUS
BCMP2PEnablePersistent(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL enable)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	p2papi_enable_persistent(hdl, enable);
	return status;
}

/* Whether persistent capability is enabled */
BCMP2P_BOOL
BCMP2PIsPersistentEnabled(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_is_persistent_enabled(hdl);
}

/* Whether we are in a persistent group */
BCMP2P_BOOL
BCMP2PInPersistentGroup(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_in_persistent_group(hdl);
}


/* Send a P2P Invitation Request from an active GO to a target device */
BCMP2P_STATUS
BCMP2PSendInviteReqFromGO(BCMP2PHandle p2pHandle,
	PBCMP2P_DISCOVER_ENTRY pDestPeer)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return (BCMP2P_STATUS)p2papi_tx_invite_req_from_active_go(hdl,
		(struct ether_addr*)pDestPeer->mac_address, &pDestPeer->channel);
}

/* Send a P2P Invitation Request from an active GO to a target device */
BCMP2P_STATUS
BCMP2PSendInviteReqFromActiveGO(BCMP2PHandle p2pHandle,
	PBCMP2P_DISCOVER_ENTRY pDestPeer)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return (BCMP2P_STATUS)p2papi_tx_invite_req_from_active_go(hdl,
		(struct ether_addr*)pDestPeer->mac_address, &pDestPeer->channel);
}

/* Send a P2P Invitation Request from an inactive GO to a target device */
BCMP2P_STATUS
BCMP2PSendInviteReqFromInactiveGO(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *grp_dev_addr,
	BCMP2P_CHANNEL *dst_listen_channel, BCMP2P_ETHER_ADDR *dstDevAddr,
	BCMP2P_UINT8 *ssid, BCMP2P_UINT32 ssidLen)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return (BCMP2P_STATUS)p2papi_tx_invite_req_from_inactive_go(hdl, ssid, ssidLen,
		(struct ether_addr*)grp_dev_addr,
		(struct ether_addr*)dstDevAddr, dst_listen_channel);
}

/* Send a P2P Invitation Request from an connected or unconnected GC to a
 * target device.
 */
BCMP2P_STATUS
BCMP2PSendInviteReqFromGC(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *grp_dev_addr,
	BCMP2P_UINT8 *ssid, BCMP2P_UINT32 ssidLen,
	BCMP2P_ETHER_ADDR *dstAddr,
	BCMP2P_CHANNEL *dst_listen_channel)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return (BCMP2P_STATUS)p2papi_tx_invite_req_from_gc(hdl, ssid, ssidLen,
		(struct ether_addr*)grp_dev_addr,
		(struct ether_addr*)dstAddr, dst_listen_channel);
}

/* Send a P2P Invitation Request */
BCMP2P_STATUS
BCMP2PSendInviteRequest(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *dst, BCMP2P_CHANNEL *dst_listen_channel,
	BCMP2P_CHANNEL *op_channel,
	BCMP2P_ETHER_ADDR *grp_bssid, BCMP2P_BOOL is_reinvoke,
	BCMP2P_ETHER_ADDR *grpid_dev_addr,
	BCMP2P_UINT8 *grpid_ssid, BCMP2P_UINT32 grpid_ssid_len)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return (BCMP2P_STATUS)p2plib_tx_invite_req(hdl,
		(struct ether_addr *)dst, dst_listen_channel,
		op_channel, (struct ether_addr *)grp_bssid,
		is_reinvoke ? P2P_INVSE_REINVOKE_PERSIST_GRP : P2P_INVSE_JOIN_ACTIVE_GRP,
		(struct ether_addr *)grpid_dev_addr,
		(char *)grpid_ssid, grpid_ssid_len);
}

/* Send a P2P Invitation Response */
BCMP2P_STATUS
BCMP2PSendInviteResponse(BCMP2PHandle p2pHandle,
	BCMP2P_INVITE_PARAM *invitation_req, BCMP2P_INVITE_RESPONSE response,
	BCMP2P_BOOL isGO)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return (BCMP2P_STATUS)p2papi_tx_invite_rsp(hdl, invitation_req, response, isGO ? true : false);
}


/* Join an existing P2P Group without GO Negotiation, using WPS to obtain the
 * credentials.
 */
BCMP2P_STATUS
BCMP2PJoinGroupWithWps(BCMP2PHandle p2pHandle, BCMP2P_ETHER_ADDR *grpBssid,
	BCMP2P_UINT8 *grpSsid, BCMP2P_UINT32 grpSsidLen,
	BCMP2P_ETHER_ADDR *grpDevAddr, BCMP2P_CHANNEL *grpOpChannel)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_join_group_with_wps(hdl, (struct ether_addr*)grpBssid,
		grpSsid, grpSsidLen, (struct ether_addr*)grpDevAddr, grpOpChannel);
}

/* Join an existing P2P Group using the given WPA2-PSK AES credentials, without
 * GO negotiation, without WPS.
 */
BCMP2P_STATUS
BCMP2PJoinGroupWithCredentials(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *devAddr,
	BCMP2P_CHANNEL *channel,
	BCMP2P_UINT8 *ssid, BCMP2P_UINT32 ssidLength,
	BCMP2P_ETHER_ADDR *bssid, BCMP2P_UINT8 *outKeyWPA,
	BCMP2P_UINT32 timeout)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	hdl->join_timeout_secs = timeout;

	return p2papi_join_group_with_credentials(hdl,
		(struct ether_addr *)devAddr, channel,
		(char *)ssid, (struct ether_addr*)bssid,
		BRCM_WPS_AUTHTYPE_WPA2PSK, BRCM_WPS_ENCRTYPE_AES,
		(char *)outKeyWPA, 0);
}
#endif /* not SOFTAP_ONLY */


#ifndef SOFTAP_ONLY
/* Register a service pair to service data store */
BCMSVCHandle
BCMP2PRegService(BCMP2PHandle p2pHandle, BCMP2P_UINT32 svcId, BCMP2P_SVC_PROTYPE svcProtocol,
	const BCMP2P_UINT8 *queryData, BCMP2P_UINT32 queryDataSize,
	const BCMP2P_UINT8 *respData, BCMP2P_UINT32 respDataSize)
{
	BCMSVCHandle *hdl = NULL;

	if (!P2PAPI_CHECK_P2PHDL(p2pHandle))
		return (NULL);

	p2plib_sd_register_svc_data(svcId, (p2psd_svc_protype_t)svcProtocol, queryData,
		queryDataSize, respData, respDataSize, (void **)&hdl);

	return (BCMP2PHandle)hdl;
}

/* Deregister a service from P2P library */
BCMP2P_STATUS
BCMP2PDeregService(BCMP2PHandle p2pHandle, BCMP2PHandle svcHanle)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	status = p2plib_sd_deregister_svc_data(svcHanle);

	return status;
}

/* Get current registered service data from Service Data Store in P2P library */
BCMP2P_STATUS
BCMP2PGetRegisteredService(BCMP2PHandle p2pHandle, BCMP2P_SVC_PROTYPE svcProtocol,
	BCMP2P_UINT8 *queryData, BCMP2P_UINT32 queryDataLen, BCMP2P_UINT8 *respDataBuf,
	BCMP2P_UINT32 *respDataLen, BCMP2P_UINT32* svcId)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	status = p2plib_sd_get_registered_service(svcProtocol, queryData,
		queryDataLen, respDataBuf, respDataLen, svcId);

	return status;
}

/* Discover serivce from a found p2p device */
BCMP2P_API BCMP2P_STATUS BCMP2PDiscoverService(BCMP2PHandle p2pHandle,
	BCMP2P_DISCOVER_ENTRY *p2pDevice, BCMP2P_SVC_LIST *svcQueryEntries)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	status = p2plib_sd_start_req_to_peer(hdl, (struct ether_addr *)p2pDevice->mac_address,
		&p2pDevice->channel, svcQueryEntries, false);

	return status;
}

/* Cancel service discovery with the responding peer device */
BCMP2P_API BCMP2P_STATUS BCMP2PCancelDiscoverService(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *rspDeviceAddr)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	status = p2plib_sd_cancel_req_svc(hdl, (struct ether_addr*)rspDeviceAddr);

	return status;
}

/* Retrieve services at the completion of BCMP2PDiscoverService */
BCMP2P_API BCMP2P_STATUS BCMP2PGetDiscoverService(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *peerAddr, BCMP2P_SVC_LIST **svcEntries)
{
	BCMP2P_SVC_LIST *svc;

	svc = p2plib_sd_get_peer_svc((struct ether_addr *)peerAddr);

	*svcEntries = svc;
	if (svc == 0)
		return BCMP2P_ERROR;
	else
		return BCMP2P_SUCCESS;
}

/* Get string that corresponds to status enum. */
const char *
BCMP2PStatusCodeToStr(BCMP2P_STATUS status)
{
	if ((status > 0) || (status <= -BCMP2P_STATUS_LAST)) {
		return ("");
	}

	return (g_status_str_table[-status]);
}

/* Enable opportunistic power save */
BCMP2P_STATUS BCMP2PEnableOppPwrSave(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL enable,	BCMP2P_UINT8 ctwindow)
{

	if (p2pwlu_set_ops((p2papi_instance_t*)p2pHandle, enable ? true : false, ctwindow) != 0)
		return BCMP2P_ERROR;

	return BCMP2P_SUCCESS;
}

/* Set NoA schedule */
BCMP2P_STATUS BCMP2PSetNoaSchedule(BCMP2PHandle p2pHandle,
	BCMP2P_NOA_TYPE type, BCMP2P_NOA_ACTION action, BCMP2P_NOA_OPTION option,
	int numDesc, BCMP2P_NOA_DESC *desc)
{
	int i;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"BCMP2PSetNoaSchedule: type=%d act=%d opt=%d numDesc=%d\n",
		type, action, option, numDesc));
	for (i = 0; i < numDesc; i++) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"    %i) start=%u int=%u dur=%u count=%u\n", i,
			desc[i].start, desc[i].interval, desc[i].duration, desc[i].count));
	}

	if (p2pwlu_set_noa((p2papi_instance_t*)p2pHandle, type, action, option,
		numDesc, (wl_p2p_sched_desc_t *)desc) != 0)
		return BCMP2P_ERROR;

	return BCMP2P_SUCCESS;
}


/* Send a Presence Request action frame from a GC to a connected GO */
BCMP2P_STATUS BCMP2PSendPresenceRequest(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL isPreferred,
	BCMP2P_UINT32 preferredDuration, BCMP2P_UINT32 preferredInterval,
	BCMP2P_BOOL isAcceptable,
	BCMP2P_UINT32 acceptableDuration, BCMP2P_UINT32 acceptableInterval)
{
	if (p2papi_presence_request((p2papi_instance_t*)p2pHandle,
		isPreferred ? true : false, preferredDuration, preferredInterval,
		isAcceptable ? true : false, acceptableDuration, acceptableInterval))
		return BCMP2P_ERROR;

	return BCMP2P_SUCCESS;
}

/* Enable/disable extended listen timing */
BCMP2P_STATUS BCMP2PExtendedListenTiming(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL isEnable, BCMP2P_UINT32 period, BCMP2P_UINT32 interval)
{
	return p2papi_extended_listen_timing((p2papi_instance_t*)p2pHandle,
		isEnable ? true : false, period, interval);
}

/* Wait for the peer to disconnect.  Returns only when the peer disconnects */
BCMP2P_STATUS
BCMP2PWaitForDisconnect(BCMP2PHandle p2pHdl)
{
	int ret;
	ret = p2papi_wait_for_disconnect(p2pHdl);

	return (ret == 0) ? BCMP2P_SUCCESS : BCMP2P_ERROR;
}

/* Send a Device Discoverability Request action frame to a P2P Group Owner to
 * request a GO client to become available for communication with us.
 */
BCMP2P_STATUS
BCMP2PSendDevDiscoverabilityReq(BCMP2PHandle p2pHandle,
	PBCMP2P_DISCOVER_ENTRY pDstGO, BCMP2P_ETHER_ADDR *clientAddr)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	int ret;

	ret = p2papi_tx_dev_discb_req(hdl, (struct ether_addr*)pDstGO->mac_address,
		pDstGO->ssid, (int) pDstGO->ssidLength, &pDstGO->channel,
		(struct ether_addr*)clientAddr);

	return (ret == 0) ? BCMP2P_SUCCESS : BCMP2P_ERROR;
}

/* Get a discovered GO's Nth GO client from the GO's probe response P2P IE
 * Group Info attribute.
 */
BCMP2P_STATUS
BCMP2PGetDiscoveredGOClientInfo(
	BCMP2PHandle p2pHandle, PBCMP2P_DISCOVER_ENTRY pGO, int clientIndex,
	BCMP2P_ETHER_ADDR *outClientAddr)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_get_discovered_go_client(hdl, pGO, clientIndex,
		(struct ether_addr*)outClientAddr);
}
#endif /* not SOFTAP_ONLY */

/* Set power saving mode */
BCMP2P_STATUS
BCMP2PSetPowerSavingMode(BCMP2PHandle p2pHandle, BCMP2P_PS_MODE mode)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_set_power_saving_mode(hdl, (int)mode);
}

/* Get power saving mode */
BCMP2P_STATUS
BCMP2PGetPowerSavingMode(BCMP2PHandle p2pHandle, BCMP2P_PS_MODE *mode)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	return p2papi_get_power_saving_mode(hdl, (int *)mode);
}

/* Enable intra-BSS capability. */
BCMP2P_STATUS
BCMP2PEnableIntraBss(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL enable)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	p2papi_enable_intra_bss(hdl, enable);
	return status;
}

/* Enable concurrent operation capability. */
BCMP2P_STATUS
BCMP2PEnableConcurrent(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL enable)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	p2papi_enable_concurrent(hdl, enable);
	return status;
}

#ifndef SOFTAP_ONLY
/* Enable P2P invitation capability. */
BCMP2P_STATUS
BCMP2PEnableInvitation(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL enable)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	p2papi_enable_invitation(hdl, enable);
	return status;
}

/* Enable service discovery capability. */
BCMP2P_STATUS
BCMP2PEnableServiceDiscovery(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL enable)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	p2papi_enable_service_discovery(hdl, enable);
	return status;
}

/* Enable client discovery capability. */
BCMP2P_STATUS
BCMP2PEnableClientDiscovery(BCMP2PHandle p2pHandle,
	BCMP2P_BOOL enable)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	p2papi_enable_client_discovery(hdl, enable);
	return status;
}


#endif /* SOFTAP_ONLY */

/* Set the operating channel. */
BCMP2P_STATUS BCMP2PSetOperatingChannel(BCMP2PHandle p2pHandle,
	BCMP2P_CHANNEL_CLASS channel_class, BCMP2P_UINT32 channel)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_CHANNEL ch;

	ch.channel_class = channel_class;
	ch.channel = channel;

	if (!p2papi_is_valid_channel(&ch))
		return BCMP2P_ERROR;

	memcpy(&hdl->op_channel, &ch, sizeof(hdl->op_channel));
	memcpy(&hdl->ap_config.operatingChannel, &ch,
		sizeof(hdl->ap_config.operatingChannel));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"BCMP2PSetOperatingChannel: channel=%d:%d\n",
		ch.channel_class, ch.channel));
	p2papi_refresh_ies(hdl);
	return BCMP2P_SUCCESS;
}

/* Get the operating channel. */
BCMP2P_STATUS BCMP2PGetOperatingChannel(BCMP2PHandle p2pHandle,
	BCMP2P_CHANNEL_CLASS *channel_class, BCMP2P_UINT32 *channel)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	*channel_class = hdl->op_channel.channel_class;
	*channel = hdl->op_channel.channel;
	return BCMP2P_SUCCESS;
}

/* Set the intent value. */
BCMP2P_STATUS BCMP2PSetIntent(BCMP2PHandle p2pHandle,
	BCMP2P_UINT32 intent)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	hdl->ap_config.grp_owner_intent = intent;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"BCMP2PSetIntent: intent=%d\n", hdl->ap_config.grp_owner_intent));
	return BCMP2P_SUCCESS;
}

/* Get the intent value. */
BCMP2P_UINT32 BCMP2PGetIntent(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return hdl->ap_config.grp_owner_intent;
}

/* Select the WPS config method to be used. */
BCMP2P_STATUS BCMP2PSelectWpsConfigMethod(BCMP2PHandle p2pHandle,
	BCMP2P_WPS_CONFIG_METHOD_TYPE configMethod)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	BCMP2P_WPS_DEVICE_PWD_ID devicePwdId = BCMP2P_WPS_DEFAULT;

	if (configMethod == BCMP2P_WPS_LABEL) {
		devicePwdId = BCMP2P_WPS_DEFAULT;
	}
	else if (configMethod == BCMP2P_WPS_DISPLAY) {
		devicePwdId = BCMP2P_WPS_REG_SPEC;
	}
	else if (configMethod == BCMP2P_WPS_KEYPAD) {
		devicePwdId = BCMP2P_WPS_USER_SPEC;
	}
	else if (configMethod == BCMP2P_WPS_PUSHBUTTON) {
		devicePwdId = BCMP2P_WPS_PUSH_BTN;
	}
	else {
		status = BCMP2P_ERROR;
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"BCMP2PSetWpsConfigMethod: cfgMeth=0x%x devPwdId=%d st=%d\n",
		configMethod, devicePwdId, status));

	if (status == BCMP2P_SUCCESS) {
		hdl->wps_device_pwd_id = devicePwdId;
	}

	return status;
}

/* Set the supported WPS config methods. */
BCMP2P_STATUS BCMP2PSetSupportedWpsConfigMethods(BCMP2PHandle p2pHandle,
	BCMP2P_WPS_CONFIG_METHODS configMethods)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;

	p2papi_clear_provision(hdl);
	hdl->ap_config.WPSConfig.wpsConfigMethods = configMethods;
	p2papi_refresh_ies(hdl);

	return BCMP2P_SUCCESS;
}

/* Get the supported WPS config methods. */
BCMP2P_WPS_CONFIG_METHODS BCMP2PGetSupportedWpsConfigMethods(BCMP2PHandle p2pHandle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	return hdl->ap_config.WPSConfig.wpsConfigMethods;
}

/* Set the listen interval. */
BCMP2P_STATUS BCMP2PSetListenInterval(BCMP2PHandle p2pHandle,
                                      unsigned int interval)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	hdl->listen_interval = interval;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"BCMP2PSetListenInterval: listen interval=%u\n", interval));

	return (BCMP2P_SUCCESS);
}

/* Set the primary device type */
BCMP2P_API BCMP2P_STATUS BCMP2PSetPrimaryDeviceType(BCMP2PHandle p2pHandle,
	BCMP2P_UINT8 category, BCMP2P_UINT8 subCategory)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2pHandle;
	hdl->pri_dev_type = category;
	hdl->pri_dev_subcat = subCategory;

	return BCMP2P_SUCCESS;
}

/*
 * Get channel class for a channel specified in 'chanspec' format
 *
 * 'chanspec' is a 16-bit integer and it holds channel-number, band, bandwidth and control sideband:
 *    +------------------------------------------------------+
 *    | 15 | 14 | 13 | 12 | 11 | 10 | 9 | 8 | 7   to      0  |
 *    |---------|--------------|------------|----------------|
 *    | Band    | BW           |    SB      | channel number |
 *    +------------------------------------------------------+
 *    bit 15 - 14: 2 bits, spectral band (0: 2GHz, 1: 3GHz, 2: 4GHz, 3: 5GHz)
 *    bit 13 - 11: 3 bits, bandwidth (0: 5MHz, 1:10MHz, 2:20Mhz, 3:40MHz, 4:80Mhz, 5:160MHz, 6:80+80MHz)
 *    bit 10 -  8: 3 bits, sideband 
 *                 0: 20MHz primary 0:lower 1:upper
 *                 1: 40MHz primary 0:lower 1:upper
 *                 2: 80MHz primary 0:lower 1:upper
 *    bit  7 -  0: 8 bits, channel number
 */
BCMP2P_API BCMP2P_BOOL BCMP2PChanspecToChannel(BCMP2P_UINT16 inChanspec,
	BCMP2P_CHANNEL *outChannel)
{
	return p2papi_chspec_to_channel((chanspec_t) inChanspec, outChannel);
}

/*
 * Get channel in 'chanspec' format from a HSL channel
 */
BCMP2P_API BCMP2P_BOOL BCMP2PChannelToChanspec(BCMP2P_CHANNEL *inChannel,
	BCMP2P_UINT16 *outChanspec)
{
	chanspec_t chspec;
	if (p2papi_channel_to_chspec(inChannel, &chspec))
	{
		*outChanspec = chspec;
		return BCMP2P_TRUE;
	}

	return BCMP2P_FALSE;
}

/* Get channel class for a specified channel */
BCMP2P_API BCMP2P_BOOL BCMP2PGetChannelClass(BCMP2P_UINT32 channel,
	BCMP2P_BOOL is_40mhz, BCMP2P_CHANNEL_CLASS *channel_class)
{
	/* note, for 11ac, use BCMP2PGetChannelClassChanspec() */
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_ACRATES)
	chanspec_t chanspec = is_40mhz ? CH40MHZ_CHSPEC(channel, WL_CHANSPEC_CTL_SB_LOWER) : CH20MHZ_CHSPEC(channel);

	BCMP2P_CHANNEL	hslChannel;
	if (BCMP2PChanspecToChannel(chanspec, &hslChannel))
	{
		*channel_class = hslChannel.channel_class;
		return BCMP2P_TRUE;
	}

	return BCMP2P_FALSE;

#else
	return p2papi_find_channel_class(channel, is_40mhz ? true : false, channel_class);
#endif
}

/* Convert channel to string */
BCMP2P_API BCMP2P_STATUS BCMP2PChannelToString(BCMP2P_CHANNEL *channel,
	BCMP2P_CHANNEL_STRING buffer)
{
	chanspec_t chspec;

	if (p2papi_channel_to_chspec(channel, &chspec)) {
		p2papi_chspec_ntoa(chspec, buffer);
		return BCMP2P_SUCCESS;
	}
	return BCMP2P_ERROR;
}

/* Convert string to channel */
BCMP2P_API BCMP2P_STATUS BCMP2PStringToChannel(char *string,
	BCMP2P_CHANNEL *channel)
{
	chanspec_t chspec;
	BCMP2P_CHANNEL ch;

	chspec = p2papi_chspec_aton(string);
	if (chspec != 0) {
		if (p2papi_chspec_to_channel(chspec, &ch)) {
			memcpy(channel, &ch, sizeof(*channel));
			return BCMP2P_SUCCESS;
		}
	}
	return BCMP2P_ERROR;
}

/* Set channel list and override the default channel list defined by
 * the WLAN interface.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PSetChannelList(BCMP2PHandle p2pHandle,
	int numChannels, BCMP2P_CHANNEL *channels)
{
	p2papi_instance_t *hdl = (p2papi_instance_t *)p2pHandle;

	/* use default channel list */
	if (numChannels == 0) {
		if (hdl->user_channel_list != 0) {
			free(hdl->user_channel_list);
			hdl->user_channel_list = 0;
		}
	}

	if (hdl->user_channel_list == 0) {
		hdl->user_channel_list =
			(p2p_chanlist_t *)malloc(sizeof(*hdl->user_channel_list));
		if (hdl->user_channel_list == 0)
			return BCMP2P_ERROR;
	}

	if (!p2papi_channel_array_to_list(numChannels, channels,
		hdl->user_channel_list)) {
		free(hdl->user_channel_list);
		hdl->user_channel_list = 0;
		return BCMP2P_ERROR;
	}

	return BCMP2P_SUCCESS;
}

/* Channel list returned will either be the default channel list defined
 * by WLAN interface or channel list overriden by BCMP2PSetChannelList.
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetChannelList(BCMP2PHandle p2pHandle,
	int maxNumChannels, BCMP2P_CHANNEL *channels, int *numChannels)
{
	p2papi_instance_t *hdl = (p2papi_instance_t *)p2pHandle;

	if (!p2papi_channel_list_to_array(p2papi_get_non_dfs_channel_list(hdl),
		maxNumChannels, channels, numChannels))
		return BCMP2P_ERROR;

	return BCMP2P_SUCCESS;
}

/* Channel list returned will be the default channel list defined
 * by WLAN interface
 */
BCMP2P_API BCMP2P_STATUS BCMP2PGetDefaultValidChannelList(BCMP2PHandle p2pHandle,
	int maxNumChannels, BCMP2P_CHANNEL *channels, int *numChannels)
{
	p2papi_instance_t *hdl = (p2papi_instance_t *)p2pHandle;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (!p2papi_channel_list_to_array(&hdl->non_dfs_channel_list,
		maxNumChannels, channels, numChannels))
		return BCMP2P_ERROR;

	return BCMP2P_SUCCESS;
}

#ifndef SOFTAP_ONLY

BCMP2P_STATUS BCMP2PConnect(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *peerDeviceAddr,
	BCMP2P_PERSISTENT *persist)
{
	BCMP2P_DISCOVER_ENTRY peerInfo;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "BCMP2PConnect: %02x:%02x:%02x:%02x:%02x:%02x\n",
		peerDeviceAddr->octet[0], peerDeviceAddr->octet[1], peerDeviceAddr->octet[2],
		peerDeviceAddr->octet[3], peerDeviceAddr->octet[4], peerDeviceAddr->octet[5]));

	/* get peer information */
	if (BCMP2PGetDiscoverPeer(p2pHandle, peerDeviceAddr, &peerInfo) != BCMP2P_SUCCESS)
		return BCMP2P_PEER_NOT_FOUND;

	/* no need to access svc-resp/ie-data, simply free it */
	BCMP2PFreeDiscoverResultData(p2pHandle, &peerInfo, 1);

	return BCMP2PConnect2(p2pHandle,
		peerDeviceAddr,	&peerInfo.channel, peerInfo.is_p2p_group,
		(BCMP2P_ETHER_ADDR *)peerInfo.int_address, (char *)peerInfo.grp_ssid,
		persist);
}

BCMP2P_STATUS BCMP2PConnect2(BCMP2PHandle p2pHandle,
	BCMP2P_ETHER_ADDR *peerDeviceAddr, BCMP2P_CHANNEL *peerChannel,
	BCMP2P_BOOL isPeerGo, BCMP2P_ETHER_ADDR *peerIntAddr,
	char *peerSsid, BCMP2P_PERSISTENT *persist)
{
	BCMP2P_STATUS status = BCMP2P_ERROR;
	BCMP2P_BOOL isPersist = BCMP2P_FALSE;
	/* wait time to allow group to be created before sending invite */
	uint16 go_cfg_tmo_ms = 500;
	p2papi_instance_t *hdl = (p2papi_instance_t *)p2pHandle;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "BCMP2PConnect2\n"));

	if (peerDeviceAddr != 0)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "peerDeviceAddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
			peerDeviceAddr->octet[0], peerDeviceAddr->octet[1],
			peerDeviceAddr->octet[2], peerDeviceAddr->octet[3],
			peerDeviceAddr->octet[4], peerDeviceAddr->octet[5]));
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "peerDeviceAddr=<null>\n"));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "peerChannel=%d:%d\n",
		peerChannel->channel_class, peerChannel->channel));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "isPeerGo=%d\n", isPeerGo));

	if (peerIntAddr != 0)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "peerIntAddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
			peerIntAddr->octet[0], peerIntAddr->octet[1], peerIntAddr->octet[2],
			peerIntAddr->octet[3], peerIntAddr->octet[4], peerIntAddr->octet[5]));
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "peerIntAddr=<null>\n"));

	if (peerSsid != 0)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "peerSsid=%s\n", peerSsid));
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "peerSsid=<null>\n"));

	if (persist != 0)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "persist: is_go=%d, ssid=%s"
			" %02x:%02x:%02x:%02x:%02x:%02x\n",
			persist->is_go, persist->ssid,
			persist->peer_dev_addr.octet[0], persist->peer_dev_addr.octet[1],
			persist->peer_dev_addr.octet[2], persist->peer_dev_addr.octet[3],
			persist->peer_dev_addr.octet[4], persist->peer_dev_addr.octet[5]));
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "persist=<null>\n"));

	if (peerDeviceAddr == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "peer device address invalid\n"));
		goto exit;
	}

	/* check if persistent data available and matches peeer device address */
	if (persist != 0 &&	memcmp(&persist->peer_dev_addr,
		peerDeviceAddr,	sizeof(*peerDeviceAddr)) == 0) {
		isPersist = BCMP2P_TRUE;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "persistent credentials valid\n"));
	}
	else {
		isPersist = BCMP2P_FALSE;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "ignoring persistent credentials\n"));
	}

	if (isPeerGo) {
		/* peer is GO */
		if (peerSsid == 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "peer ssid invalid\n"));
			goto exit;
		}
		if (peerIntAddr == 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "peer interface address invalid\n"));
			goto exit;
		}

		if (isPersist && !persist->is_go &&
			peerSsid != 0 &&
			strcmp((char *)persist->ssid, peerSsid) == 0) {
			/* peer is GO with ssid matching persistent data -
			 * join using persistent credentials
			 */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "connecting to re-invoked group\n"));
			status = BCMP2PJoinGroupWithCredentials(p2pHandle,
				peerDeviceAddr,	peerChannel,
				(BCMP2P_UINT8 *)peerSsid, strlen((const char *)peerSsid),
				peerIntAddr, persist->pmk,
				BCMP2P_CONNECT_TMO_SECS);
			if (status != BCMP2P_SUCCESS) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"BCMP2PJoinGroupWithCredentials failed %d\n", status));
				goto exit;
			}
		}
		else if (!BCMP2PIsGroupOwner(p2pHandle) && !BCMP2PIsSTA(p2pHandle)) {
			/* peer is GO - join existing group using WPS */
			/* provision discovery must be run before connecting to existing group */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "connecting to existing group\n"));
			status = BCMP2PCreateLinkToDevAddr(p2pHandle,
				peerDeviceAddr, peerChannel,
				BCMP2P_TRUE, peerIntAddr, BCMP2P_CONNECT_TMO_SECS);
			if (status != BCMP2P_SUCCESS) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"BCMP2PCreateLinkToDevAddr failed %d\n", status));
				goto exit;
			}
		}
		else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "not valid connecting to GO"));
			goto exit;
		}
	}
	else if (BCMP2PIsGroupOwner(p2pHandle)) {
		BCMP2P_ETHER_ADDR intAddr;
		BCMP2P_ETHER_ADDR devAddr;
		BCMP2P_UINT8 ssid[BCMP2P_MAX_SSID_LEN + 1];
		BCMP2P_BOOL reinvoke = BCMP2P_FALSE;
		BCMP2P_CHANNEL channel;

		/* initiating device is GO */
		status = BCMP2PGetIntAddr(p2pHandle, &intAddr);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetIntAddr failed %d\n", status));
			goto exit;
		}
		status = BCMP2PGetDevAddr(p2pHandle, &devAddr);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetDevAddr failed %d\n", status));
			goto exit;
		}
		status = BCMP2PGetGOCredentials(p2pHandle, ssid, NULL, NULL);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetGOCredentials failed %d\n", status));
			goto exit;
		}
		if (isPersist && persist->is_go &&
			strcmp((char *)persist->ssid, (char *)ssid) == 0) {
			/* initiating device is GO with ssid matching persistent data -
			 * send invite to reinvoke
			 */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"GO sending invite to peer to reinvoke\n"));
			reinvoke = BCMP2P_TRUE;
		}
		else {
			/* initiating device is GO - send invite to peer to join group */
			/* peer receiving invite is required to send provision discovery */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "GO sending invite to peer\n"));
			reinvoke = BCMP2P_FALSE;
		}
		status = BCMP2PGetOperatingChannel(p2pHandle, &channel.channel_class,
			&channel.channel);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetOperatingChannel failed %d\n", status));
			goto exit;
		}
		status = BCMP2PSendInviteRequest(p2pHandle,
			peerDeviceAddr, peerChannel, &channel, &intAddr,
			reinvoke, &devAddr, ssid, strlen((char *)ssid));
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PSendInviteRequest failed %d\n", status));
			goto exit;
		}
	}
	else if (BCMP2PIsSTA(p2pHandle)) {
		BCMP2P_PEER_INFO goInfo;
		BCMP2P_UINT32 count;
		BCMP2P_ETHER_ADDR devAddr;
		BCMP2P_UINT8 ssid[BCMP2P_MAX_SSID_LEN + 1];
		BCMP2P_CHANNEL channel;

		/* initiating device is STA - send invite to peer to join group */
		/* peer receiving invite is required to send provision discovery */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "STA sending invite to peer\n"));
		/* get bssid of GO */
		status = BCMP2PGetPeerInfo(p2pHandle, &goInfo, sizeof(goInfo), &count);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetPeerInfo failed %d\n", status));
			goto exit;
		}
		/* get dev addr of GO */
		status = BCMP2PGetGODevAddr(p2pHandle, &devAddr);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetGODevAddr failed %d\n", status));
			goto exit;
		}
		/* get ssid of GO */
		status = BCMP2PGetGOCredentials(p2pHandle, ssid, NULL, NULL);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetGOCredentials failed %d\n", status));
			goto exit;
		}
		status = BCMP2PGetOperatingChannel(p2pHandle, &channel.channel_class,
			&channel.channel);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetOperatingChannel failed %d\n", status));
			goto exit;
		}
		status = BCMP2PSendInviteRequest(p2pHandle,
			peerDeviceAddr, peerChannel, &channel,
			(BCMP2P_ETHER_ADDR *)goInfo.mac_address,
			BCMP2P_FALSE, &devAddr,
			ssid, strlen((char *)ssid));
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PSendInviteRequest failed %d\n", status));
			goto exit;
		}
	}
	else if (isPersist && persist->is_go) {
		BCMP2P_ETHER_ADDR intAddr;
		BCMP2P_ETHER_ADDR devAddr;
		BCMP2P_CHANNEL channel;

		/* initiating device is persistent GO -
		 * restore GO and send invite to peer to join group
		 */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"restoring persistent GO %s\n", persist->ssid));
		status = BCMP2PUpdateWPAKey(p2pHandle,
			(char *)persist->pmk, (char *)persist->passphrase);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PUpdateWPAKey failed %d\n", status));
			goto exit;
		}
		status = BCMP2PCreateGroup(p2pHandle,
			persist->ssid, BCMP2P_TRUE);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PCreateGroup failed %d\n", status));
			goto exit;
		}

		/* allow group to be created before sending invite */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"BCMP2PConnect2 : wait for GO-cfg %u ms(extra=%u ms) before invite\n",
			go_cfg_tmo_ms, hdl->extra_peer_go_cfg_tmo_ms));

		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, go_cfg_tmo_ms);

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "GO sending invite to peer\n"));
		status = BCMP2PGetIntAddr(p2pHandle, &intAddr);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetIntAddr failed %d\n", status));
			goto exit;
		}
		status = BCMP2PGetDevAddr(p2pHandle, &devAddr);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetDevAddr failed %d\n", status));
			goto exit;
		}
		status = BCMP2PGetOperatingChannel(p2pHandle, &channel.channel_class,
			&channel.channel);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PGetOperatingChannel failed %d\n", status));
			goto exit;
		}
		status = BCMP2PSendInviteRequest(p2pHandle,
			peerDeviceAddr, peerChannel, &channel,
			&intAddr, BCMP2P_TRUE, &devAddr,
			persist->ssid, strlen((char *)persist->ssid));
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PSendInviteRequest failed %d\n", status));
			goto exit;
		}
	}
	else if (isPersist && !persist->is_go) {
		BCMP2P_CHANNEL channel;

		/* initiating device is persistent client -
		 * send invite to peer to reinvoke group and join
		 * group on successful invite response
		 */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"sending invite to reinvoke GO %s\n", persist->ssid));
		channel.channel_class = BCMP2P_DEFAULT_OP_CHANNEL_CLASS;
		channel.channel = 0;	/* not used */

		status = BCMP2PSendInviteRequest(p2pHandle,	peerDeviceAddr,
			peerChannel, &channel, 0, BCMP2P_TRUE, peerDeviceAddr,
			persist->ssid, strlen((char *)persist->ssid));
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PSendInviteRequest failed %d\n", status));
			goto exit;
		}
		/* invite response will trigger persistent client to join */
	}
	else {
		/* both devices are neither GO nor STA - group formation */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "group formation\n"));
		status = BCMP2PCreateLinkToDevAddr(p2pHandle,
			peerDeviceAddr, peerChannel,
			BCMP2P_FALSE, 0, BCMP2P_CONNECT_TMO_SECS);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"BCMP2PCreateLinkToDevAddr failed %d\n", status));
			goto exit;
		}
	}

exit:
	return status;
}

BCMP2P_STATUS
BCMP2PAddMgmtCustomIE(BCMP2PHandle p2pHandle, BCMP2P_MGMT_IE_FLAG ie_flag,
	BCMP2P_UINT8 *ie_buf, BCMP2P_UINT16 ie_buf_len, BCMP2P_BOOL set_immed)
{
	p2papi_instance_t *hdl = (p2papi_instance_t *)p2pHandle;

	return p2papi_add_mgmt_custom_ie(hdl, ie_flag, ie_buf, ie_buf_len, set_immed);
}

BCMP2P_STATUS
BCMP2PAddAcfCustomIE(BCMP2PHandle p2pHandle, BCMP2P_ACF_IE_FLAG ie_flag,
	BCMP2P_UINT8 *ie_buf, BCMP2P_UINT16 ie_buf_len)
{
	p2papi_instance_t *hdl = (p2papi_instance_t *)p2pHandle;

	return p2papi_add_acf_custom_ie(hdl, ie_flag, ie_buf, ie_buf_len);
}

BCMP2P_STATUS
BCMP2PRemoveMgmtCustomIE(BCMP2PHandle p2pHandle, BCMP2P_MGMT_IE_FLAG ie_flag)
{
	p2papi_instance_t *hdl = (p2papi_instance_t *)p2pHandle;

	return p2papi_del_mgmt_custom_ie(hdl, ie_flag);
}

BCMP2P_STATUS
BCMP2PRemoveAcfCustomIE(BCMP2PHandle p2pHandle, BCMP2P_ACF_IE_FLAG ie_flag)
{
	p2papi_instance_t *hdl = (p2papi_instance_t *)p2pHandle;

	return p2papi_del_acf_custom_ie(hdl, ie_flag);
}

BCMP2P_STATUS
BCMP2PRegisterGonReqCallabck(BCMP2PHandle p2pHandle,
	int notificationType, BCMP2P_GONREQ_CALLBACK funcCallback,
	void *pCallbackContext,	void *pReserved)
{
	p2papi_instance_t *hdl = (p2papi_instance_t *)p2pHandle;

	return p2papi_register_gon_req_cb(hdl, notificationType, funcCallback,
		pCallbackContext, pReserved);
}



BCMP2P_STATUS
BCMP2PGetReinvokeChannel(BCMP2PHandle p2pHandle, BCMP2P_CHANNEL *opChannel )
{
	p2papi_instance_t* hdl = (p2papi_instance_t *)p2pHandle;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	/* check that peers have common channels in channel list */
	if (hdl->negotiated_channel_list.num_entries == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"BCMP2PGetReinvokeChannel:"
			" no common channel list\n"));
		status = BCMP2P_ERROR;
	}

	/* check operating channel is in channel list */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"BCMP2PGetReinvokeChannel:"
		" GO's operating channel %d"
		" invite req channel = %d\n",
		opChannel->channel,
		hdl->invite_req.operatingChannel.channel));
	if (!p2papi_find_channel(opChannel,
		&hdl->negotiated_channel_list)) {
		/* Check preferred channel in invite req */
			if (!p2papi_find_channel(&hdl->invite_req.operatingChannel,
			&hdl->negotiated_channel_list)) {
				/* select operating channel from channel list */
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"BCMP2PGetReinvokeChannel:"
					"Can not match any channel\n"));
				p2papi_select_channel(opChannel,
					&hdl->negotiated_channel_list);
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"BCMP2PGetReinvokeChannel:"
					" using operating channel"
					" %d:%d from channel list\n",
					opChannel->channel_class,
					opChannel->channel));
			}
			else
			{
				memcpy (opChannel, &hdl->invite_req.operatingChannel, sizeof(BCMP2P_CHANNEL));
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"BCMP2PGetReinvokeChannel:"
					" Use invite_req op channel %d:%d \n",
					   opChannel->channel_class,
					   opChannel->channel));
			}
			status = BCMP2P_SUCCESS;
	}
	else
		status = BCMP2P_SUCCESS;
	return status;
}


#endif /* SOFTAP_ONLY */

BCMP2P_STATUS
BCMP2PStaStoreUAPSD(BCMP2PHandle p2pHandle, BCMP2P_UINT8 maxSPLength, BCMP2P_UINT8 acBE,
BCMP2P_UINT8 acBK, BCMP2P_UINT8 acVI, BCMP2P_UINT8 acVO)
{
	p2papi_instance_t* hdl = (p2papi_instance_t *)p2pHandle;

	hdl->maxSPLength = maxSPLength;
	hdl->acBE = acBE;
	hdl->acBK = acBK;
	hdl->acVI = acVI;
	hdl->acVO = acVO;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"maxsplen = %d acbe = %d acbk = %d acvi = %d acvo = %d\n",
		maxSPLength, acBE, acBK, acVI, acVO));
	return BCMP2P_SUCCESS;
}
