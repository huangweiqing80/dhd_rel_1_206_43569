/*
 * Broadcom P2P Sample App for UPNP Service Discovery
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 */

#if P2P_UPNP_DISCOVERY

#include <stdlib.h>
#include <ctype.h>

/* P2P Library include files */
#include <p2plib_api.h>
#include <p2plib_int.h>
#include <p2plib_aftx.h>
#include <p2pwl.h>


/* WL driver include files */
#include <bcmendian.h>
#include <wlioctl.h>
#include <bcmutils.h>

#include "p2p_app.h"
#include "p2papp_upnp.h"
#include "bdlna_p2p.h"

/* 0x10 represents UPnP-arch-DeviceArchitecture-v1.0 */
#define P2P_UPNP_QUERY_VERSION "0x10 "
#define P2P_UPNP_RESPONSE_VERSION "0x10 uuid:"

#define P2P_UPNP_QUERY_SSDP "0x10 ssdp:all"
#define P2P_UPNP_QUERY_ROOTDEV "0x10 upnp:rootdevice"
#define P2P_UPNP_QUERY_UUID "0x10 uuid:"


#define P2P_UPNP_QUERY_DMS "0x10 urn:schemas-upnp-org:service:ContentDirectory:1"
#define P2P_UPNP_QUERY_DMR "0x10 urn:schemas-upnp-org:service:MediaRenderer:1"


#define P2P_UPNP_MAX_QUERY_VALUES 10
#define UPNP_MAX_RUNNING_DEVICES 5

/* if unicode, following needs to be multiply by 2 */
#define UPNP_UUID_SIZE_IN_BYTES		36
#define UPNP_MAX_QUERY_BUF_SIZE		200
#define UPNP_MAX_RESPONSE_BUF_SIZE	2000
#define P2P_UPNP_MAX_DATA_CONCAT 	100
/* if unicode, above needs to be multiply by 2 */


static BCMSVCHandle upnpSvcHandle[P2P_UPNP_MAX_QUERY_VALUES];
static int uPnPsvc_num = 0;
static int p2papp_sd_register_upnp_svc(int idx,
	BCMP2P_UINT8* head_svc_query_data, BCMP2P_UINT8* uuid);


#if defined TARGETENV_android
extern int bcm_p2p_get_dms_svctypes_uuid(BP2PSvcDiscInfo_t* pSvcDiscInfo);
#else
int bcm_p2p_get_dmr_svctypes_uuid(BP2PSvcDiscInfo_t* pSvcDiscInfo);
#endif


int p2papp_sd_register_upnp_allsvcs(void)
{
	BCMP2P_UINT8 svc_query_data[UPNP_MAX_QUERY_BUF_SIZE];
	BP2PSvcDiscInfo_t svcDiscInfo;
	BCMP2P_UINT8 *temp, *temp2;
	int i = 0;
	/*
	 * Below is to be done for all upnp devices in the system
	 */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "%s Entry\n", __FUNCTION__));
#ifdef TARGETENV_android
	bcm_p2p_get_dms_svctypes_uuid(&svcDiscInfo);
#else
	bcm_p2p_get_dmr_svctypes_uuid(&svcDiscInfo);
#endif

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "svcDiscInfo %s\n", svcDiscInfo.svcTypes));

	/* ssdp:all */
	temp = svc_query_data;
	strcpy((char*)temp, P2P_UPNP_QUERY_SSDP);
	p2papp_sd_register_upnp_svc(i, svc_query_data, svcDiscInfo.uuid);
	i++;
	/* upnp:rootdevice */
	temp = svc_query_data;
	strcpy((char*)temp, P2P_UPNP_QUERY_ROOTDEV);
	p2papp_sd_register_upnp_svc(i, svc_query_data, svcDiscInfo.uuid);
	i++;

	/* upnp:device-uuid */
	temp = svc_query_data;
	strcpy((char*)temp, P2P_UPNP_QUERY_UUID);
	strcat((char*)temp, (char*)svcDiscInfo.uuid);
	p2papp_sd_register_upnp_svc(i, svc_query_data, svcDiscInfo.uuid);
	i++;

	/* urn:schemas-upnp-org:service:serviceType:ver */
	temp2 = svcDiscInfo.svcTypes;
	while (strcmp((char*)temp2, ""))
		{
		temp = svc_query_data;
		strcpy((char*)temp, P2P_UPNP_QUERY_VERSION);
		strcat((char*)temp, (char*)temp2);
		p2papp_sd_register_upnp_svc(i, temp, svcDiscInfo.uuid);
		temp2 += strlen((char*)temp2) + 1;
		i++;
		}

	uPnPsvc_num = i;

	return 0;
}

void p2papp_sd_upnp_print_information(BCMP2P_UINT8* dst_str,
	BCMP2P_UINT32 dst_str_size, BCMP2P_UINT8* resp_data, BCMP2P_UINT32 resp_data_size)
{
	BCMP2P_UINT8* RetSubStr = NULL;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "%s Entry Resp data %s\n", __FUNCTION__, resp_data));

	if (dst_str_size < P2P_UPNP_MAX_DATA_CONCAT)
	{
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "%s:dst_str buffer 0x%x size %d is less than %d\n",
			__FUNCTION__, dst_str, dst_str_size, P2P_UPNP_MAX_DATA_CONCAT));
		return;
	}

	RetSubStr = (BCMP2P_UINT8*)strstr((char*)resp_data, P2P_UPNP_RESPONSE_VERSION);

	if (RetSubStr)
	{
		strncat((char*)dst_str, "UPNP:", 5);
		/* lets grab the UUID */
		RetSubStr += strlen(P2P_UPNP_RESPONSE_VERSION);
		strncat((char*)dst_str, (char*)RetSubStr, 36);
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"%s:print string after uuid %s\n", __FUNCTION__, dst_str));
	}
	else
	{
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"%s:svc response doesn't have valid RESPONSE version\n", __FUNCTION__));
		return;
	}

	/* Search for Media Renderer service */
	RetSubStr = (BCMP2P_UINT8*)strstr((char*)resp_data, "MediaRenderer:");

	if (RetSubStr)
	{
		/* We found a Media Renderer device */
		strncat((char*)dst_str, " DMR", 4);
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"%s:print string after dmr %s\n", __FUNCTION__, dst_str));
	}
	else
	{
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"%s:MediaRenderer: not found in the svc response\n", __FUNCTION__));
	}

	/* Search for Content directory service */
	RetSubStr = (BCMP2P_UINT8*)strstr((char*)resp_data, "ContentDirectory:");
	if (RetSubStr)
	{
		/* We found a Content directory service */
		strncat((char*)dst_str, " DMS", 4);
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"%s:print string after dms %s\n", __FUNCTION__, dst_str));
	}
	else
	{
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"%s:ContentDirectory: not found in the svc response\n", __FUNCTION__));
	}

	strncat((char*)dst_str, " ", 1);
	return;

}

BCMP2P_STATUS p2papp_sd_upnp_CreateListOfQueries(BCMP2P_UINT8** svcQueryEntries,
	BCMP2P_UINT32* svcQueryListSize)
{
#define NUM_QUERIES 2
	const BCMP2P_UINT8* query[NUM_QUERIES];
	BCMP2P_UINT32 query_size[NUM_QUERIES];
	BCMP2P_UINT32 total_query_size = 0;
	BCMP2P_SVC_LIST* svc_list;
	BCMP2P_SVC_ENTRY* svc_entry_beg;

	int i;
	query[0] = (BCMP2P_UINT8*)P2P_UPNP_QUERY_DMS;
	query[1] = (BCMP2P_UINT8*)P2P_UPNP_QUERY_DMR;
	/* query[2] = (BCMP2P_UINT8*)P2P_UPNP_QUERY_SSDP; */
	/* query[3] = (BCMP2P_UINT8*)P2P_UPNP_QUERY_ROOTDEV; */

	for (i = 0; i < NUM_QUERIES; i++)
	{
		query_size[i] =  strlen((char*)query[i]);
		total_query_size += query_size[i];
	}

	/* Create service discovery parameters to send to peer. */
	*svcQueryListSize = (sizeof(BCMP2P_SVC_LIST) - 1) +
		(NUM_QUERIES*(sizeof(BCMP2P_SVC_ENTRY) - 1)) + total_query_size;
	svc_list = (BCMP2P_SVC_LIST *) malloc(*svcQueryListSize);
	memset(svc_list, 0, *svcQueryListSize);
	if (svc_list == NULL)
	{
		*svcQueryListSize = 0;
		return BCMP2P_NOT_ENOUGH_SPACE;
	}

	svc_list->status = BCMP2P_SD_STATUS_SUCCESS;
	svc_list->svcNum = NUM_QUERIES;
	svc_list->dataSize = sizeof(BCMP2P_SVC_ENTRY) - 1 + total_query_size;

	svc_entry_beg = (BCMP2P_SVC_ENTRY *) svc_list->svcEntries;

	for (i = 0; i < NUM_QUERIES; i++)
	{
		svc_entry_beg->svcProtol = BCMP2P_SVC_PROTYPE_UPNP;
		svc_entry_beg->svc_id = 0;
		svc_entry_beg->status = BCMP2P_SD_STATUS_SUCCESS;
		svc_entry_beg->dataSize = query_size[i];
		memcpy(svc_entry_beg->svcData, query[i], query_size[i]);
		svc_entry_beg = (BCMP2P_SVC_ENTRY*)((BCMP2P_UINT32)svc_entry_beg +
			(sizeof(BCMP2P_SVC_ENTRY) - 1) + svc_entry_beg->dataSize);
	}

	*svcQueryEntries = (BCMP2P_UINT8*) svc_list;
	return BCMP2P_SUCCESS;
}


/* Release Service Data Store memory */
int p2papp_sd_unregister_upnp_allsvcs(void)
{
	int i;
	for (i = 0; i < uPnPsvc_num; i++)
		BCMP2PDeregService(p2papp_dev_hdl, upnpSvcHandle[i]);
	return 0;
}


static int p2papp_sd_register_upnp_svc(int idx,
	BCMP2P_UINT8* head_svc_query_data, BCMP2P_UINT8* uuid)
{
	BCMP2P_STATUS ret = BCMP2P_SUCCESS;
	BCMP2P_UINT8* svc_query_data = head_svc_query_data + strlen((char*)P2P_UPNP_QUERY_VERSION);
	BCMP2P_UINT8* concat_string = (BCMP2P_UINT8*)"::";
	int concat_string_len = strlen((char*)concat_string);
	BCMP2P_UINT8* prefix_string = (BCMP2P_UINT8*)P2P_UPNP_RESPONSE_VERSION;
	int prefix_string_len = strlen((char*)prefix_string);

	int svc_query_len = strlen((char*)svc_query_data);
	int head_svc_query_len = strlen((char*)head_svc_query_data);
	int uuid_len = strlen((char*)uuid);

	BCMP2P_UINT8 svc_resp_data[UPNP_MAX_RESPONSE_BUF_SIZE];
	uint32 svc_resp_len = 0;
	BCMP2P_UINT8* temp = svc_resp_data;
	uint32 svc_id = 0;

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "%s Entry head_svc_query_data %s svc_query_data %s \n",
		__FUNCTION__, head_svc_query_data, svc_query_data));

	ret = BCMP2PGetRegisteredService(p2papp_dev_hdl, BCMP2P_SVC_PROTYPE_UPNP,
	 head_svc_query_data, head_svc_query_len, svc_resp_data, &svc_resp_len, (uint32*)&svc_id);
	if (svc_resp_len > 0)
	{
		/* entry exists in SDS */
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "svc entry %s exists in SDS resp %s len %d\n",
			head_svc_query_data, svc_resp_data, svc_resp_len));
		temp = svc_resp_data + svc_resp_len;
	}
	else
	{
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"svc entry %s does not exist in SDS\n", head_svc_query_data));
		/* entry doesn't exist in SDS */
		strcpy((char*)temp, (char*)prefix_string);
		svc_resp_len += prefix_string_len;
	}
	if ((svc_resp_len + uuid_len + svc_query_len + concat_string_len)
		> UPNP_MAX_RESPONSE_BUF_SIZE)
	{
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"svc_resp_data buf exceeded existing svc_resp_len=%d\n", svc_resp_len));
		return -1;
	}

	strcat((char*)temp, (char*)uuid);
	if (strstr((char*)svc_query_data, "uuid:") == NULL)
	{
		strcat((char*)temp, (char*)concat_string);
		strcat((char*)temp, (char*)svc_query_data);
		svc_resp_len += concat_string_len + svc_query_len + uuid_len;
	}
	else
	{
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"skipping uuid: at the end of response for specific uuid query"));
		svc_resp_len += concat_string_len + uuid_len;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "Register for query %s len %d Response %s len %d\n",
		head_svc_query_data, head_svc_query_len, svc_resp_data, svc_resp_len));
	upnpSvcHandle[idx] = BCMP2PRegService(p2papp_dev_hdl, 0, BCMP2P_SVC_PROTYPE_UPNP,
		head_svc_query_data, head_svc_query_len, svc_resp_data, svc_resp_len);
	if (upnpSvcHandle[idx])
	{
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "	 SvcQuery %s reg success done\n",
			head_svc_query_data));
	}

	return ret;

}

#if !defined TARGETENV_android /* Test code for linux define a DMR here */
/* For linux version, lets define a DMR here itself since we don't have libdms.so for linux */
/* Once running P2P code on Settop box, we need to define this funciton in DLNA code */

int bcm_p2p_get_dmr_svctypes_uuid(BP2PSvcDiscInfo_t* pSvcDiscInfo)
{
	BCMP2P_UINT8* temp = pSvcDiscInfo->svcTypes;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "%s Entry\n", __FUNCTION__));
	strcpy((char*)pSvcDiscInfo->uuid, (char*)"12345678-90AB-CDEF-GHIJ-KLMNOPQRSTUV");
	strcpy((char*)temp, (char*)"urn:schemas-upnp-org:service:MediaRenderer:1");
	temp = (BCMP2P_UINT8*)((uint32)temp + strlen((char*)temp) + 1);
	strcpy((char*)temp, "");
	return 0;
}
#endif /* TARGETENV_android */

/* Sample code for registering UPNP Queries (all types) */


#endif /* P2P_UPNP_DISCOVERY */
