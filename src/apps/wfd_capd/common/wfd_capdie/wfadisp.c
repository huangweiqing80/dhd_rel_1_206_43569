#include <wfd_capd.h>
#include <wfd_capdie.h>
#include <wfadisp.h>

#include <HostDecls.h>

#define IS_DEVICE_MISMATCHED(d1,d2) \
(	!(WFDCAPD_DEVICE_TYPE_SRC == (d1) && (WFDCAPD_DEVICE_TYPE_PRIM_SINK == (d2) || WFDCAPD_DEVICE_TYPE_SEC_SINK == (d2))) && \
	!(WFDCAPD_DEVICE_TYPE_SRC == (d2) && (WFDCAPD_DEVICE_TYPE_PRIM_SINK == (d1) || WFDCAPD_DEVICE_TYPE_SEC_SINK == (d1))) \
)

#define IS_MAC_ADDR_EQUAL(m1,m2) \
(	(m1)[0]==(m2)[0] && (m1)[1]==(m2)[1] && (m1)[2]==(m2)[2] && \
	(m1)[3]==(m2)[3] && (m1)[4]==(m2)[4] && (m1)[5]==(m2)[5] \
)

#if !defined(ARRAYSIZE)
#define ARRAYSIZE(a) (sizeof(a)/sizeof(a[0]))
#endif /* !ARRAYSIZE */

static void
FreeDidEntry(
	PWFADISPDIDLIST *used_head,
	PWFADISPDIDLIST *free_head
	)
{
	PWFADISPDIDLIST did_entry;

	ASSERT(NULL != used_head);
	ASSERT(NULL != free_head);

	/* reclaim */
	did_entry = *used_head;
	*used_head = (*used_head)->next;
	did_entry->next = *free_head;
	*free_head = did_entry;
	FREE(did_entry->reserved);
}

static void
FreeAllDidEntries(
	PWFADISPDEV h
	)
{
	ASSERT(NULL != h);

	while (NULL != h->used_did)
		FreeDidEntry(&h->used_did, &h->free_did);
}

static PWFADISPDIDLIST *
LocateDid(
	PWFADISPDEV h,
	const unsigned char *peer_intf_addr
	)
{
	PWFADISPDIDLIST *head = &h->used_did;

	ASSERT(NULL != h);
	ASSERT(NULL != peer_intf_addr);

	while (*head != NULL) {
		if (IS_MAC_ADDR_EQUAL((*head)->did.peer_dev_addr, peer_intf_addr))
			return head;
		head = &(*head)->next;
	}
	return NULL;
}

static WFDCAPD_STATUS
AllocAndGetIe(
	const WFDCAPD_CAP_CONFIG *cfg,
	const wfd_capdie_dev_ie_t *dev_ie,
	WFDCAPD_UINT8 dev_ie_count,
	WFD_CAPD_IE_FLAG flag,
	void **out_blob,
	unsigned *out_blob_bytes
	)
{
	WFDCAPD_STATUS status;
	WFDCAPD_UINT8 *blob;
	WFDCAPD_UINT16 blob_bytes;

	ASSERT(NULL != cfg);
	ASSERT(NULL != dev_ie);
	ASSERT(NULL != out_blob);
	ASSERT(NULL != out_blob_bytes);

	blob = NULL;

	do {
		/* get size */
		status =
		wfd_capdie_create_custom_ie(
			cfg, dev_ie, dev_ie_count, flag, NULL, &blob_bytes);
		if (WFDCAPD_SUCCESS != status)
			break;

		/* alloc */
		blob = (WFDCAPD_UINT8 *)MALLOC(blob_bytes);
		if (NULL == blob) {
			status = WFDCAPD_MEMORY_ALLOC_FAIL;
			break;
		}

		/* init */
		status =
		wfd_capdie_create_custom_ie(
			cfg, dev_ie, dev_ie_count, flag, blob, &blob_bytes);
		if (WFDCAPD_SUCCESS != status) 
			break;

		/* copy-out */
		*out_blob = blob;
		*out_blob_bytes = blob_bytes;
		blob = NULL;

	} while(0);

	FREE(blob);

	return status;
}

WFDCAPD_STATUS
WFADispInitDevice(
	PWFADISPDEV h,
	const WFDCAPD_CAP_CONFIG *cfg
	)
{
	unsigned i;
	PWFADISPDIDLIST last;

	/* check args and values */
	if (NULL == h || NULL == cfg)
		return WFDCAPD_INVALID_PARAMS;
	if (WFDCAPD_DEVICE_TYPE_SRC_PRIM_SINK == cfg->dev_type)
		return WFDCAPD_INVALID_PARAMS;

	/* initialize context */
	MEMZERO(h, sizeof *h);
	for (last=NULL, i=ARRAYSIZE(h->did_pool); i!=0; ) {
		h->did_pool[--i].next = last;
		last = &h->did_pool[i];
	}
	h->free_did = last;
	h->params = *cfg;

	return WFDCAPD_SUCCESS;
}

void
WFADispDeinitDevice(
	PWFADISPDEV h
	)
{
	ASSERT(NULL != h);

	/* check args */
	if (NULL == h)
		return;

	/* free used did list */
	FreeAllDidEntries(h);
}

WFDCAPD_STATUS
WFADispSessionAvailability(
	PWFADISPDEV h,
	int is_available
	)
{
	/* check args */
	if (NULL == h)
		return WFDCAPD_INVALID_PARAMS;

	/* set host availability */
	h->params.sess_avl = is_available ? WFDCAPD_TRUE : WFDCAPD_FALSE;

	return WFDCAPD_SUCCESS;
}

WFDCAPD_STATUS
WFADispSetRtspPort(
	PWFADISPDEV h,
	int port
	)
{
	/* check args */
	if (NULL == h)
		return WFDCAPD_INVALID_PARAMS;

	/* set host rtsp port number */
	h->params.rtsp_tcp_port = port;

	return WFDCAPD_SUCCESS;
}

WFDCAPD_STATUS
WFADispSetPrefConnType(
	PWFADISPDEV h,
	WFDCAPD_CONNECTION_TYPE connection_type
	)
{
	/* check args */
	if (NULL == h)
		return WFDCAPD_INVALID_PARAMS;

	/* set host rtsp port number */
	h->params.preferred_connection = connection_type;

	return WFDCAPD_SUCCESS;
}

WFDCAPD_STATUS
WFADispSetAltMac(
	PWFADISPDEV h,
	WFDCAPD_ETHER_ADDR *alt_mac
	)
{
	/* check args */
	if (NULL == h)
		return WFDCAPD_INVALID_PARAMS;
	
	if (alt_mac == NULL)
		return WFDCAPD_INVALID_PARAMS;

	/* set alternative mac */
	memcpy(&h->params.alt_mac, alt_mac, sizeof(WFDCAPD_ETHER_ADDR));

	return WFDCAPD_SUCCESS;
}

WFDCAPD_STATUS
WFADispSetDevType(
	PWFADISPDEV h,
	WFDCAPD_DEVICE_TYPE dev_type
	)
{
	/* check args */
	if (NULL == h)
		return WFDCAPD_INVALID_PARAMS;
	
	/* set device type */
	h->params.dev_type = dev_type;

	return WFDCAPD_SUCCESS;
}

WFDCAPD_STATUS
WFADispOkToConnectWithPeer(
	PWFADISPDEV h,
	const unsigned char *peer_ie_blob,
	unsigned peer_ie_blob_bytes,
	PWFADISPCONNECTSTATUS cxstatusout
	)
{
	WFDCAPD_STATUS status;
	WFADISPCONNECTSTATUS cxstatus = WFADISP_OK;
	WFDCAPD_CAP_CONFIG cfg;

	/* check args */
	if (NULL == h || NULL == peer_ie_blob || 0 == peer_ie_blob_bytes ||
	    NULL == cxstatusout)
	{
		return WFDCAPD_INVALID_PARAMS;
	}

	do {
		/* check host session */
		ASSERT(WFDCAPD_TRUE == h->params.sess_avl);
		if (WFDCAPD_FALSE == h->params.sess_avl) {
			cxstatus = WFADISP_HOST_SESSION_UNAVAILABLE;
			break;
		}

		/* decode peer IEs */
		status = wfd_capdie_get_dev_cfg(peer_ie_blob, peer_ie_blob_bytes, &cfg);
		if (WFDCAPD_SUCCESS != status)
			break;

		/* check peer session */
		if (WFDCAPD_FALSE == cfg.sess_avl) {
			cxstatus = WFADISP_PEER_SESSION_UNAVAILABLE;
			break;
		}
		/* check that devices match */
		if (WFDCAPD_DEVICE_TYPE_SRC_PRIM_SINK == cfg.dev_type) {
			cxstatus = WFADISP_DEVICE_TYPE_MISMATCH;
			break;
		}
		if (IS_DEVICE_MISMATCHED(h->params.dev_type, cfg.dev_type)) {
			cxstatus = WFADISP_DEVICE_TYPE_MISMATCH;
			break;
		}

	} while(0);

	/* copy-out */
	if (NULL != cxstatusout)
		*cxstatusout = cxstatus;

	return status;
}

WFDCAPD_STATUS
WFADispGroupOwnerRegisterPeer(
	PWFADISPDEV h,
	const unsigned char *peer_intf_addr,
	const unsigned char *ie_blob,
	unsigned ie_blob_bytes
	)
{
	WFDCAPD_STATUS status;
	PWFADISPDIDLIST did_entry;
	WFDCAPD_CAP_CONFIG cfg;
	PWFADISPIEBLOBINFO blobinfo;

	/* check args */
	if (NULL == h || NULL == ie_blob || 0 == ie_blob_bytes || NULL == peer_intf_addr)
		return WFDCAPD_INVALID_PARAMS;
	if (NULL != LocateDid(h, peer_intf_addr))
		return WFDCAPD_INVALID_PARAMS;

	/* decode peer IE */
	status = wfd_capdie_get_dev_cfg(ie_blob, ie_blob_bytes, &cfg);
	if (WFDCAPD_SUCCESS != status)
		return status;

	/* check for free did */
	if (NULL == h->free_did)
		return WFDCAPD_NOT_ENOUGH_SPACE;

	/* cache IE blob */
	blobinfo = (PWFADISPIEBLOBINFO)MALLOC(sizeof(*blobinfo)+ie_blob_bytes);
	if (NULL == blobinfo)
		return WFDCAPD_MEMORY_ALLOC_FAIL;
	blobinfo->blob = blobinfo+1;
	blobinfo->blob_bytes = ie_blob_bytes;
	MEMCPY(blobinfo->blob, ie_blob, ie_blob_bytes);

	/* get free did */
	did_entry = h->free_did;
	h->free_did = h->free_did->next;

	/* initialize did */
	MEMCPY(did_entry->did.peer_dev_addr, peer_intf_addr, 6);
	MEMCPY(&did_entry->did.device_info, &cfg, sizeof cfg);
	did_entry->reserved = blobinfo;

	/* claim did as used */
	did_entry->next = h->used_did;
	h->used_did = did_entry;

	return WFDCAPD_SUCCESS;
}

WFDCAPD_STATUS
WFADispGroupOwnerUnregisterPeer(
	PWFADISPDEV h,
	const unsigned char *peer_intf_addr
	)
{
	PWFADISPDIDLIST *used_did;

	/* check args */
	if (NULL == h)
		return WFDCAPD_INVALID_PARAMS;

	/* free all */
	if (NULL == peer_intf_addr) {
		FreeAllDidEntries(h);
	}

	/* free specified */
	else {
		/* locate used did */
		used_did = LocateDid(h, peer_intf_addr);
		if (NULL == used_did)
			return WFDCAPD_INVALID_PARAMS;

		/* reclaim */
		FreeDidEntry(used_did, &h->free_did);
	}

	return WFDCAPD_SUCCESS;
}

WFDCAPD_STATUS
WFADispGetIes(
	PWFADISPDEV h,
	PWFADISPIEBUF info
	)
{
#define SET_IEBLOBINFO(FLAG, FIELD) \
do { \
	status = \
	AllocAndGetIe(&h->params, dev_ie, dev_ie_count, (FLAG), \
		&info->FIELD.blob, &info->FIELD.blob_bytes \
	); \
	if (WFDCAPD_SUCCESS != status) \
		goto DONE; \
} while(0)

	WFDCAPD_STATUS status;
	wfd_capdie_dev_ie_t dev_ie[ARRAYSIZE(h->did_pool)];
	unsigned dev_ie_count;
	PWFADISPDIDLIST did_list;

	/* check args */
	if (NULL == h || NULL == info)
		return WFDCAPD_INVALID_PARAMS;

	/* fill in the session info array */
	for (dev_ie_count=0, did_list=h->used_did; did_list != NULL; did_list = did_list->next) {
		wfd_capdie_dev_ie_t *dev_ie_elt = &dev_ie[dev_ie_count++];
		PWFADISPIEBLOBINFO ieblobinfo = (PWFADISPIEBLOBINFO)did_list->reserved;
		MEMCPY(dev_ie_elt->peer_addr, did_list->did.peer_dev_addr, 6);
		dev_ie_elt->ie_data = (WFDCAPD_UINT8 *)ieblobinfo->blob;
		dev_ie_elt->ie_data_len = ieblobinfo->blob_bytes;
	}

	/* populate IE buffer */
	MEMZERO(info, sizeof *info);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_BEACON, beacon);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_PRBREQ, prbreq);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_PRBRSP, prbrsp);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_ASSOCREQ, assocreq);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_ASSOCRSP, assocrsp);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_GONREQ, gonreq);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_GONRSP, gonrsp);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_GONCONF, gonconf);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_INVREQ, invreq);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_INVRSP, invrsp);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_PDREQ, pdreq);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_PDRSP, pdrsp);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_TDLS_SETUPREQ, tdls_setupreq);
	SET_IEBLOBINFO(WFD_CAPD_IE_FLAG_TDLS_SETUPRSP, tdls_setuprsp);

DONE:
	if (WFDCAPD_SUCCESS != status)
		WFADispFreeIeBuf(info);

	return status;
#undef SET_IEBLOBINFO
}

WFDCAPD_STATUS
WFADispFreeIeBuf(
	PWFADISPIEBUF iebuf
	)
{
#define CLR_IEBLOBINFO(ELT) \
	do { FREE(iebuf->ELT.blob); } while(0)

	/* check args */
	if (NULL == iebuf)
		return WFDCAPD_INVALID_PARAMS;

	/* free fields */
	CLR_IEBLOBINFO(beacon);
	CLR_IEBLOBINFO(prbreq);
	CLR_IEBLOBINFO(prbrsp);
	CLR_IEBLOBINFO(assocreq);
	CLR_IEBLOBINFO(assocrsp);
	CLR_IEBLOBINFO(gonreq);
	CLR_IEBLOBINFO(gonrsp);
	CLR_IEBLOBINFO(gonconf);
	CLR_IEBLOBINFO(invreq);
	CLR_IEBLOBINFO(invrsp);
	CLR_IEBLOBINFO(pdreq);
	CLR_IEBLOBINFO(pdrsp);
	CLR_IEBLOBINFO(tdls_setupreq);
	CLR_IEBLOBINFO(tdls_setuprsp);

	MEMZERO(iebuf, sizeof *iebuf);

	return WFDCAPD_SUCCESS;
#undef CLR_IEBLOBINFO
}
