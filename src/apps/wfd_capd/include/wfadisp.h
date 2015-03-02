/*
 * Broadcom Common Wi-Fi Display IE state management API (internal)
 *
 * Logic that determines when and which frames WFA Display IEs are
 * applied.
 *
 * Draft Revision 2.1
 *	- Return an IE buffer that has already preallocated the IEs
 *
 * Draft Revision 2
 *	- Apply IEs to all WFA Display frames in one set instead of
 *	  selectively setting IEs based on DA and local MAC (bsscfg).
 *
 * Draft Revision 1.1
 *	- replaced WFADISPROLE with intf_addr
 *      - use cb for upd ie for finer controller
 *
 * Draft Revision 1
 *	- initial
 *
 * Copyright (C) 2012, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: $
 */
#ifndef __WFADISP_H__
#define __WFADISP_H__

/** Connection Statuses */
typedef enum WFADISPCONNECTSTATUS {
	WFADISP_OK,
	WFADISP_HOST_SESSION_UNAVAILABLE,
	WFADISP_PEER_SESSION_UNAVAILABLE,
	WFADISP_DEVICE_TYPE_MISMATCH,
} WFADISPCONNECTSTATUS, *PWFADISPCONNECTSTATUS;

/** IE BLOb info */
typedef struct WFADISPIEBLOBINFO {
	void *blob;
	unsigned blob_bytes;
} WFADISPIEBLOBINFO, *PWFADISPIEBLOBINFO;

/** IE buffer */
typedef struct WFADISPIEBUF {
	WFADISPIEBLOBINFO beacon;
	WFADISPIEBLOBINFO prbreq;
	WFADISPIEBLOBINFO prbrsp;
	WFADISPIEBLOBINFO assocreq;
	WFADISPIEBLOBINFO assocrsp;
	WFADISPIEBLOBINFO gonreq;
	WFADISPIEBLOBINFO gonrsp;
	WFADISPIEBLOBINFO gonconf;
	WFADISPIEBLOBINFO invreq;
	WFADISPIEBLOBINFO invrsp;
	WFADISPIEBLOBINFO pdreq;
	WFADISPIEBLOBINFO pdrsp;
	WFADISPIEBLOBINFO tdls_setupreq;
	WFADISPIEBLOBINFO tdls_setuprsp;
} WFADISPIEBUF, *PWFADISPIEBUF;

/* maximum Device Information Descriptor per IE */
#define WFADISP_MAX_DID 8

/**
 * Device Information Descriptor
 * Wi-Fi Display, section 5.1.11 
 */
typedef struct WFADISPDID{
	unsigned char peer_dev_addr[6];
	WFDCAPD_CAP_CONFIG device_info;
} WFADISPDID, *PWFADISPDID;

/** Peer Information with optional DID (GO only) */
typedef struct WFADISPINFO {
	WFDCAPD_CAP_CONFIG device_info;
	WFADISPDID did[WFADISP_MAX_DID];
	unsigned char did_count;
} WFADISPINFO, *PWFADISPINFO;

/** Device Information Descriptor List */
typedef struct WFADISPDIDLIST {
	struct WFADISPDIDLIST *next;
	WFADISPDID did;
	void *reserved;
} WFADISPDIDLIST, *PWFADISPDIDLIST;

/** opaque (caller declared) */
typedef struct WFADISPDEV {
	/** pools */
	WFADISPDIDLIST did_pool[WFADISP_MAX_DID*2], *free_did, *used_did;

	/** device parameters */
	WFDCAPD_CAP_CONFIG params;

} WFADISPDEV, *PWFADISPDEV;

/**
 * WFDCAPD_DEVICE_TYPE_SRC_PRIM_SINK is unsupported.
 * On success, caller should set IEs.
 */
WFDCAPD_STATUS
WFADispInitDevice(
	PWFADISPDEV,
	const WFDCAPD_CAP_CONFIG *
	);

/**
 * The caller is responsible for unsetting any IEs applied to
 * the underlying device.
 */
void
WFADispDeinitDevice(
	PWFADISPDEV
	);

WFDCAPD_STATUS
WFADispSessionAvailability(
	PWFADISPDEV,
	int is_available
	);

WFDCAPD_STATUS
WFADispSetRtspPort(
	PWFADISPDEV h,
	int port
	);

WFDCAPD_STATUS
WFADispSetPrefConnType(
	PWFADISPDEV h,
	WFDCAPD_CONNECTION_TYPE connection_type
	);

WFDCAPD_STATUS
WFADispSetAltMac(
	PWFADISPDEV h,
	WFDCAPD_ETHER_ADDR *alt_mac
	);

WFDCAPD_STATUS
WFADispSetDevType(
	PWFADISPDEV h,
	WFDCAPD_DEVICE_TYPE dev_type
	);


/**
 * This must be called prior to making a connection so that
 * the source/sink may be matched as well as availability (ours and
 * the peer).  There is no additional checking of frames beyond
 * this (a la 4.5.2.1), because (1) dual source/sink is unsupported by the
 * API and (2) we assume that the peer's device type will remain immutable.
 * There is still an opportunity for the availability to change
 * though, but we'll live with that for now.
 */
WFDCAPD_STATUS
WFADispOkToConnectWithPeer(
	PWFADISPDEV,
	const unsigned char *peer_ie_blob,
	unsigned peer_ie_blob_bytes,
	PWFADISPCONNECTSTATUS
	);

/**
 * WFA Display, section 5.1.11
 * On success, caller should set IEs.
 */
WFDCAPD_STATUS
WFADispGroupOwnerRegisterPeer(
	PWFADISPDEV h,
	const unsigned char *peer_intf_addr,
	const unsigned char *ie_blob,
	unsigned ie_blob_bytes
	);

/** On success, caller should set IEs. */
WFDCAPD_STATUS
WFADispGroupOwnerUnregisterPeer(
	PWFADISPDEV h,
	const unsigned char *peer_intf_addr
	);
#define WFADispGroupOwnerUnregisterAllPeers(h) WFADispGroupOwnerUnregisterPeer(h, NULL)

/**
 * The caller should unset all IEs and set new IEs atomically to
 * avoid race conditions.
 */
WFDCAPD_STATUS
WFADispGetIes(
	PWFADISPDEV h,
	PWFADISPIEBUF info
	);

WFDCAPD_STATUS
WFADispFreeIeBuf(
	PWFADISPIEBUF iebuf
	);

#endif /* __WFADISP_H__ */
