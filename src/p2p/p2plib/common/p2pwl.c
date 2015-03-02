/*
 * P2P Library OS-independent WL driver access APIs.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2pwl.c,v 1.132 2011-01-25 02:46:24 $
 */
#include <stdio.h>
#include <stdlib.h>

/* P2P Library include files */
#include <p2plib_int.h>
#include <p2plib_osl.h>
#include <p2pwl.h>

/* WL driver include files */
#include <wlioctl.h>
#include <bcmutils.h>
#include <802.11.h>


/* Convert an Ethernet address to a string of the form "7c:2f:33:4a:00:21" */
char *
p2pwl_ether_etoa(const struct ether_addr *n, char *etoa_buf)
{
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
 * Format an iovar buffer.
 * iovar name is converted to lower case
 */
static uint
p2pwl_iovar_mkbuf(const char *name, char *data, uint datalen,
	char *iovar_buf, uint buflen, int *perr)
{
	uint iovar_len;

	iovar_len = (uint32) strlen(name) + 1;

	/* check for overflow */
	P2PLIB_ASSERT((iovar_len + datalen) <= buflen);
	if ((iovar_len + datalen) > buflen) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_iovar_mkbuf: buf too short, %u < %u\n",
			buflen, (iovar_len + datalen)));
		*perr = BCME_BUFTOOSHORT;
		return 0;
	}

	/* copy data to the buffer past the end of the iovar name string */
	if (datalen > 0) {
		memmove(&iovar_buf[iovar_len], data, datalen);
	}

	/* copy the name to the beginning of the buffer */
	strcpy(iovar_buf, name);

/*
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwl_iovar_mkbuf: data=%p len=%u, iovar_buf=%p len=%u\n",
		data, datalen, iovar_buf, iovar_len));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		" %02x %02x %02x %02x %02x %02x %02x %02x\n",
		iovar_buf[0], iovar_buf[1], iovar_buf[2], iovar_buf[3],
		iovar_buf[4], iovar_buf[5], iovar_buf[6], iovar_buf[7]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		" %02x %02x %02x %02x %02x %02x %02x %02x\n",
		iovar_buf[8], iovar_buf[9], iovar_buf[10], iovar_buf[11],
		iovar_buf[12], iovar_buf[13], iovar_buf[14], iovar_buf[15]));
*/

	*perr = 0;
	return (iovar_len + datalen);
}


/*
 * Get named iovar on a specfied bss, providing both parameter and i/o buffers.
 * The iovar name is converted to lower case
 */
int
p2pwl_iovar_getbuf_bss(P2PWL_HDL wl, const char *iovar, void *param,
	int paramlen, void *bufptr, int buflen, int bssidx)
{
	int err;

	P2PAPI_WL_CHECK_HDL(wl);
	p2pwl_iovar_mkbuf(iovar, (char *) param, paramlen, (char *) bufptr, buflen,
		&err);
	if (err) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwl_iovar_getbuf: mkbuf err %d\n", err));
		return err;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwl_iovar_getbuf_bss: iovar=%s, bssidx=%d\n",
		iovar, bssidx));

	return p2posl_wl_ioctl_bss(wl, WLC_GET_VAR, bufptr, buflen, FALSE, bssidx);
}

/*
 * Get specified ioctl.
 */
int
p2pwl_ioctl_get_bss(P2PWL_HDL wl, int cmd, void *buf, int len, int bssidx)
{
	P2PAPI_WL_CHECK_HDL(wl);
	return p2posl_wl_ioctl_bss(wl, cmd, buf, len, FALSE, bssidx);
}


/*
 * Get a parameterless iovar into a given buffer.
 * iovar name is converted to lower case
 */
int
p2pwl_iovar_get_bss(P2PWL_HDL wl, const char *iovar, void *outbuf, int len,
	int bssidx)
{
	char smbuf[WLC_IOCTL_SMLEN];
	int err;

	P2PAPI_WL_CHECK_HDL(wl);

	/* use the return buffer if it is bigger than what we have on the stack */
	if (len > (int)sizeof(smbuf)) {
		err = p2pwl_iovar_getbuf_bss(wl, iovar, NULL, 0, outbuf, len, bssidx);
	} else {
		memset(smbuf, 0, sizeof(smbuf));
		err = p2pwl_iovar_getbuf_bss(wl, iovar, NULL, 0, smbuf, sizeof(smbuf),
			bssidx);
		if (err == 0)
			memcpy(outbuf, smbuf, len);
	}

	return err;
}


/*
 * Get the named integer iovar on the specified BSS.
 * iovar name is converted to lower case
 */
int
p2pwl_iovar_getint_bss(P2PWL_HDL wl, const char *iovar, int *pval, int bssidx)
{
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	ret = p2pwl_iovar_get_bss(wl, iovar, pval, sizeof(int), bssidx);
	if (ret >= 0)
	{
		*pval = dtoh32(*pval);
	}
	return ret;
}



/*
 * Set a named iovar on a specified BSS, providing both parameter and i/o
 * buffers.  The iovar name is converted to lower case.
 */
int
p2pwl_iovar_setbuf_bss(P2PWL_HDL wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen, int bssidx)
{
	int err;
	int iolen;

	P2PAPI_WL_CHECK_HDL(wl);
	iolen = p2pwl_iovar_mkbuf(iovar, (char *) param, paramlen, (char *)bufptr,
		buflen, &err);
	if (err) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwl_iovar_setbuf_bss: mkbuf err %d\n", err));
		return err;
	}

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"p2pwl_iovar_setbuf_bss: iovar=%s, bssidx=%d\n", iovar, bssidx));

	return p2posl_wl_ioctl_bss(wl, WLC_SET_VAR, bufptr, iolen, TRUE, bssidx);
}


/*
 * Set specified ioctl.
 */
int
p2pwl_ioctl_set_bss(P2PWL_HDL wl, int cmd, void *buf, int len, int bssidx)
{
	P2PAPI_WL_CHECK_HDL(wl);
	return p2posl_wl_ioctl_bss(wl, cmd, buf, len, TRUE, bssidx);
}


/*
 * Set a named iovar given the parameter buffer, on a specified BSS.
 * The iovar name is converted to lower case.
 */
int
p2pwl_iovar_set_bss(P2PWL_HDL wl, const char *iovar, void *param, int paramlen,
	int bssidx)
{
	char smbuf[WLC_IOCTL_SMLEN];
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	memset(smbuf, 0, sizeof(smbuf));

	ret = p2pwl_iovar_setbuf_bss(wl, iovar, param, paramlen, smbuf,
		sizeof(smbuf), bssidx);
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"P2PAPI: set bss %d iovar %s failed (%d)\n",
			bssidx, iovar, ret));
	}
	return ret;
}


/*
 * Set named iovar given an integer parameter, on the specified BSS.
 * iovar name is converted to lower case
 */
int
p2pwl_iovar_setint_bss(P2PWL_HDL wl, const char *iovar, int val, int bssidx)
{
	P2PAPI_WL_CHECK_HDL(wl);
	val = htod32(val);
	return p2pwl_iovar_set_bss(wl, iovar, &val, sizeof(int), bssidx);
}

/*
 * Format a bsscfg indexed iovar buffer.
 * This is a common implementation called by most OSL implementations of
 * p2posl_bssiovar_mkbuf().  DO NOT call this function directly from the
 * common code -- call p2posl_bssiovar_mkbuf() instead to allow the OSL to
 * override the common implementation if necessary.
 */
int
p2pwl_common_bssiovar_mkbuf(const char *iovar, int bssidx, void *param,
	int paramlen, void *bufptr, int buflen, int *perr)
{
	const char *prefix = "bsscfg:";
	int8* p;
	uint prefixlen;
	uint namelen;
	uint iolen;

	if (bssidx == 0) {
		return p2pwl_iovar_mkbuf(iovar, (char *) param, paramlen,
			(char *) bufptr, buflen, perr);
	}

	prefixlen = (uint32) strlen(prefix);	/* length of bsscfg prefix */
	namelen = (uint32) strlen(iovar) + 1;	/* length of iovar name + null */
	iolen = prefixlen + namelen + sizeof(int32) + paramlen;

	/* check for overflow */
	P2PLIB_ASSERT(iolen <= buflen);
	if (buflen < 0 || iolen > (uint)buflen) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_common_bssiovar_mkbuf: buf too short, %u < %u\n",
			buflen, iolen));
		*perr = BCME_BUFTOOSHORT;
		return 0;
	}

	p = (int8*)bufptr;

	/* copy prefix, no null */
	memcpy(p, prefix, prefixlen);
	p += prefixlen;

	/* copy iovar name including null */
	memcpy(p, iovar, namelen);
	p += namelen;

	/* bss config index as first param */
	bssidx = htod32(bssidx);
	memcpy(p, &bssidx, sizeof(int32));
	p += sizeof(int32);

	/* parameter buffer follows */
	if (paramlen)
		memcpy(p, param, paramlen);

	*perr = 0;
	return iolen;
}

/*
 * Get a named & bss indexed driver iovar using the primary ioctl interface.
 */
int
p2pwl_bssiovar_getbuf(P2PWL_HDL wl, const char *iovar, int bssidx,
	void *param, int paramlen, void *bufptr, int buflen)
{
	int err;

	P2PAPI_WL_CHECK_HDL(wl);

	p2posl_bssiovar_mkbuf(iovar, bssidx, param, paramlen, bufptr, buflen, &err);
	if (err)
		return err;

	return p2posl_wl_ioctl_bss(wl, WLC_GET_VAR, bufptr, buflen, FALSE, 0);
}

/*
 * Get named & bss indexed driver variable to buffer value
 * using the primary ioctl interface.
 */
int
p2pwl_bssiovar_get(P2PWL_HDL wl, const char *iovar, int bssidx, void *outbuf,
	int len)
{
	char smbuf[WLC_IOCTL_SMLEN];
	int err;

	P2PAPI_WL_CHECK_HDL(wl);

	/* use the return buffer if it is bigger than what we have on the stack */
	if (len > (int)sizeof(smbuf)) {
		err = p2pwl_bssiovar_getbuf(wl, iovar, bssidx, NULL, 0, outbuf, len);
	} else {
		memset(smbuf, 0, sizeof(smbuf));
		err = p2pwl_bssiovar_getbuf(wl, iovar, bssidx, NULL, 0, smbuf,
			sizeof(smbuf));
		if (err == 0)
			memcpy(outbuf, smbuf, len);
	}

	return err;
}

/*
 * Set a bss-indexed iovar on the primary ioctl interface, providing both
 * parameter and i/o buffers.
 */
int
p2pwl_bssiovar_setbuf(P2PWL_HDL wl, const char *iovar, int bssidx,
	void *param, int paramlen, void *bufptr, int buflen)
{
	int err;
	int iolen;

	P2PAPI_WL_CHECK_HDL(wl);

	iolen = p2posl_bssiovar_mkbuf(iovar, bssidx, param, paramlen, bufptr,
		buflen, &err);
	if (err)
		return err;

	return p2posl_wl_ioctl_bss(wl, WLC_SET_VAR, bufptr, iolen, TRUE, 0);
}

/*
 * Set named & bss indexed driver variable to buffer value
 * on the primary ioctl interface.
 */
int
p2pwl_bssiovar_set(P2PWL_HDL wl, const char *iovar, int bssidx,
	void *param, int paramlen)
{
	char smbuf[WLC_IOCTL_MEDLEN];

	P2PAPI_WL_CHECK_HDL(wl);
	memset(smbuf, 0, sizeof(smbuf));

	return p2pwl_bssiovar_setbuf(wl, iovar, bssidx, param, paramlen, smbuf,
		sizeof(smbuf));
}

/*
 * Set named & bsscfg indexed driver variable to int value
 * on the primary ioctl interface.
 */
int
p2pwl_bssiovar_setint(P2PWL_HDL wl, const char *iovar, int bssidx,
	int val)
{
	P2PLOG3("---wl %s -C %d %d\n", iovar, bssidx, val);
	P2PAPI_WL_CHECK_HDL(wl);
	val = htod32(val);

	return p2pwl_bssiovar_set(wl, iovar, bssidx, &val, sizeof(int));
}


/* Validate the wireless interface */
int
p2pwl_check_wl_if(P2PWL_HDL wl)
{
	int ret;
	int val;

	if (!P2PAPI_WL_CHECK_HDL(wl)) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2pwl_check_wl_if: bad wl hdl\n"));
		return -1;
	}

	val = -333;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl WLC_GET_MAGIC\n"));
	ret = p2posl_wl_ioctl_bss(wl, WLC_GET_MAGIC, &val, sizeof(int), FALSE, 0);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"WLC_GET_MAGIC ioctl failed with %d\n", ret));
		return ret;
	}
	if (val != WLC_IOCTL_MAGIC) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"P2P WL magic ioctl failed, val=0x%x(%d) instead of 0x%x\n",
			val, val, WLC_IOCTL_MAGIC));
		return -1;
	}

	val = -333;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl WLC_GET_VERSION\n"));
	ret = p2posl_wl_ioctl_bss(wl, WLC_GET_VERSION, &val, sizeof(int), FALSE, 0);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"WLC_GET_VERSION ioctl failed with %d\n", ret));
		return ret;
	}
	val = dtoh32(val);
	if (val > WLC_IOCTL_VERSION) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"P2P WL driver version mismatch %d > %d\n",
			val, WLC_IOCTL_VERSION));
		return -1;
	}
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_IOTYPECOMPAT)
	g_legacy_chanspec = (val == WLC_IOCTL_VERSION_LEGACY_IOTYPES);
#endif
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl drv Legacy IoTypes \n"));

	return 0;
}


/* Format a vndr_ie iovar buffer.
 * Returns the number of bytes written to the buffer.
 * Parameters:
 *   iebuf - ptr to iovar buffer which may be an unaligned address.
 *   add_del_cmd - "add" or "del" (null terminated).
 */
static int
set_vndr_ie_buf(uint8 *iebuf, const char* add_del_cmd,
	uint32 pktflag, uint8 oui0, uint8 oui1, uint8 oui2, uint8 ie_id,
	const uint8 *data, int datalen)
{
	vndr_ie_setbuf_t hdr;	/* aligned temporary vndr_ie buffer header */
	int iecount;
	uint32 data_offset;

	/* Copy the vndr_ie SET command ("add"/"del") to the buffer */
	strncpy(hdr.cmd, add_del_cmd, VNDR_IE_CMD_LEN - 1);
	hdr.cmd[VNDR_IE_CMD_LEN - 1] = '\0';

	/* Set the IE count - the buffer contains only 1 IE */
	iecount = htod32(1);
	memcpy((void *)&hdr.vndr_ie_buffer.iecount, &iecount, sizeof(int));

	/* Copy packet flags that indicate which packets will contain this IE */
	pktflag = htod32(pktflag);
	memcpy((void *)&hdr.vndr_ie_buffer.vndr_ie_list[0].pktflag, &pktflag,
		sizeof(uint32));

	/* Add the IE ID to the buffer */
	hdr.vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.id = ie_id;

	/* Add the IE length to the buffer */
	hdr.vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.len =
		(uint8) VNDR_IE_MIN_LEN + datalen;

	/* Add the IE OUI to the buffer */
	hdr.vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui[0] = oui0;
	hdr.vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui[1] = oui1;
	hdr.vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui[2] = oui2;

	/* Copy the aligned temporary vndr_ie buffer header to the IE buffer */
	memcpy(iebuf, &hdr, sizeof(hdr) - 1);

	/* Copy the IE data to the IE buffer */
	data_offset =
		(uint8*)&hdr.vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.data[0] -
		(uint8*)&hdr;
	memcpy(iebuf + data_offset, data, datalen);

	return data_offset + datalen;
}

/* Replace an existing vendor-specific IE: atomically delete the old IE and
 * then add a new one.
 *
 * Either old_data or new_data can be NULL.
 * If old_data is NULL and new_data is not, this adds an IE without deleting.
 * If new_data is NULL and old_data is not, this deletes an IE without adding.
 * If bothh old_data and new_data are NULL, this fn does nothing.
 */
int
p2pwl_vndr_ie(P2PWL_HDL wl, int bsscfg_idx, uint32 pktflag,
	uint8 oui0, uint8 oui1, uint8 oui2, uint8 ie_id,
	const uint8 *old_data, int old_datalen,
	const uint8 *new_data, int new_datalen)
{
	uint8 *iebuf;
	int iebuf_len;
	uint8 *curr_iebuf;
	int del_iebuf_len = 0;
	int add_iebuf_len = 0;
	int buflen;
	int old_ielen = VNDR_IE_MIN_LEN + old_datalen;
	int new_ielen = VNDR_IE_MIN_LEN + new_datalen;
	int err = -1;

	P2PAPI_WL_CHECK_HDL(wl);

	/* Validate the pktflag parameter */
	if ((pktflag & ~(VNDR_IE_BEACON_FLAG |
		VNDR_IE_PRBRSP_FLAG |
		VNDR_IE_ASSOCRSP_FLAG |
		VNDR_IE_AUTHRSP_FLAG |
		VNDR_IE_PRBREQ_FLAG |
		VNDR_IE_ASSOCREQ_FLAG))) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_vndr_ie: Invalid packet flag 0x%x (%d)\n",
			pktflag, pktflag));
		return -1;
	}

	/* Validate the data lengths */
	if (old_ielen > VNDR_IE_MAX_LEN) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_vndr_ie: old IE length %d exceeds %d!\n",
			old_ielen, VNDR_IE_MAX_LEN));
		return -1;
	}
	if (new_ielen > VNDR_IE_MAX_LEN) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_vndr_ie: new IE length %d exceeds %d!\n",
			new_ielen, VNDR_IE_MAX_LEN));
		return -1;
	}

	/* Validate the data pointers and data lengths */
	if (old_data == NULL && new_data == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwl_vndr_ie: no IE data to delete nor add\n"));
		return 0;
	}
	if ((old_data == NULL && old_datalen != 0) ||
		(old_data != NULL && old_datalen == 0)) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_vndr_ie: del IE data/len mismatch, len=%d\n", old_datalen));
		return -1;
	}
	if ((new_data == NULL && new_datalen != 0) ||
		(new_data != NULL && new_datalen == 0)) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_vndr_ie: add IE data/len mismatch, len=%d\n", new_datalen));
		return -1;
	}

	/* Allocate memory for the iovar buffer.  The iovar buffer consists of a
	 * vndr_ie "del" buffer followed by a vndr_ie "add" buffer.
	 */
	buflen = sizeof(vndr_ie_setbuf_t) + old_datalen - 1
		+ sizeof(vndr_ie_setbuf_t) + new_datalen - 1;
	iebuf = (uint8*) P2PAPI_MALLOC(buflen);
	if (!iebuf) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_vndr_ie: iebuf alloc failure (%d bytes)\n", buflen));
		return -1;
	}
	curr_iebuf = iebuf;
	iebuf_len = 0;

	/* If the old IE data is not NULL, create a vndr_ie "del" iovar buffer */
	if (old_data != NULL) {
		del_iebuf_len = set_vndr_ie_buf(curr_iebuf, "del", pktflag,
			oui0, oui1, oui2, ie_id, old_data, old_datalen);
		iebuf_len += del_iebuf_len;
		curr_iebuf += del_iebuf_len;

		/* Log the equivalent "wl del" command with the full hex string.
		 * Note that we actually do 1 atomic del+add vndr_ie iovar set
		 * instead of 2 separate "wl del" and "wl add" vndr_ie iovar sets.
		 */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"---wl del_ie -C %d %d %d %02x:%02x:%02x \n",
			bsscfg_idx, pktflag, old_datalen, oui0, oui1, oui2));
		/* log data */
		p2papi_log_hexdata(BCMP2P_LOG_MED,
			"      data",
			(unsigned char *)&old_data[0], old_datalen);
		BCMP2PLOG((BCMP2P_LOG_MED, FALSE, "\n"));
	}

	/* If the new IE data is not NULL, append a vndr_ie "add" iovar buffer */
	if (new_data != NULL) {
		add_iebuf_len = set_vndr_ie_buf(curr_iebuf, "add", pktflag,
			oui0, oui1, oui2, ie_id, new_data, new_datalen);
		iebuf_len += add_iebuf_len;

		/* Log the equivalent "wl add" command with the full hex string.
		 * Note that we actually do 1 atomic del+add vndr_ie iovar set
		 * instead of 2 separate "wl del" and "wl add" vndr_ie iovar sets.
		 */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"---wl add_ie -C %d %d %d %02x:%02x:%02x \n",
			bsscfg_idx, pktflag, new_datalen, oui0, oui1, oui2));
		/* log data */
		p2papi_log_hexdata(BCMP2P_LOG_MED,
			"      data ",
			(unsigned char *)&new_data[0], new_datalen);
		BCMP2PLOG((BCMP2P_LOG_MED, FALSE, "\n"));
	}

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"p2pwl_vndr_ie: del-len=%d add-len=%d iebuf_len=%d buflen=%d\n",
		del_iebuf_len, add_iebuf_len, iebuf_len, buflen));
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"             : idx=%d pktf=0x%x oui=0x%02x%02x%02x id=%u\n",
		bsscfg_idx, pktflag, oui0, oui1, oui2, ie_id));

	/* Check for IE buffer overflow */
	P2PLIB_ASSERT(iebuf_len <= buflen);
	if (iebuf_len > buflen) {
		/* This means we overwrote past the end of the malloc'd buffer which
		 * corrupts the next malloc memory block.
		 */
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_vndr_ie: IE buf overflow!  %d > %d\n", iebuf_len, buflen));
		goto ie_exit;
	}


	/* Set the IE by invoking the WL driver iovar "vndr_ie" */
	err = p2pwl_bssiovar_set(wl, "vndr_ie", bsscfg_idx, iebuf, iebuf_len);


ie_exit:
	P2PAPI_FREE(iebuf);
	return err;
}

int
p2pwl_get_mac_addr(P2PWL_HDL wl, struct ether_addr *out_mac_addr)
{
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	memset(out_mac_addr, 0, sizeof(*out_mac_addr));
	ret = p2pwl_iovar_get_bss(wl, "cur_etheraddr", out_mac_addr,
		sizeof(*out_mac_addr), 0);
	if (ret == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"---wl%s%s cur_etheraddr   ==> %02x:%02x:%02x:%02x:%02x:%02x\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, 0),
			out_mac_addr->octet[0], out_mac_addr->octet[1],
			out_mac_addr->octet[2], out_mac_addr->octet[3],
			out_mac_addr->octet[4], out_mac_addr->octet[5]));
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"---wl%s%s cur_etheraddr   ==> error %d\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, 0), ret));
	}
	return ret;
}

int
p2pwl_set_mac_addr(P2PWL_HDL wl, struct ether_addr *mac_addr, int bssidx)
{
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	if (bssidx == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"---wl cur_etheraddr %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac_addr->octet[0], mac_addr->octet[1], mac_addr->octet[2],
			mac_addr->octet[3], mac_addr->octet[4], mac_addr->octet[5]));
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"---wl%s%s cur_etheraddr %02x:%02x:%02x:%02x:%02x:%02x\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, bssidx),
			mac_addr->octet[0], mac_addr->octet[1], mac_addr->octet[2],
			mac_addr->octet[3], mac_addr->octet[4], mac_addr->octet[5]));
	}
	ret = p2pwl_iovar_set_bss(wl, "cur_etheraddr", mac_addr, sizeof(*mac_addr),
		bssidx);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl cur_etheraddr' error %d\n", ret));
	}
	return ret;
}


void
p2pwl_scan_prep(int channel, wl_scan_params_t *params)
{
	int num_chans = (channel == 0) ? 0 : 1;

	memcpy(&params->bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->bss_type = DOT11_BSSTYPE_ANY;
	params->scan_type = DOT11_SCANTYPE_ACTIVE;
/*	params->nprobes = htod32(-1); */
	params->nprobes = htod32(P2PAPI_SCAN_NPROBES);
	params->active_time = htod32(-1);
	params->passive_time = htod32(-1);
/*	params->home_time = htod32(-1); */
	params->home_time = htod32(P2PAPI_SCAN_HOME_TIME_MS);
	params->channel_list[0] = htodchanspec(channel);

	/* Our scan params have 1 channel and 0 ssids */
	params->channel_num = htod32((0 << WL_SCAN_PARAMS_NSSID_SHIFT) |
	(num_chans & WL_SCAN_PARAMS_COUNT_MASK));
}

/* allocate scan params buffer for 1 channel -- return 'null' if failed */
wl_scan_params_t *
p2pwl_alloc_scan_params(int channel, int nprobes, int *out_params_size)
{
	wl_scan_params_t *params;
	int params_size;

	*out_params_size = 0;

	/* Our scan params only need space for 1 channel and 0 ssids */
	params_size = WL_SCAN_PARAMS_FIXED_SIZE + 1 * sizeof(uint16);
	params = (wl_scan_params_t*)P2PAPI_MALLOC(params_size);
	if (params == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"P2PAPI: p2pwl_alloc_scan_params mem alloc failed (%d bytes)\n",
			params_size));
		return params;
	}
	memset(params, 0, params_size);
	params->nprobes = nprobes;

	p2pwl_scan_prep(channel, params);

	*out_params_size = params_size;	/* rtn size to the caller */
	return params;
}

/* Scan abort can only apply to primary interface to take effect */
/* Caller must pass in a primary-wl handle 'wl' for this function */
int
p2pwl_scan_abort(P2PWL_HDL wl)
{
	int err = 0;
	wl_scan_params_t *params;
	int params_size;

	/* verify the input primary WL handle */
	/* P2PAPI_WL_PRM_CHECK_HDL(wl); */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwl_scan_abort via primary interface\n"));

	/* Our scan params only need space for 1 channel and 0 ssids */
	params = p2pwl_alloc_scan_params(-1, 0, &params_size);
	if (params == NULL) {
		return -1;
	}

	err = p2papi_osl_wl_primary_ioctl(wl, WLC_SCAN, params, params_size, TRUE);
	P2PAPI_FREE(params);
	return err;
}

int
p2pwl_scan(P2PWL_HDL wl, int channel, int nprobes)
{
	/* Our scan params only need space for 1 channel and 0 ssids */
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + 1 * sizeof(uint16);
	wl_scan_params_t *params;
	int err = 0;

	P2PAPI_WL_CHECK_HDL(wl);
	params = (wl_scan_params_t*)malloc(params_size);
	if (params == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"P2PAPI: p2pwl_scan mem alloc failed (%d bytes)\n", params_size));
		return -1;
	}
	memset(params, 0, params_size);
	params->nprobes = nprobes;

	p2pwl_scan_prep(channel, params);

	err = p2papi_osl_wl_primary_ioctl(wl, WLC_SCAN, params, params_size, TRUE);
	free(params);
	return err;
}

/* Do a P2P scan of 3 given channels with the given channel dwell time.
 * Equivalent to the WL command "wl p2p_scan -a <ms> -c <c1>,<c2>,<c3>"
 */
int
p2pwl_scan_channels(P2PWL_HDL wl, int nprobes, int chan_dwell_ms,
	int channel1, int channel2, int channel3, unsigned char *ioctl_buf,
	size_t ioctl_buf_size, uint8 *scanpar_buf, size_t scanpar_buf_size,
	bool abort, int bssidx)
{
	uint32 num_chans = 3;
	int eparams_size;
	wl_escan_params_t *eparams;
	int err = 0;
	void *memblk;
	size_t memsize;
	wl_p2p_scan_t *p2p_params;

	P2PAPI_WL_CHECK_HDL(wl);

	/* Allocate scan params which need space for 3 channels and 0 ssids */
	eparams_size = (WL_SCAN_PARAMS_FIXED_SIZE + OFFSETOF(wl_escan_params_t, params)) +
	    num_chans * sizeof(uint16);
	memsize = sizeof(wl_p2p_scan_t) + eparams_size;
	memblk = scanpar_buf;
	if (memsize > scanpar_buf_size) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_scan_channels: scanpar buf too small (need %d bytes)\n",
			memsize));
		return -1;
	}
	memset(memblk, 0, memsize);

	/* Fill in the P2P scan structure at the start of the iovar param block */
	p2p_params = (wl_p2p_scan_t*) memblk;
	p2p_params->type = 'E';

	/* Fill in the Scan structure that follows the P2P scan structure */
	eparams = (wl_escan_params_t*) (p2p_params + 1);
	if (channel2 == 0)
		num_chans--;
	if (channel3 == 0)
		num_chans--;

	p2pwl_scan_prep(channel1, &eparams->params);
	if (nprobes)
		eparams->params.nprobes = htod32(nprobes);
	eparams->params.active_time = htod32(chan_dwell_ms);
	eparams->params.passive_time = htod32(0);
/*
	params->home_time = htod32(0);
*/
	eparams->params.channel_num = htod32((0 << WL_SCAN_PARAMS_NSSID_SHIFT) |
		(num_chans & WL_SCAN_PARAMS_COUNT_MASK));
	eparams->params.channel_list[0] = htodchanspec(channel1);
	eparams->params.channel_list[1] = htodchanspec(channel2);
	eparams->params.channel_list[2] = htodchanspec(channel3);
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2pwl_scan_channels: ty=%d np=%d at=%d cn=%d cl=%d,%d,%d\n",
		eparams->params.scan_type, eparams->params.nprobes,
		eparams->params.active_time,
		eparams->params.channel_num, eparams->params.channel_list[0],
		eparams->params.channel_list[1], eparams->params.channel_list[2]));

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"---wl p2p_scan E -a %d -h %d -n %d -c %d,%d,%d\n",
		chan_dwell_ms, P2PAPI_SCAN_HOME_TIME_MS, dtoh32(nprobes),
		channel1, channel2, channel3));
	eparams->version = htod32(ESCAN_REQ_VERSION);
	eparams->action =
		htod16(abort ? WL_SCAN_ACTION_ABORT : WL_SCAN_ACTION_START);
	eparams->sync_id = htod16(p2papi_osl_random());
	err = p2pwl_bssiovar_setbuf(wl, "p2p_scan", bssidx, memblk, memsize,
		ioctl_buf, ioctl_buf_size);

	return err;
}

/* Do a P2P scan of the given channel list.
 * Equivalent to the WL command "wl p2p_scan -n <np> -a <ms> -c <c1>,<c2>,..."
 */
int
p2pwl_scan_nchannels(P2PWL_HDL wl, int nprobes, int chan_dwell_ms,
	BCMP2P_INT32 num_chans, BCMP2P_UINT16* channels, unsigned char *ioctl_buf,
	size_t ioctl_buf_size, BCMP2P_UINT8 *scanpar_buf, size_t scanpar_buf_size,
	BCMP2P_BOOL abort, int bssidx)
{
	int eparams_size;
	wl_escan_params_t *eparams;
	int err = 0;
	void *memblk;
	size_t memsize;
	wl_p2p_scan_t *p2p_params;
	int i;

	P2PAPI_WL_CHECK_HDL(wl);

	/* Allocate scan params which need space for 3 channels and 0 ssids */
	eparams_size = (WL_SCAN_PARAMS_FIXED_SIZE +
		OFFSETOF(wl_escan_params_t, params)) +
		num_chans * sizeof(eparams->params.channel_list[0]);
	memsize = sizeof(wl_p2p_scan_t) + eparams_size;
	memblk = scanpar_buf;
	if (memsize > scanpar_buf_size) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2pwl_scan_nchannels: scanpar buf too small (%u > %u)\n",
			memsize, scanpar_buf_size));
		return -1;
	}
	memset(memblk, 0, memsize);

	/* Fill in the P2P scan structure at the start of the iovar param block */
	p2p_params = (wl_p2p_scan_t*) memblk;
	p2p_params->type = 'E';

	/* Fill in the Scan structure that follows the P2P scan structure */
	eparams = (wl_escan_params_t*) (p2p_params + 1);
	p2pwl_scan_prep(0, &eparams->params);
	if (nprobes)
		eparams->params.nprobes = htod32(nprobes);
	eparams->params.active_time = htod32(chan_dwell_ms);
	eparams->params.passive_time = htod32(0);
/*
	params->home_time = htod32(0);
*/
	eparams->params.channel_num = htod32((0 << WL_SCAN_PARAMS_NSSID_SHIFT) |
		(num_chans & WL_SCAN_PARAMS_COUNT_MASK));
	for (i = 0; i < num_chans; i++) {
		eparams->params.channel_list[i] = htodchanspec(channels[i]);
	}
	eparams->version = htod32(ESCAN_REQ_VERSION);
	eparams->action =
		htod16(abort ? WL_SCAN_ACTION_ABORT : WL_SCAN_ACTION_START);
	eparams->sync_id = htod16((uint16)p2papi_osl_random());
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwl_scan_nchannels: #ch=0x%x ty=0x%x ver=0x%x act=0x%x sid=0x%x\n",
		eparams->params.channel_num, eparams->params.scan_type,
		eparams->version, eparams->action, eparams->sync_id));

	/* Log the equivalent 'wl' command for this scan */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl p2p_scan E -a %d -p %d -h %d -n %d -c %d\n",
		dtoh32(eparams->params.active_time),
		dtoh32(eparams->params.passive_time),
		dtoh32(eparams->params.home_time),
		nprobes, channels[0]));
	for (i = 1; i < num_chans; i++) {
		BCMP2PLOG((BCMP2P_LOG_MED, FALSE, ",%d", channels[i]));
	}
	BCMP2PLOG((BCMP2P_LOG_MED, FALSE, "\n"));

	err = p2pwl_bssiovar_setbuf(wl, "p2p_scan", bssidx, memblk, memsize,
		ioctl_buf, ioctl_buf_size);

	return err;
}

/*
 * Input:
 *       scan_result: caller-provided input buffer that is used to stor
 *                    the scan-result
 *       bufsize: size of the caller-provided buffer in bytes
 * Output:
 *       return 0 if succeeds and scan-results will be stored in the buffer
 *       return -1 if error (e.g. buffer is too small)
 */
int
p2pwl_scan_get_results(P2PWL_HDL wl, wl_scan_results_t *scan_results, int bufsize)
{
	int ret = -1;

	P2PAPI_WL_CHECK_HDL(wl);

	if (bufsize <= sizeof(wl_scan_results_t))
		return -1;					/* buffer is too small */

	/* initialize the header */
	memset((unsigned char *)scan_results, 0, bufsize);
	scan_results->buflen = bufsize;

	ret = p2papi_osl_wl_primary_ioctl(wl, WLC_SCAN_RESULTS, scan_results, bufsize, FALSE);

	if (ret == 0) {
		uint32 i;
		for (i = 0; i < scan_results->count; i++) {
			scan_results->bss_info[i].chanspec =
				P2PWL_CHSPEC_IOTYPE_DTOH(scan_results->bss_info[i].chanspec);
		}
	}

	return ret;
}

/* Join a BSS with previously set security settings */
int
p2pwl_join(P2PWL_HDL wl, const char *ssid_str, unsigned long ssid_len,
	int bssidx)
{
	int ret;
	wlc_ssid_t ssid;

	P2PAPI_WL_CHECK_HDL(wl);
	if (ssid_len > sizeof(ssid.SSID))
		ssid_len = sizeof(ssid.SSID);
	strncpy((char *)ssid.SSID, ssid_str, ssid_len);
	ssid.SSID_len = htod32(ssid_len);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s join %.*s\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		ssid_len, ssid.SSID));
	ret = p2posl_wl_ioctl_bss(wl, WLC_SET_SSID, &ssid, sizeof(ssid), TRUE,
		bssidx);
	return ret;
}

/* Join a BSS with previously set security settings using the WLC_SET_SSID
 * ioctl.
 */
static int
p2pwl_join_bssid_with_ioctl(P2PWL_HDL wl, const char *ssid_str, unsigned long ssid_len,
	struct ether_addr *bssid, int num_chanspec, chanspec_t *chanspec, int bssidx)
{
	int ret;
	int join_params_size;
	wl_join_params_t *join_params;
	int i;

	P2PAPI_WL_CHECK_HDL(wl);

	join_params_size = WL_JOIN_PARAMS_FIXED_SIZE +
		num_chanspec * sizeof(chanspec_t);
	if ((join_params = (wl_join_params_t *)P2PAPI_MALLOC(join_params_size)) == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"P2PAPI: p2pwl_join_bssid_with_ioctl mem alloc failed (%d bytes)\n",
			join_params_size));
		return -1;
	}

	/* setup join parameters */
	memset(join_params, 0, join_params_size);

	if (ssid_len > sizeof(join_params->ssid.SSID))
		ssid_len = sizeof(join_params->ssid.SSID);
	strncpy((char *)join_params->ssid.SSID, ssid_str, ssid_len);
	join_params->ssid.SSID_len = htod32((uint32)ssid_len);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwl_join_bssid_with_ioctl: alloc=%d #ch=%d ssid_len=%d bssidx=%d\n",
		join_params_size, num_chanspec, ssid_len, bssidx));

	if (bssid)
		memcpy(&join_params->params.bssid, bssid, ETHER_ADDR_LEN);
	else
		memcpy(&join_params->params.bssid, &ether_bcast, ETHER_ADDR_LEN);

	/* channel spec */
	join_params->params.chanspec_num = htod32(num_chanspec);
	for (i = 0; i < join_params->params.chanspec_num; i++) {
		join_params->params.chanspec_list[i] =
			htodchanspec(P2PWL_CHSPEC_IOTYPE_HTOD(chanspec[i]));
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl%s%s join %.*s bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		ssid_len, join_params->ssid.SSID,
		join_params->params.bssid.octet[0], join_params->params.bssid.octet[1],
		join_params->params.bssid.octet[2], join_params->params.bssid.octet[3],
		join_params->params.bssid.octet[4], join_params->params.bssid.octet[5]));
	ret = p2posl_wl_ioctl_bss(wl, WLC_SET_SSID, join_params, join_params_size,
		TRUE, bssidx);
	P2PAPI_FREE(join_params);
	return ret;
}

/* Join a BSS with previously set security settings.
 *
 * First try using the "join" iovar.  If that iovar is not supported by the
 * driver then try using the WLC_SET_SSID ioctl.  The iovar is preferred
 * because it allows setting the join scan parameters.
 */
int
p2pwl_join_bssid(P2PWL_HDL wl, const char *ssid_str, unsigned long ssid_len,
	struct ether_addr *bssid, int num_chanspec, chanspec_t *chanspec, int bssidx)
{
#ifdef WL_EXTJOIN_PARAMS_FIXED_SIZE  /* if driver has "join" iovar */
	int ret;
	int join_params_size;
	wl_extjoin_params_t *join_params;
	int i;

	P2PAPI_WL_CHECK_HDL(wl);

	join_params_size = WL_EXTJOIN_PARAMS_FIXED_SIZE +
		num_chanspec * sizeof(chanspec_t);
	join_params = (wl_extjoin_params_t*)P2PAPI_MALLOC(join_params_size);
	if (join_params == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"P2PAPI: p2pwl_join_bssid mem alloc failed (%d bytes)\n",
			join_params_size));
		return -1;
	}
	memset(join_params, 0, join_params_size);

	/* Set up ssid parameter */
	if (ssid_len > sizeof(join_params->ssid.SSID))
		ssid_len = sizeof(join_params->ssid.SSID);
	strncpy((char *)join_params->ssid.SSID, ssid_str, ssid_len);
	join_params->ssid.SSID_len = htod32((uint32)ssid_len);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwl_join_bssid: alloc %d bytes,#ch=%d,ssid_len=%d\n",
		join_params_size, num_chanspec, ssid_len));

	/* Set up join scan parameters */
	join_params->scan.scan_type = 1;
	join_params->scan.nprobes = -1;
	join_params->scan.active_time = -1;
	if (num_chanspec == 1)
		join_params->scan.passive_time = P2PWL_JOIN_SCAN_PASSIVE_TIME_LONG;
	else
		join_params->scan.passive_time = P2PWL_JOIN_SCAN_PASSIVE_TIME;
	join_params->scan.home_time = -1;

	/* Set up association parameters: BSSID and chanspec list */
	if (bssid)
		memcpy(&join_params->assoc.bssid, bssid, ETHER_ADDR_LEN);
	else
		memcpy(&join_params->assoc.bssid, &ether_bcast, ETHER_ADDR_LEN);

	join_params->assoc.chanspec_num = num_chanspec;
	for (i = 0; i < join_params->assoc.chanspec_num; i++) {
		join_params->assoc.chanspec_list[i] = P2PWL_CHSPEC_IOTYPE_HTOD(chanspec[i]);
	}

	/* Set the iovar to start the join */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl joiniovar -C %d %s bssid %02x:%02x:%02x:%02x:%02x:%02x\n",
		bssidx, join_params->ssid.SSID,
		join_params->assoc.bssid.octet[0], join_params->assoc.bssid.octet[1],
		join_params->assoc.bssid.octet[2], join_params->assoc.bssid.octet[3],
		join_params->assoc.bssid.octet[4], join_params->assoc.bssid.octet[5]));
	ret = p2pwl_bssiovar_set(wl, "join", bssidx, join_params, join_params_size);

	P2PAPI_FREE(join_params);
	/* If the "join" iovar is not supported by the WL driver
	 *     Try the join again using the WLC_SET_SSID ioctl.
	 */
	if (ret == BCME_UNSUPPORTED) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwl_join_bssid: 'join' iovar unsupported, trying ioctl.\n"));
		p2pwl_join_bssid_with_ioctl(wl, ssid_str, ssid_len, bssid,
			num_chanspec, chanspec, bssidx);
	}
	return ret;
#else /* no "join" iovar */
	return p2pwl_join_bssid_with_ioctl(wl, ssid_str, ssid_len, bssid,
		num_chanspec, chanspec, bssidx);
#endif /* WL_EXTJOIN_PARAMS_FIXED_SIZE */
}

/* Join a BSS with no security */
int
p2pwl_join_open(P2PWL_HDL wl, char *bss_ssid, int bssidx)
{
	int ret;
	wlc_ssid_t ssid;
	int wsec = 0, auth = 0, infra = 1; /* defaults: imode bss amode open */
	int wpa_auth = WPA_AUTH_DISABLED;

	/* verify that SSID was specified and is a valid length */
	P2PAPI_WL_CHECK_HDL(wl);
	if (!bss_ssid || (strlen(bss_ssid) > DOT11_MAX_SSID_LEN))
		return -1;

	/* set ssid */
	ssid.SSID_len = (uint32) strlen(bss_ssid);
	memcpy(ssid.SSID, bss_ssid, ssid.SSID_len);
	ssid.SSID_len = htod32(ssid.SSID_len);

	/* set infrastructure mode */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s infra %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		infra));
	infra = htod32(infra);
	ret = p2posl_wl_ioctl_bss(wl, WLC_SET_INFRA, &infra, sizeof(int), TRUE,
		bssidx);
	if (ret < 0)
		return ret;

	/* set authentication mode */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s auth %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		auth));
	auth = htod32(auth);
	ret = p2posl_wl_ioctl_bss(wl, WLC_SET_AUTH, &auth, sizeof(int), TRUE,
		bssidx);
	if (ret < 0)
		return ret;

	/* set wsec mode */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s wsec %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		wsec));
	ret = p2pwl_iovar_setint_bss(wl, "wsec", wsec, bssidx);
	if (ret < 0)
		return ret;

	/* set WPA_auth mode */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s wpa_auth %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		wpa_auth));
	wpa_auth = htod32(wpa_auth);
	ret = p2posl_wl_ioctl_bss(wl, WLC_SET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth),
		TRUE, bssidx);
	if (ret < 0)
		return ret;

	/* set wpa supplicant off */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s sup_wpa 0\n",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx)));
	P2PLOG("---wl sup_wpa 0\n");
	ret = p2pwl_iovar_setint_bss(wl, "sup_wpa", 0, 0);
	if (ret < 0)
		return ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s join %s imode bss amode open\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		ssid.SSID));
	return p2posl_wl_ioctl_bss(wl, WLC_SET_SSID, &ssid, sizeof(wlc_ssid_t),
		TRUE, bssidx);
}

int
p2pwl_disassoc(P2PWL_HDL wl, int bssidx)
{
	P2PAPI_WL_CHECK_HDL(wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s disassoc\n",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx)));
	return p2posl_wl_ioctl_bss(wl, WLC_DISASSOC, NULL, 0, TRUE, bssidx);
}


/* Check if we are associated to an AP on the specified BSS.
 * Call this only on the peer acting as a STA.
 */
P2PWL_BOOL
p2pwl_is_associated_bss(P2PWL_HDL wl, struct ether_addr *out_bssid, int bssidx)
{
	int ret;
	int loopIdx;
	P2PWL_BOOL bAssociated = false;

	P2PAPI_WL_CHECK_HDL(wl);

	/* check for the network association -- loop to make sure data is correct */
	for (loopIdx = 0; loopIdx < 10; loopIdx++) {
		memset(out_bssid, 0, sizeof(*out_bssid));
		ret = p2posl_wl_ioctl_bss(wl, WLC_GET_BSSID, out_bssid, ETHER_ADDR_LEN,
			FALSE, bssidx);

		/* ret == 0 means the adapter is associated */
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"---WLC_GET_BSSID   ==> is_assoc=%d (ret=%d) bssidx=%d\n",
			(ret == 0), ret, bssidx));
		if (ret != 0)
			break;		/* if error, out of the loop */

		/* check 'bssid' */
		if (out_bssid->octet[0] == 0 && out_bssid->octet[1] == 0 &&
			out_bssid->octet[2] == 0 && out_bssid->octet[3] == 0 &&
			out_bssid->octet[4] == 0 && out_bssid->octet[5] == 0)
		{
			BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "p2pwl_is_associated_bss:"
				" WLC_GET_BSSID not ready, bssid=All 0s, loop=%d\n",
				loopIdx));
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_WAIT_ASSOC_STATUS, 100);
			continue;	/* continue the loop */
		}

		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"p2pwl_is_associated_bss: bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
			out_bssid->octet[0], out_bssid->octet[1], out_bssid->octet[2],
			out_bssid->octet[3], out_bssid->octet[4], out_bssid->octet[5]));
		bAssociated = true;
		break;
	}
	return bAssociated;
}

/* Get the number of STAs associated to our BSS.
 * Call this only on the peer acting as an AP.
 * Returns 0 if success, non-zero if error.
 */
int
p2pwl_get_assoc_count(P2PWL_HDL wl, P2PWL_BOOL show_maclist,
	unsigned char *ioctl_buf, int *out_assoc_count, int bssidx)
{
	uint max = (P2PAPI_IOCTL_BUF_SIZE2 - sizeof(int)) / ETHER_ADDR_LEN;
	struct maclist *maclist = (struct maclist *) ioctl_buf;
	int ret;
	uint count = 0;
	struct ether_addr *ea;
	uint i;
#if P2PLOGGING
	char etoa_buf[ETHER_ADDR_LEN * 3];
#endif

	P2PAPI_WL_CHECK_HDL(wl);
	maclist->count = htod32(max);

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "---wl%s%s assoclist\n",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx)));
	ret = p2posl_wl_ioctl_bss(wl, WLC_GET_ASSOCLIST, maclist,
		P2PAPI_IOCTL_BUF_SIZE2, FALSE, bssidx);
	if (ret != 0) {
		P2PLOG1("p2pwl_get_assoc_count: ioctl error %d\n", ret);
		return ret;
	}

	count = dtoh32(maclist->count);
	if (count != 0) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2pwl_get_assoc_count: count=%u\n", count));
		if (show_maclist) {
			for (i = 0, ea = maclist->ea;  i < count && i < max;  i++, ea++) {
				BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
					"  %d. %s\n", i, p2pwl_ether_etoa(ea, etoa_buf)));
			}
		}
	}
	*out_assoc_count = count;
	return 0;
}

/* Get the number of STAs authorized to our BSS.
 * Call this only on the peer acting as an AP.
 * Returns 0 if success, non-zero if error.
 */
int
p2pwl_get_autho_sta_list(P2PWL_HDL wl, P2PWL_BOOL show_maclist,
	unsigned char *ioctl_buf, int *out_assoc_count, int bssidx)
{
	uint max = (P2PAPI_IOCTL_BUF_SIZE - sizeof(int)) / ETHER_ADDR_LEN;
	struct maclist *maclist = (struct maclist *) ioctl_buf;
	int ret;
	uint count = 0;
	struct ether_addr *ea;
	uint i;
#if P2PLOGGING
	char etoa_buf[ETHER_ADDR_LEN * 3];
#endif

	P2PAPI_WL_CHECK_HDL(wl);
	maclist->count = htod32(max);

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "---wl%s%s autho_sta_list\n",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx)));
	ret = p2pwl_iovar_getbuf_bss(wl, "autho_sta_list", NULL, 0,
		maclist, P2PAPI_IOCTL_BUF_SIZE, bssidx);
	if (ret != 0) {
		P2PLOG1("p2pwl_get_autho_sta_list: ioctl error %d\n", ret);
		return ret;
	}

	count = dtoh32(maclist->count);
	if (count != 0) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2pwl_get_autho_sta_list: count=%u\n", count));
		if (show_maclist) {
			for (i = 0, ea = maclist->ea;  i < count && i < max;  i++, ea++) {
				BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
					"  %d. %s\n", i, p2pwl_ether_etoa(ea, etoa_buf)));
			}
		}
	}
	*out_assoc_count = count;
	return 0;
}


/*
 * Check if a BSS is up.
 * This is a common implementation called by most OSL implementations of
 * p2posl_bss_isup().  DO NOT call this function directly from the
 * common code -- call p2posl_bss_isup() instead to allow the OSL to
 * override the common implementation if necessary.
 */
P2PWL_BOOL
p2pwl_common_bss_isup(P2PWL_HDL wl, int bsscfg_idx)
{
	int result, val;
	P2PWL_BOOL isup = FALSE;
	char getbuf[64];
	int *intbuf = (int *)getbuf;

	P2PAPI_WL_CHECK_HDL(wl);

	/* Check if the BSS is up */
	*intbuf = -1;
	result = p2pwl_iovar_getbuf_bss(wl, "bss", &bsscfg_idx, sizeof(bsscfg_idx),
		getbuf, sizeof(getbuf), 0);
	if (result != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwl_bss_isup: 'wl bss -C %d' failed: %d\n",
			bsscfg_idx, result));
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "NOTE: this ioctl error is normal "
			"when the BSS has not been created yet.\n"));
	} else {
		val = *intbuf;
		val = dtoh32(val);
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"---wl bss -C %d   ==> %d\n", bsscfg_idx, val));
		isup = (val ? TRUE : FALSE);
	}
	return isup;
}

/* Bring up or down a BSS */
int
p2pwl_bss(P2PWL_HDL wl, int bsscfg_idx, P2PWL_BOOL up)
{
	int ret;
	int val = up ? 1 : 0;

	struct {
		int cfg;
		int val;
	} bss_setbuf;

	P2PAPI_WL_CHECK_HDL(wl);
	bss_setbuf.cfg = htod32(bsscfg_idx);
	bss_setbuf.val = htod32(val);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl bss -C %d %s\n",
		bsscfg_idx, up ? "up" : "down"));
	ret = p2pwl_iovar_set_bss(wl, "bss", &bss_setbuf, sizeof(bss_setbuf), 0);
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"'p2pwl_bss %d' failed with %d\n", up, ret));
	}

	return ret;
}

int
p2pwl_set_chanspec(P2PWL_HDL wl, chanspec_t chspec, int bssidx)
{
	P2PAPI_WL_CHECK_HDL(wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s chanspec 0x%x\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		chspec));
	chspec = P2PWL_CHSPEC_IOTYPE_HTOD(chspec);
	return p2pwl_iovar_setint_bss(wl, "chanspec", htodchanspec(chspec), bssidx);
}

int
p2pwl_get_chanspec(P2PWL_HDL wl, chanspec_t *chspec, int bssidx)
{
	int ret;
	int val;

	P2PAPI_WL_CHECK_HDL(wl);

	ret = p2pwl_iovar_getint_bss(wl, "chanspec", &val, bssidx);
	if (ret == 0) {
		val = dtoh32(val);
		*chspec =  P2PWL_CHSPEC_IOTYPE_DTOH((chanspec_t)val);
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s chanspec   ==> 0x%x\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, bssidx),
			*chspec));
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"---wl%s%s chanspec   ==> error %d\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, bssidx), ret));
	}

	return ret;
}


int
p2pwl_up(P2PWL_HDL wl)
{
	P2PAPI_WL_CHECK_HDL(wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl up\n"));
	return p2posl_wl_ioctl_bss(wl, WLC_UP, NULL, 0, TRUE, 0);
}

int
p2pwl_down(P2PWL_HDL wl)
{
	P2PAPI_WL_CHECK_HDL(wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl down\n"));
	return p2posl_wl_ioctl_bss(wl, WLC_DOWN, NULL, 0, TRUE, 0);
}

/* Check if the WL driver is up */
P2PWL_BOOL
p2pwl_isup(P2PWL_HDL wl)
{
	int ret;
	int val = -1;
	P2PWL_BOOL isup = FALSE;

	P2PAPI_WL_CHECK_HDL(wl);
	ret = p2posl_wl_ioctl_bss(wl, WLC_GET_UP, &val, sizeof(val), FALSE, 0);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl isup: failed with %d\n", ret));
	}
	else {
		val = dtoh32(val);
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl isup   ==> %d\n", val));
		isup = (val ? TRUE : FALSE);
	}

	return isup;
}


int
p2pwl_set_p2p_discovery(P2PWL_HDL wl, int on)
{
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s p2p_disc %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, 0),
		on));
	ret = p2pwl_iovar_setint_bss(wl, "p2p_disc", on, 0);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl%s%s p2p_disc %d' error %d\n",
			p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, 0),
			on, ret));
	}
	return ret;
}

/* Set the WL driver's P2P mode.
 * mode is one of WL_P2P_DISC_ST_{SCAN,LISTEN,SEARCH}.
 */
int
p2pwl_set_p2p_mode(P2PWL_HDL wl, uint8 mode, chanspec_t chspec, uint16 listen_ms,
	int bssidx)
{
	wl_p2p_disc_st_t discovery_mode;
	int ret;

	/* Put the WL driver into P2P Listen Mode to respond to P2P probe reqs */
	discovery_mode.state = mode;
	if (chspec != 0)
		chspec = P2PWL_CHSPEC_IOTYPE_HTOD(chspec);
	discovery_mode.chspec = htodchanspec(chspec);
	discovery_mode.dwell = htod16(listen_ms);
	if (mode == WL_P2P_DISC_ST_LISTEN)
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "---wl%s%s p2p_state %u %x %u\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, bssidx),
			discovery_mode.state, chspec, discovery_mode.dwell));
	else
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "---wl%s%s p2p_state %u\n",
			p2posl_get_netif_name_prefix(wl),
			p2posl_get_netif_name_bss(wl, bssidx), discovery_mode.state));

	ret = p2pwl_bssiovar_set(wl, "p2p_state", bssidx, &discovery_mode,
		sizeof(discovery_mode));
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "'wl p2p_state' error %d\n", ret));
	}
	return ret;
}

/* Get the index of the P2P Discovery BSS */
int
p2pwl_get_p2p_disc_idx(P2PWL_HDL wl, int *index)
{
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s p2p_dev\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, 0)));
	ret = p2pwl_iovar_getint_bss(wl, "p2p_dev", index, 0);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwl_get_p2p_disc_idx: p2p_dev bsscfg_idx=%d ret=%d\n", *index, ret));
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl p2p_dev' error %d\n", ret));
		return ret;
	}
	return ret;
}

int
p2pwl_set_p2p_fname(P2PWL_HDL wl, wlc_ssid_t *ssid)
{
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s p2p_ssid %s   (len %u)\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, 0),
		ssid->SSID, ssid->SSID_len));
	ret = p2pwl_iovar_set_bss(wl, "p2p_ssid", ssid, sizeof(*ssid), 0);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2pwl_set_p2p_fname err %d\n", ret));
	}
	return ret;
}


int
p2pwl_set_apsta(P2PWL_HDL wl, int val)
{
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s apsta %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, 0),
		val));
	ret = p2pwl_iovar_setint_bss(wl, "apsta", val, 0);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "wl apsta: error %d\n", ret));
	}
	return ret;
}

int
p2pwl_get_apsta(P2PWL_HDL wl)
{
	int val = -99;
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	ret = p2pwl_iovar_getint_bss(wl, "apsta", &val, 0);
	if (ret >= 0) {
		ret = dtoh32(val);
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s apsta   ==> %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, 0),
		ret));
	return ret;
}

int
p2pwl_set_ssid(P2PWL_HDL wl, int bsscfg_idx, unsigned char *name,
	unsigned long len)
{
	int ret;
	wlc_ssid_t ssid;

	P2PAPI_WL_CHECK_HDL(wl);
	if (len > sizeof(ssid.SSID))
		len = sizeof(ssid.SSID);
	memcpy(ssid.SSID, name, len);
	ssid.SSID_len = htod32(len);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl ssid -C %d %.*s\n", bsscfg_idx, len, ssid.SSID));
	ret = p2pwl_bssiovar_set(wl, "ssid", bsscfg_idx, &ssid, sizeof(ssid));
	if (ret < 0)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl ssid -C %d %.*s: error %d\n",
			bsscfg_idx, len, ssid.SSID, ret));
	return ret;
}

int
p2pwl_get_ssid(P2PWL_HDL wl, int bsscfg_idx, wlc_ssid_t *ssid)
{
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	ssid->SSID_len = 0;
	ssid->SSID[0] = '\0';

	ret = p2pwl_bssiovar_get(wl, "ssid", bsscfg_idx, ssid, sizeof(*ssid));
	if (ret < 0)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl ssid -C %d: error %d\n",
			bsscfg_idx, ret));
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"---wl ssid -C %d   ==> %s (len=%d)\n",
			bsscfg_idx, ssid->SSID, ssid->SSID_len));

	return ret;
}

int
p2pwl_send_act_frame(P2PWL_HDL wl, wl_af_params_t *af_params,
	unsigned char *ioctl_buf, int bssidx)
{
	int ret;
	wl_action_frame_t *action_frame = &af_params->action_frame;

	(void) action_frame;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl%s%s actframe -C %d %02x:%02x:%02x:%02x:%02x:%02x \n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		bssidx,
		action_frame->da.octet[0], action_frame->da.octet[1],
		action_frame->da.octet[2], action_frame->da.octet[3],
		action_frame->da.octet[4], action_frame->da.octet[5]));
	/* the next param in "wl actframe" is a hex dump of the action frame data */
	{
		uint8 *b = (uint8*)action_frame->data;
		/* log data */
		p2papi_log_hexdata(BCMP2P_LOG_MED,
			"        data",
			(unsigned char *)&b[0], action_frame->len);
	}
	/* the next 2 params in "wl actframe" are the channel and dwell time */
	BCMP2PLOG((BCMP2P_LOG_MED, FALSE, "  %u %u\n",
		af_params->channel, af_params->dwell_time));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    len=%u channel=%u dwell_time=%u\n",
		action_frame->len, af_params->channel, af_params->dwell_time));

	/* Transmit the action frame */
/*	ASSERT(sizeof(*af_params) <= WLC_IOCTL_MEDLEN); */
	ret = p2pwl_bssiovar_setbuf(wl, "actframe", bssidx, af_params,
		sizeof(*af_params), ioctl_buf, WLC_IOCTL_MAXLEN);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwl_send_act_frame via actframe iovar: status=%u\n", ret));

	return ret;
}



int
p2pwl_set_int_bss(P2PWL_HDL wl, int ioctl_cmd, int val, int bssidx)
{
	int setval = htod32(val);
	int ret;

	ret = p2posl_wl_ioctl_bss(wl, ioctl_cmd, &setval, sizeof(setval), TRUE,
		bssidx);
	return ret;
}


int
p2pwl_get_int_bss(P2PWL_HDL wl, int ioctl_cmd, int *val, int bssidx)
{
	int ret;

	ret = p2posl_wl_ioctl_bss(wl, ioctl_cmd, val, sizeof(*val), FALSE, bssidx);
	if (ret >= 0) {
		val = dtoh32(val);
	}
	return ret;
}


int
p2pwl_get_macmode(P2PWL_HDL wl, int *val, int bssidx)
{
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	*val = -99;
	ret = p2pwl_get_int_bss(wl, WLC_GET_MACMODE, val, bssidx);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s macmode   ==> %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		*val));
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "'wl macmode' failed with %d\n", ret));
	}
	return ret;
}

int
p2pwl_set_macmode(P2PWL_HDL wl, int val, int bssidx)
{
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s macmode %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
		val));
	ret = p2pwl_set_int_bss(wl, WLC_SET_MACMODE, val, bssidx);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "'wl macmode 1' failed with %d\n",
			ret));
	}
	return ret;
}

int
p2pwl_get_maclist(P2PWL_HDL wl, uint8 *ioctl_buf, size_t ioctl_buf_size,
	unsigned int mac_list_max, struct ether_addr *out_mac_list,
	unsigned int *out_mac_count, int bssidx)
{
	struct maclist *maclist = (struct maclist *) ioctl_buf;
	unsigned int listmax = (ioctl_buf_size - sizeof(int)) / ETHER_ADDR_LEN;
	struct ether_addr *ea;
	unsigned int i;
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s mac\n",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx)));

	/* Do the wl driver ioctl to get the maclist */
	maclist->count = htod32(listmax);
	ret = p2posl_wl_ioctl_bss(wl, WLC_GET_MACLIST, maclist, WLC_IOCTL_MAXLEN,
		FALSE, bssidx);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "   'wl mac': error %d\n", ret));
		return ret;
	}
	*out_mac_count = dtoh32(maclist->count);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "   'wl mac' result: count=%d\n",
		*out_mac_count));
	if (*out_mac_count > mac_list_max)
		*out_mac_count = mac_list_max;

	/* Copy the mac list from the ioctl buf to the output mac list */
	for (i = 0; i < *out_mac_count; i++) {
		ea = &out_mac_list[i];
		memcpy(ea, &maclist->ea[i], sizeof(*ea));
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"    %02x:%02x:%02x:%02x:%02x:%02x\n",
			ea->octet[0], ea->octet[1], ea->octet[2],
			ea->octet[3], ea->octet[4], ea->octet[5]));
	}

	return 0;
}

int
p2pwl_set_maclist(P2PWL_HDL wl, uint8 *ioctl_buf, size_t ioctl_buf_size,
	struct ether_addr *in_mac_list, unsigned int in_mac_count, int bssidx)
{
	struct maclist *maclist = (struct maclist *) ioctl_buf;
	struct ether_addr *ea;
	unsigned int i, len;
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s mac",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx)));

	/* Copy the mac list from the input mac list to the ioctl buf */
	for (i = 0; i < in_mac_count; i++) {
		ea = &maclist->ea[i];
		memcpy(ea, &in_mac_list[i], sizeof(*ea));
		BCMP2PLOG((BCMP2P_LOG_MED, FALSE,
			" %02x:%02x:%02x:%02x:%02x:%02x",
			ea->octet[0], ea->octet[1], ea->octet[2],
			ea->octet[3], ea->octet[4], ea->octet[5]));
	}
	BCMP2PLOG((BCMP2P_LOG_MED, FALSE, "\n"));

	/* Calculate the ioctl buf size */
	maclist->count = htod32(in_mac_count);
	len = sizeof(maclist->count) + in_mac_count * sizeof(maclist->ea);
	if (len > ioctl_buf_size) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwl_set_maclist: len %u too large\n", len));
		return -1;
	}

	/* Do the wl driver ioctl to set the maclist */
	ret = p2posl_wl_ioctl_bss(wl, WLC_SET_MACLIST, maclist, len, TRUE, bssidx);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "   'wl mac': error %d\n", ret));
		return ret;
	}

	return 0;
}

/* Create a new P2P BSS.
 * Parameters:
 * - mac      : MAC address of the BSS to create
 * - if_type  : interface type: WL_P2P_IF_GO or WL_P2P_IF_CLIENT
 * - chspec   : chspec to use if creating a GO BSS.
 * Returns 0 if success.
 */
int
p2pwl_p2p_ifadd(P2PWL_HDL wl, struct ether_addr *mac, uint8 if_type,
	chanspec_t chspec)
{
	wl_p2p_if_t ifreq;
	int ret;

	memcpy(ifreq.addr.octet, mac->octet, sizeof(ifreq.addr.octet));
	ifreq.type = if_type;
	ifreq.chspec = P2PWL_CHSPEC_IOTYPE_HTOD(chspec);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl p2p_ifadd %02x:%02x:%02x:%02x:%02x:%02x %s %u\n",
		ifreq.addr.octet[0], ifreq.addr.octet[1], ifreq.addr.octet[2],
		ifreq.addr.octet[3], ifreq.addr.octet[4], ifreq.addr.octet[5],
		(if_type == WL_P2P_IF_GO) ? "go" : "client",
		(chspec & WL_CHANSPEC_CHAN_MASK) >> WL_CHANSPEC_CHAN_SHIFT));

	ret = p2pwl_iovar_set_bss(wl, "p2p_ifadd", &ifreq, sizeof(ifreq), 0);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl p2p_ifadd' error %d\n", ret));
	}
	return ret;
}

/* Delete a P2P BSS.
 * Parameters:
 * - mac      : MAC address of the BSS to create
 * Returns 0 if success.
 */
int
p2pwl_p2p_ifdel(P2PWL_HDL wl, struct ether_addr *mac)
{
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl p2p_ifdel %02x:%02x:%02x:%02x:%02x:%02x\n",
		mac->octet[0], mac->octet[1], mac->octet[2],
		mac->octet[3], mac->octet[4], mac->octet[5]));
	ret = p2pwl_iovar_set_bss(wl, "p2p_ifdel", mac, sizeof(*mac), 0);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl p2p_ifdel' error %d\n", ret));
	}
	return ret;
}

/* Get the index of a created P2P BSS.
 * Parameters:
 * - mac      : MAC address of the created BSS
 * - index    : output: index of created BSS
 * Returns 0 if success.
 */
int
p2pwl_p2p_ifidx(P2PWL_HDL wl, struct ether_addr *mac, int *index)
{
	int ret;
	uint8 getbuf[64];

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl p2p_if %02x:%02x:%02x:%02x:%02x:%02x\n",
		mac->octet[0], mac->octet[1], mac->octet[2],
		mac->octet[3], mac->octet[4], mac->octet[5]));
	ret = p2pwl_iovar_getbuf_bss(wl, "p2p_if", mac, sizeof(*mac),
		getbuf, sizeof(getbuf), 0);
	if (ret == 0) {
		memcpy(index, getbuf, sizeof(*index));
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl p2p_if   ==> %d\n", *index));
	}

	return ret;
}

/* Update a P2P BSS. (mainly use on Windows)
 * Parameters:
 * - mac      : MAC address of the BSS to update
 * - if_type  : interface type: WL_P2P_IF_GO or WL_P2P_IF_CLIENT
 * - chspec   : chspec to use if updating a GO BSS.
 * Returns 0 if success.
 */
int
p2pwl_p2p_ifupd(P2PWL_HDL wl, struct ether_addr *mac, uint8 if_type,
	chanspec_t chspec, int bssidx)
{
	wl_p2p_if_t ifreq;
	int ret;

	memcpy(ifreq.addr.octet, mac->octet, sizeof(ifreq.addr.octet));
	ifreq.type = if_type;
	ifreq.chspec =  P2PWL_CHSPEC_IOTYPE_HTOD(chspec);

#ifdef WL_P2P_IF_DEV
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl p2p_ifupd -C %d %02x:%02x:%02x:%02x:%02x:%02x %s 0x%x\n",
		bssidx,
		ifreq.addr.octet[0], ifreq.addr.octet[1], ifreq.addr.octet[2],
		ifreq.addr.octet[3], ifreq.addr.octet[4], ifreq.addr.octet[5],
		(if_type == WL_P2P_IF_GO) ? "go" :
		(if_type == WL_P2P_IF_CLIENT) ? "client" :
		(if_type == WL_P2P_IF_DEV) ? "dev" : "unknown",
		chspec));
#else
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl p2p_ifupd -C %d %02x:%02x:%02x:%02x:%02x:%02x %u %u\n",
		bssidx,
		ifreq.addr.octet[0], ifreq.addr.octet[1], ifreq.addr.octet[2],
		ifreq.addr.octet[3], ifreq.addr.octet[4], ifreq.addr.octet[5],
		if_type, chspec));
#endif /* WL_P2P_IF_DEV */

	ret = p2pwl_bssiovar_set(wl, "p2p_ifupd", bssidx, &ifreq, sizeof(ifreq));
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl p2p_ifupd' error %d\n", ret));
	}
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "'wl p2p_ifupd' succeeds\n"));

	return ret;
}

/* Check if 'p2p' is supported in the driver */
int
p2pwl_is_p2p_supported(P2PWL_HDL wl)
{
	int ret;
	int is_p2p_supported = 0;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl p2p\n"));
	ret = p2pwl_iovar_getint_bss(wl, "p2p", &is_p2p_supported, 0);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwl_get_p2p_supported=%d\n", is_p2p_supported, ret));
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl p2p' error %d\n", ret));
		return 0;		/* assume 'p2p' is not supported */
	}

	return is_p2p_supported;
}

/* Set the driver's Spectrum Management mode (set to 0 to disable Dynamic
 * Frequency Selection).
 */
int
p2pwl_set_spect_mgmt(P2PWL_HDL wl, int spect_mgmt)
{
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl spect %d\n", spect_mgmt));
	ret = p2pwl_set_int_bss(wl, WLC_SET_SPECT_MANAGMENT, spect_mgmt, 0);
	if (ret < 0)
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "   'wl spect %d': error %d\n",
			spect_mgmt, ret));

	return ret;
}

int
p2pwl_get_spect_mgmt(P2PWL_HDL wl, int *val)
{
	int ret;

	P2PAPI_WL_CHECK_HDL(wl);

	ret = p2pwl_get_int_bss(wl, WLC_GET_SPECT_MANAGMENT, val, 0);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s spect   ==> %d\n",
		p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, 0),
		*val));
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "'wl spect' failed with %d\n", ret));
	}
	return ret;
}


/* set PM */
int
p2pwl_set_PM(P2PWL_HDL wl, int val, int bssidx)
{
	int PM = htod32(val);
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s PM %d\n",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx), val));
	ret = p2posl_wl_ioctl_bss(wl, WLC_SET_PM, &PM, sizeof(PM), TRUE, bssidx);
	if (ret < 0)
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl PM %d' error %d\n", val, ret));

	return ret;
}

/* get PM */
int
p2pwl_get_PM(P2PWL_HDL wl, int *val, int bssidx)
{
	int PM;
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s PM  ==> %d\n",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx), *val));
	ret = p2posl_wl_ioctl_bss(wl, WLC_GET_PM, &PM, sizeof(PM), FALSE, bssidx);
	if (ret < 0)
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl PM' error\n", ret));

	*val = dtoh32(PM);
	return ret;
}


int
p2pwl_set_listen_interval(P2PWL_HDL wl, unsigned int val, int bssidx)
{
	unsigned int interval = htod32(val);
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s assoc_listen %u\n",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx), val));

	ret = p2pwl_bssiovar_set(wl, "assoc_listen", bssidx, &interval, sizeof(interval));
	if (ret < 0)
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl assoc_listen %u' error %d\n", val, ret));

	return ret;
}

/* set roam_off */
int
p2pwl_set_roam_off(P2PWL_HDL wl, unsigned int val, int bssidx)
{
	int roam_off = htod32(val);
	int ret;

	/* set roam_off TRUE/FALSE */
	if (roam_off)
		roam_off = 1;
	else
		roam_off = 0;

        BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s roam_off %d\n",
                p2posl_get_netif_name_prefix(wl), p2posl_get_netif_name_bss(wl, bssidx),
                roam_off));
        ret = p2pwl_iovar_setint_bss(wl, "roam_off", roam_off, bssidx);

	if (ret < 0)
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl roam_off %d' error %d\n", val, ret));

	return ret;
}


int
p2pwl_set_wme_apsd_sta(P2PWL_HDL wl, uint8 maxSPLen, uint8 acBE, uint8 acBK,
	uint8 acVI, uint8 acVO, int bssidx)
{
	int ret;
	uint32 apsd_sta_qosinfo;

	apsd_sta_qosinfo = (maxSPLen << WME_QI_STA_MAXSPLEN_SHIFT) & WME_QI_STA_MAXSPLEN_MASK;
	apsd_sta_qosinfo |= (acBE << WME_QI_STA_APSD_BE_SHIFT) & WME_QI_STA_APSD_BE_MASK;
	apsd_sta_qosinfo |= (acBK << WME_QI_STA_APSD_BK_SHIFT) & WME_QI_STA_APSD_BK_MASK;
	apsd_sta_qosinfo |= (acVI << WME_QI_STA_APSD_VI_SHIFT) & WME_QI_STA_APSD_VI_MASK;
	apsd_sta_qosinfo |= (acVO << WME_QI_STA_APSD_VO_SHIFT) & WME_QI_STA_APSD_VO_MASK;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl%s%s wme_qosinfo 0x%x\n",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx), apsd_sta_qosinfo));

	apsd_sta_qosinfo = htod32(apsd_sta_qosinfo);

	ret = p2pwl_bssiovar_set(wl, "wme_qosinfo", bssidx, &apsd_sta_qosinfo,
		sizeof(apsd_sta_qosinfo));
	if (ret < 0)
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "'wl wme_qosinfo 0x%x' error %d\n",
			apsd_sta_qosinfo, ret));

	return ret;
}
