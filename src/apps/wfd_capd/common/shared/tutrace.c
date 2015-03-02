/*
 * Debug messages
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id:$
 */

#if defined(WIN32) || defined(WINCE)
#include <windows.h>
#endif
#if !defined(WIN32)
#include <stdarg.h>
#endif
#include <stdio.h>
#include <string.h>
#if defined(__linux__)
#include <time.h>
#endif
#include "tutrace.h"

#define WFDCAPD_DISPBUF_SIZE 512

static TRACEMSG_OUTPUT_FN traceMsgOutputFn = NULL;

void
wfd_capd_redirect_log(TRACEMSG_OUTPUT_FN fn)
{
	traceMsgOutputFn = fn;
}

#ifdef _TUDEBUGTRACE
void
wfd_capd_print_trace_msg(int level, const char *lpszFunction,
	int nLine, char *lpszFormat, ...)
{
	char szTraceMsg[2000];
	int cbMsg;
	va_list lpArgv;

#ifdef _WIN32_WCE
	TCHAR szMsgW[2000];
#endif

	if (!(TUTRACELEVEL & level)) {
		return;
	}
	/* Format trace msg prefix */
	if (traceMsgOutputFn != NULL)
		cbMsg = sprintf(szTraceMsg, "WFDCAPD: %s(%d):", lpszFunction, nLine);
	else
		cbMsg = sprintf(szTraceMsg, "%s(%d):", lpszFunction, nLine);


	/* Append trace msg to prefix. */
	va_start(lpArgv, lpszFormat);
	cbMsg = vsprintf(szTraceMsg + cbMsg, lpszFormat, lpArgv);
	va_end(lpArgv);

	if (traceMsgOutputFn != NULL) {
		traceMsgOutputFn(((TUTRACELEVEL & TUERR) != 0), szTraceMsg);
	} else {
#ifndef _WIN32_WCE
	#ifdef WIN32
		OutputDebugString(szTraceMsg);
	#else /* Linux */
		fprintf(stdout, "%s", szTraceMsg);
	#endif /* WIN32 */
#else /* _WIN32_WCE */
		MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szTraceMsg, -1,
			szMsgW, strlen(szTraceMsg)+1);
		RETAILMSG(1, (szMsgW));
#endif /* _WIN32_WCE */
	}
}

void
wfd_capd_print_hexdata(char *heading, const uint8 *data, int dataLen)
{
	char dispBuf[WFDCAPD_DISPBUF_SIZE];
	char *dispBufPrefix = "          ";
	int i;

	if (strlen(heading) >= WFDCAPD_DISPBUF_SIZE)
		return;

	/* Print heading and data length */
	WFDCAPDLOG((TUTRACE_INFO, "%s: %d\n", heading, dataLen));

	/* Printf data in hex format */
	for (i = 0; i < dataLen; i++) {
		/* show 16-byte in one row */
		if (i % 16 == 0) {
			if (i > 0)
				WFDCAPDLOG((TUTRACE_INFO, "%s\n", dispBuf));
			strcpy(dispBuf, dispBufPrefix);
		}
		sprintf(&dispBuf[strlen(dispBuf)], "%02x ", data[i]);
	}
	if (strlen(dispBuf) > strlen(dispBufPrefix))
		WFDCAPDLOG((TUTRACE_INFO, "%s\n", dispBuf));
}

void
wfd_capd_log_mac(const char *heading, const uint8 *mac)
{
	#define WFDCAPD_DISPBUF_SIZE 512
	char mac_str[32];
	
	if (!mac)
		return;

	sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", 
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if (heading)
		WFDCAPDLOG((TUTRACE_INFO, "%s %s\n", heading, mac_str));
	else
		WFDCAPDLOG((TUTRACE_INFO, "%s\n", mac_str));
}

#endif  /* _TUDEBUGTRACE */
