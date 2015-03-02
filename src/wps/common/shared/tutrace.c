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
 * $Id: tutrace.c 470764 2014-04-16 08:40:23Z $
 */

#if defined(WIN32) || defined(WINCE)
#include <windows.h>
#endif
#if !defined(WIN32)
#include <stdarg.h>
#endif
#include <stdio.h>

#include <sys/time.h>
#include <time.h>

#include <ctype.h>
#include "tutrace.h"

static WPS_TRACEMSG_OUTPUT_FN traceMsgOutputFn = NULL;

#ifdef _TUDEBUGTRACE
static unsigned int wps_msglevel = TUTRACELEVEL;
#else
static unsigned int wps_msglevel = 0;
#endif

void
wps_set_traceMsg_output_fn(WPS_TRACEMSG_OUTPUT_FN fn)
{
	traceMsgOutputFn = fn;
}

unsigned int
wps_tutrace_get_msglevel()
{
	return wps_msglevel;
}

void
wps_tutrace_set_msglevel(unsigned int level)
{
	wps_msglevel = level;
}

#ifdef _TUDEBUGTRACE
void
print_traceMsg(int level, const char *lpszFile,
                   int nLine, char *lpszFormat, ...)
{
	char szTraceMsg[2000];
	int cbMsg = 0;
	va_list lpArgv;

#ifdef _WIN32_WCE
	TCHAR szMsgW[2000];
#endif
	char *TraceMsgPtr = szTraceMsg;

	if (!(TUTRACELEVEL & level)) {
		return;
	}

#ifdef __linux__
	if (wps_msglevel & TUTIME) {
		char time_stamp[80];
		struct timeval tv;
		struct timespec ts;
		struct tm lt;

		gettimeofday(&tv, NULL);
		ts.tv_sec = tv.tv_sec;
		ts.tv_nsec = tv.tv_usec * 1000;
		localtime_r(&ts.tv_sec, &lt);

		snprintf((char *)time_stamp, sizeof(time_stamp), "%02dh:%02dm:%02ds:%03ldms",
			lt.tm_hour, lt.tm_min, lt.tm_sec, (ts.tv_nsec/1000000));
		cbMsg = sprintf(TraceMsgPtr, "[@%s]: ", time_stamp);
		TraceMsgPtr += cbMsg;
	}
#endif /* __linux__ */

	/* Format trace msg prefix */
	if (traceMsgOutputFn != NULL)
		cbMsg = sprintf(TraceMsgPtr, "WPS: %s(%d):", lpszFile, nLine);
	else
		cbMsg = sprintf(TraceMsgPtr, "%s(%d):", lpszFile, nLine);
	TraceMsgPtr += cbMsg;

	/* Append trace msg to prefix. */
	va_start(lpArgv, lpszFormat);
	cbMsg = vsprintf(TraceMsgPtr, lpszFormat, lpArgv);
	va_end(lpArgv);
	TraceMsgPtr += cbMsg;

	if (traceMsgOutputFn != NULL) {
		traceMsgOutputFn(((TUTRACELEVEL & TUERR) != 0), szTraceMsg);
	} else {
#ifndef _WIN32_WCE
	#ifdef WIN32
		OutputDebugString(szTraceMsg);
	#else /* Linux */
		if (level & wps_msglevel)
			fprintf(stdout, "%s", szTraceMsg);
	#endif /* WIN32 */
#else /* _WIN32_WCE */
		MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szTraceMsg, -1,
			szMsgW, strlen(szTraceMsg)+1);
		RETAILMSG(1, (szMsgW));
#endif /* _WIN32_WCE */
	}
}

/* Just print the message, no msglevel check */
static void
WPS_Print(char *lpszFormat, ...)
{
	char szTraceMsg[2000];
	int cbMsg = 0;
	va_list lpArgv;

#ifdef _WIN32_WCE
	TCHAR szMsgW[2000];
#endif
	char *TraceMsgPtr = szTraceMsg;

	/* Append trace msg to prefix. */
	va_start(lpArgv, lpszFormat);
	cbMsg = vsprintf(TraceMsgPtr, lpszFormat, lpArgv);
	va_end(lpArgv);
	TraceMsgPtr += cbMsg;

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
#endif /* _TUDEBUGTRACE */

int
WPS_HexDumpAscii(unsigned int level, char *title, unsigned char *buf, unsigned int len)
{
#ifdef _TUDEBUGTRACE
	int i, llen;
	const unsigned char *pos = buf;
	const int line_len = 16;

	if ((wps_msglevel & level) == 0)
		return -1;

	WPS_Print("WPS: %s : hexdump_ascii(len=%lu):\n", title, (unsigned long) len);
	while (len) {
		llen = len > line_len ? line_len : len;
		WPS_Print("    ");
		for (i = 0; i < llen; i++)
			WPS_Print(" %02x", pos[i]);
		for (i = llen; i < line_len; i++)
			WPS_Print("   ");
		WPS_Print("   ");
		for (i = 0; i < llen; i++) {
			if (isprint(pos[i]))
				WPS_Print("%c", pos[i]);
			else
				WPS_Print("*");
		}
		for (i = llen; i < line_len; i++)
			WPS_Print(" ");
		WPS_Print("\n");
		pos += llen;
		len -= llen;
	}
#endif /* _TUDEBUGTRACE */

	return 0;
}
