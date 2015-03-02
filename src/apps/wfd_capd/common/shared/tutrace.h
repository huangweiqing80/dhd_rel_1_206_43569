/*
 * TuTrace
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

#ifndef _WFDCAPDLOG_H
#define _WFDCAPDLOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <typedefs.h>

typedef void (* TRACEMSG_OUTPUT_FN)(bool is_err, char *trace_msg);
void wfd_capd_redirect_log(TRACEMSG_OUTPUT_FN fn);


#ifdef _TUDEBUGTRACE

#define TUTRACELEVEL    (TUINFO | TUERR)

/* trace levels */
#define TUINFO  0x0001
#define TUERR   0x0010

#define TUTRACE_ERR        TUERR, __FUNCTION__, __LINE__
#define TUTRACE_INFO       TUINFO, __FUNCTION__, __LINE__

void wfd_capd_print_trace_msg(int level, const char *lpszFile,
	int nLine, char *lpszFormat, ...);

void wfd_capd_print_hexdata(char *heading, const uint8 *data, int dataLen);

void wfd_capd_log_mac(const char *heading, const uint8 *mac);

#define WFDCAPDLOG(VARGLST)		wfd_capd_print_trace_msg VARGLST
#define WFDCAPDLOG_HEX(ARGLST)	wfd_capd_print_hexdata ARGLST
#define WFDCAPDLOG_MAC(ARGLST)	wfd_capd_log_mac ARGLST

#else

#define WFDCAPDLOG(VARGLST)     ((void)0)
#define WFDCAPDLOG_HEX(ARGLST)  ((void)0)
#define WFDCAPDLOG_MAC(ARGLST)	((void)0)

#endif /* _TUDEBUGTRACE */

#ifdef __cplusplus
}
#endif

#endif /* _TUTRACE_H */
