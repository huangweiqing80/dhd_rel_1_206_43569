/* P2P app OS supporting functions.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2papp_osl.h,v 1.1 2011-02-09 18:02:34 $
 */
#ifndef P2PAPP_OSL_H
#define P2PAPP_OSL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Init OS support functions */
int p2papp_osl_init(void);

/* Deinit OS support functions */
void p2papp_osl_deinit(void);

/* Read user entered string from STDIN with timeout. */
int p2papp_read_line(char *buf, int buf_size, int *bytes_read, long timeout_us);

/* Create event queue */
void p2papp_eventq_create(size_t eventsize);
/* Delete event queue */
void p2papp_eventq_delete(void);
/* Add event to event queue */
int p2papp_eventq_send(char *event);
/* Retrieve event from event queue */
int p2papp_eventq_receive(char *event);

/* Get the wireless network interface name */
int p2papp_get_wlan_ifname(char *dst_name, unsigned int max_name_len);

/* Initialze the Syslog Log output */
void p2papp_log_init(void);

/* Syslog Log output callback fn */
void p2papp_log_print(void *pCallbackContext, void *pReserved,
	BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp, char *logStr);

/* Execute a shell command */
void p2papp_system(const char *command);

/* Return current time string in format - "Wed Jun 30 21:49:08 1993\n" */
char *p2papp_ctime(void);

/* Syslog log timestamp base time */
extern struct timeval p2papp_time_base;
void p2papp_subtract_timestamp(struct timeval *a, struct timeval *b);



#ifndef TARGETENV_nucleusarm
#include <unistd.h>
/* Temp OSL definitions - replace these with #include <osl_ext.h> */
#define OSL_DELAY(us) usleep(us)
#else
#include <generic_osl.h>
#endif /* TARGETENV_nucleusarm */


#ifdef __cplusplus
}
#endif

#endif /* P2PAPP_OSL_H */
