/* P2P Library low level OS abstraction layer (OSL) definitions for Linux
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2posl_linux.h,v 1.16 2010-10-04 18:26:51 $
 */
#ifndef _P2POSL_LINUX_H_
#define _P2POSL_LINUX_H_

#include <pthread.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/if.h>
#include <linux/wireless.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum P2POSL_STATUS
{
	P2POSL_SUCCESS = 0,
	P2POSL_ERROR,
	P2POSL_TIMEOUT
} P2POSL_STATUS;

/* Thread handle */
typedef pthread_t p2posl_thread_t;

/* Mutex used for ensuring atomic data access */
typedef pthread_mutex_t p2posl_mutex_t;

/* Counting semaphore */
typedef struct p2posl_linux_sem_s {
	int				count;
	int				num_waiters;
	pthread_mutex_t	lock;
	pthread_cond_t	wait_until_count_nonzero;
	char			*dbg_name;
} p2posl_sem_t;

/* Create a semaphore */
p2posl_sem_t* p2posl_sem_create(const char* name);

/* Delete a semaphore */
int p2posl_sem_delete(p2posl_sem_t* sem);

/* Resets semaphore count. */
int p2posl_sem_reset(p2posl_sem_t *sem);

/* Increments semaphore count.  Unblocks one thread waiting on a sem_wait(). */
int p2posl_sem_signal(p2posl_sem_t *sem);

/* Decrements semaphore count. If count is < 0 then blocks the caller for up
 * to timeout_ms milliseconds or until another thread calls sem_give().
 * - If timeout_ms is 0, then waits forever.
 * - When unblocked due to a sem_signal(), returns P2POSL_SUCCESS.
 * - When unblocked due to a timeout, returns P2POSL_TIMEOUT.
 */
P2POSL_STATUS p2posl_sem_wait(p2posl_sem_t* sem, int timeout_ms,
	BCMP2P_LOG_LEVEL timeout_log_level);

/* Get time since process start in millisec */
unsigned int p2posl_gettime(void);

/* Diff newtime and oldtime in ms */
unsigned int p2posl_difftime(unsigned int newtime, unsigned int oldtime);

/* WL handle - contains WL driver instance data */
typedef struct p2posl_wl_hdl_s {
	int		wl_magic;	/* magic # to validate pointers to this struct */
#define P2PAPI_WL_HDL_MAGIC_NUMBER 0xe1c1	/* 57793 decimal */
	pthread_mutex_t ioctl_mutex;
	char    primary_if_name[IFNAMSIZ];
	char    discovery_if_name[IFNAMSIZ];
	char    connection_if_name[IFNAMSIZ];
	struct  ifreq primary_ifr;		/* ifr for primary (non-P2P) netif */
	struct  ifreq discovery_ifr;	/* ifr for virtual p2p discovery netif */
	struct  ifreq connection_ifr;	/* ifr for virtual p2p connection netif */
	int		primary_bssidx;
	int		discovery_bssidx;
	int		connection_bssidx;
	int     wl_sock;
} p2posl_wl_hdl_t;

#ifdef __cplusplus
}
#endif

#endif /* _P2POSL_LINUX_H_ */
