/*
 * Broadcom DHCP Server
 * OS specific routines
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: linuxosl.c,v 1.3 2009-09-10 23:30:20 $
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "dhcpdebug.h"

static pthread_mutex_t lock_mutex;


unsigned long OslGetSeconds() {
	return (unsigned long) time(NULL);
}

void OslHandleAssert(char *fileName, int Line) {
	printf("Assert failed: File %s, Line %d\n", fileName, Line);
	exit(1);
}


void *OslCreateLock() {
	if (0 != pthread_mutex_init(&lock_mutex, NULL)) {
		DHCPLOG(("OslCreateLock: mutex init error\n"));
		return (void *) NULL;
	}
	return &lock_mutex;
}

void OslDeleteLock(void *Lock) {
	if (Lock) {
		pthread_mutex_destroy((pthread_mutex_t*) Lock);
	}
}

void OslLock(void *Lock) {
	int ret;

	if (Lock) {
		ret = pthread_mutex_lock((pthread_mutex_t*) Lock);
		if (ret < 0) {
			DHCPLOG(("OslLock: error %d\n", ret));
		}
	}
}

void OslUnlock(void *Lock) {
	int ret;

	if (Lock) {
		pthread_mutex_unlock((pthread_mutex_t*) Lock);
		if (ret < 0) {
			DHCPLOG(("OslUnlock: error %d\n", ret));
		}
	}
}

