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
 * $Id: testosl.c,v 1.3 2009-09-10 20:48:39 $
 */

#include <windows.h>
#include <time.h>
#include <stdio.h>

static CRITICAL_SECTION cs;

unsigned long OslGetSeconds() {
	return (unsigned long) time(NULL);
}

void OslHandleAssert(char *fileName, int Line) {
	printf("Assert failed: File %s, Line %d\n", fileName, Line);
	exit(1);
}

void *OslCreateLock() {
	InitializeCriticalSection( &cs );

	return (void *) &cs;
}

void OslDeleteLock(void *Lock) {
	DeleteCriticalSection( Lock );
}

void OslLock(void *Lock) {
	EnterCriticalSection( Lock );

}

void OslUnlock(void *Lock) {
	LeaveCriticalSection( Lock );
}
