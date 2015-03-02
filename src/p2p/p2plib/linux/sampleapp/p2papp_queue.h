/* 
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 */

#ifndef ANDROID_P2PAPPQUEUE_H
#define ANDROID_P2PAPPQUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

	typedef struct _P2PQueue
	{
		char* pcData;
		struct _P2PQueue* pNext;
	} P2PQueue;

	/* Initialize the Queue */
	void initP2PQueue(P2PQueue** pHead);

	/* Delete queue and clean up */
	void deleteP2PQueue(P2PQueue** pHead);

	/* Add data to the head of queue */ 
	void pushFrontP2PQueue(P2PQueue** pHead, char* pcData, int size);

	/* Get the data using FIFO */
	int popLastP2PQueue(P2PQueue** pHead, char* pcData, int size);

	/* Check whether queue is empty */
	int isEmptyP2PQueue(P2PQueue** pHead);

	/* Remove all data from the queue */
	void removeAllP2PQueue(P2PQueue** pHead);

#ifdef __cplusplus
}
#endif

#endif // ANDROID_P2PAPPQUEUE_H
