/* 
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 */

#include <p2papp_queue.h>

void initP2PQueue(P2PQueue** pHead)
{
	*pHead = 0;
}


void deleteP2PQueue(P2PQueue** pHead)
{
	removeAllP2PQueue(pHead);
}

void pushFrontP2PQueue(P2PQueue** pHead, char* pcData, int size)
{
	P2PQueue* pCurrent = *pHead;
	if (*pHead == 0)
	{
		/* no entry */
		pCurrent = (P2PQueue*)malloc(sizeof(P2PQueue)); 
		pCurrent->pcData = (char*)malloc(size);
		memcpy(&pCurrent->pcData[0], &pcData[0], size);
		pCurrent->pNext = 0;
		*pHead = pCurrent;
	}
	else
	{
		P2PQueue* pNew = (P2PQueue*)malloc(sizeof(P2PQueue));
		pNew->pcData = (char*)malloc(size);
		memcpy(&pNew->pcData[0], &pcData[0],  size);
		pNew->pNext = pCurrent;
		*pHead = pNew;
	}
}

int popLastP2PQueue(P2PQueue** pHead, char* pcData, int size)
{
	int bFound = -1;

	if (*pHead)
	{
		P2PQueue* pCurrent = *pHead;
		P2PQueue* pNext = pCurrent->pNext;
		if (pNext == 0)
		{
			/* only one entry */
			memcpy(&pcData[0], &pCurrent->pcData[0], size);
			free(pCurrent->pcData);
			free(*pHead);
			*pHead = 0;
			bFound = 1;
		}
		else
		{
			while(pCurrent->pNext->pNext != 0)
			{
				pCurrent = pCurrent->pNext;
				pNext = pCurrent->pNext;
			}
			memcpy(&pcData[0],&pNext->pcData[0], size);
			free(pNext->pcData);
			free(pNext);
			pCurrent->pNext = 0;
			bFound = 1;
		}
	}
	return bFound;
}

int isEmptyP2PQueue(P2PQueue** pHead)
{
	int bEmpty = 0;
	bEmpty = *pHead == 0 ? 1: 0;
	return bEmpty;
}

void removeAllP2PQueue(P2PQueue** pHead)
{
	while (*pHead!=0)
	{
		P2PQueue* pCurrent = *pHead;
		P2PQueue* pNext = pCurrent->pNext;
		free(pCurrent->pcData);
		free(*pHead);
		*pHead = pNext;
	}
}
