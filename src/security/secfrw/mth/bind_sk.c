/*****************************************************************************
 * Binding stack definitions
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *****************************************************************************
*/

#include <stdio.h>

#include <bind_sk.h>
#include <bind_skp.h>


void
bind_sk_init(struct bind_sk *sk, int (*cb)(void *, void *, int), void *arg)
{
	sk->next = NULL;
	sk->cb = cb;
	sk->arg = arg;
}

void
bind_sk_ins(struct bind_sk **top, struct bind_sk *elt)
{
	if (NULL != *top)
		elt->next = *top;
	*top = elt;
}

struct bind_sk *
bind_sk_del(struct bind_sk **top, struct bind_sk *elt)
{
	while (*top != elt && NULL != *top)
		top = &(*top)->next;
	if (NULL != *top) {
		*top = elt->next;
		elt->next = NULL;
		return elt;
	}
	return NULL;
}

/*
 * dispatch algorithms
*/

#include <disp_alg.h>


extern int
bind_sk_dispatch_alg(void *arg, void *data, int len)
{
	int consumed;
	struct bind_sk *sk;

	/* dispatch to everyone until someone consumes the data */
	for (consumed=0, sk=arg;
		 NULL != sk && !consumed;
		 sk=sk->next)
	{
		consumed = (*sk->cb)(sk->arg, data, len);
	}

	return consumed;
}
