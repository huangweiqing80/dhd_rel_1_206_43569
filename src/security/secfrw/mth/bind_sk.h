/*****************************************************************************
 * Bind stack declarations
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

#if !defined(__BIND_SK_H__)
#define __BIND_SK_H__


struct bind_sk;

extern void
bind_sk_init(struct bind_sk *sk, int (*cb)(void *, void *, int), void *arg);

extern void
bind_sk_ins(struct bind_sk **top, struct bind_sk *elt);

extern struct bind_sk *
bind_sk_del(struct bind_sk **top, struct bind_sk *elt);


#endif /* !defined(__BIND_SK_H__) */
