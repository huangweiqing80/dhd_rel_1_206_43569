/* 
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wfi_utils.h,v 1.3 2010-03-13 05:19:12 $
 */

#ifndef _WFI_UTILS_H_
#define _WFI_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <wlioctl.h>

#define htod32(i) i
#define htod16(i) i
#define dtoh32(i) i
#define dtoh16(i) i
#define htodchanspec(i) i
#define dtohchanspec(i) i

#define DEV_TYPE_LEN 4 /* length for devtype 'dhd' */ 
#define DHD_IOCTL_SMLEN         256             /* "small" length ioctl buffer required */ 

extern int wfi_set(int IOCTL, void *buf, int len);
extern int wfi_iovar_setbuf(char *name, void *buf, int len);
extern int wfi_iovar_setint(char *name, int val);

extern int wfi_get(int IOCTL, void *buf, int len);
extern int wfi_iovar_getbuf(char *name, void *buf, int len);
extern int wfi_iovar_getint(char *name, int *val);

extern int wfi_ioctl(int cmd, void *buf, int len, uint8 set);
extern char * wfi_ether_ntoa(const struct ether_addr *ea, char *buf);

extern uint32 wfi_htonl(uint32 intlong);
extern uint16 wfi_htons(uint16 intshort);
extern uint16 wfi_htons_ptr(uint8 * in, uint8 * out);
extern uint32 wfi_htonl_ptr(uint8 * in, uint8 * out);
extern uint32 wfi_ntohl(uint8 *a);
extern uint16 wfi_ntohs(uint8 *a);
extern int wfi_get_interface_name(char* intf_name);
#ifdef __cplusplus
}
#endif

#endif /* _WFI_UTILS_H_ */
