/*
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 * $Id: wfi_utils.c,v 1.4 2010-05-08 02:47:48 $
 */

#include "wfi_api.h"
#include "wfi_utils.h"
#include "wlioctl.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <ctype.h>


#ifdef DEBUG
#define DBGPRINT(x) printf x
#else
#define DBGPRINT(x)
#endif


#ifndef __user
#define __user
#endif
#define SIOCETHTOOL     0x8946          /* Ethtool interface */ 
#define ETHTOOL_BUSINFO_LEN     32

#define DEV_TYPE_LEN	4
#define ETHTOOL_GDRVINFO	0x00000003 /* Get driver info. */
#define ETHTOOL_BUSINFO_LEN     32

struct ethtool_drvinfo {
	u_int32_t	cmd;
	char	driver[32];	/* driver short name, "tulip", "eepro100" */
	char	version[32];	/* driver version string */
	char	fw_version[32];	/* firmware version string, if applicable */
	char	bus_info[ETHTOOL_BUSINFO_LEN];	/* Bus info for this IF. */
				/* For PCI devices, use pci_dev->slot_name. */
	char	reserved1[32];
	char	reserved2[16];
	u_int32_t	n_stats;	/* number of u64's from ETHTOOL_GSTATS */
	u_int32_t	testinfo_len;
	u_int32_t	eedump_len;	/* Size of data from ETHTOOL_GEEPROM (bytes) */
	u_int32_t	regdump_len;	/* Size of data from ETHTOOL_GREGS (bytes) */
};


int
wfi_get_dev_type(char *name, void *buf, int len)
{
	int s;
	int ret = 0;
	struct ifreq ifr;
	struct ethtool_drvinfo info;

	/* open socket to kernel */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
	{
		/* get device type */
		memset(&info, 0, sizeof(info));
		info.cmd = ETHTOOL_GDRVINFO;
		ifr.ifr_data = (caddr_t)&info;
		strncpy(ifr.ifr_name, name, IFNAMSIZ);
		if ((ret = ioctl(s, SIOCETHTOOL, &ifr)) < 0) {
			*(char *)buf = '\0';
		}
		else
			strncpy(buf, info.driver, len);

		close(s);
	}
	return ret;
}


static int
get_interface_name(struct ifreq* ifr)
{
	char proc_net_dev[] = "/proc/net/dev";
	FILE *fp;
	char buf[1000], *c, *name;
	char dev_type[DEV_TYPE_LEN];
	int ret = -1;

	ifr->ifr_name[0] = '\0';

	if (!(fp = fopen(proc_net_dev, "r")))
		return ret;

	/* eat first two lines */
	if (!fgets(buf, sizeof(buf), fp) ||
	    !fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return ret;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		c = buf;
		while (isspace(*c))
			c++;
		if (!(name = strsep(&c, ":")))
			continue;
		strncpy(ifr->ifr_name, name, IFNAMSIZ);
		if (wfi_get_dev_type(name, dev_type, DEV_TYPE_LEN) >= 0 &&
			(!strncmp(dev_type, "wl", 2) || !strncmp(dev_type, "dhd", 3)))
		{
				ret = 0;
				break;
		}
		ifr->ifr_name[0] = '\0';
	}

	fclose(fp);
	return ret;
}


int
wfi_get_interface_name(char* intf_name)
{
	struct ifreq ifr;
	int ret;

	ret = get_interface_name(&ifr);
	if (ret == 0 && intf_name)
	{
		strncpy(intf_name, ifr.ifr_name, IFNAMSIZ);
		intf_name[IFNAMSIZ] = '\0';
	}
	return ret;
}

int
wfi_ioctl(int cmd, void *buf, int len, bool set)
{
	int skfd;		/* generic raw socket desc.	*/
	struct ifreq ifr;
	wl_ioctl_t ioc;
	int ret = -1;

	ret = get_interface_name(&ifr);
	if (ret == 0)
	{
	    /* Create a channel to the NET kernel. */
	    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
	    {
			/* do it */
			ioc.cmd = cmd;
			ioc.buf = buf;
			ioc.len = len;
			ioc.set = set;
			ifr.ifr_data = (caddr_t) &ioc;
			if ((ret = ioctl(skfd, SIOCDEVPRIVATE, &ifr)) < 0)
			{
				DBGPRINT(("ioctl(%d) returned with errno %d (%s)\n",
					cmd, errno, strerror(errno)));
				if (cmd != WLC_GET_MAGIC)
					ret = -1;
			}
			/* cleanup */
			close(skfd);
	    }
	    else
			ret = -1; /* socket err */
	}
	return ret;
}

int
wfi_get(int cmd, void *buf, int len)
{
	return wfi_ioctl(cmd, buf, len, FALSE);
}

int
wfi_set(int cmd, void *buf, int len)
{
	return wfi_ioctl(cmd, buf, len, TRUE);
}


/*
 * format an iovar buffer
 */
static uint
wfi_iovar_mkbuf(char *name, char *data, uint datalen, char *buf, uint buflen, int *perr)
{
	uint len;

	len = strlen(name) + 1;

	/* check for overflow */
	if ((len + datalen) > buflen) {
		*perr = WFI_RET_ERR_UNKNOWN;
		return 0;
	}

	strcpy(buf, name);

	/* append data onto the end of the name string */
	if (datalen > 0)
		memcpy(&buf[len], data, datalen);

	len += datalen;

	*perr = 0;
	return len;
}

int
wfi_iovar_getint(char *name, int *var)
{
	int len;
	char ibuf[DHD_IOCTL_SMLEN];
	int error;

	len = wfi_iovar_mkbuf(name, NULL, 0, ibuf, sizeof(ibuf), &error);
	if (error)
	{
	    return error;
	}

	if ((error = wfi_get(WLC_GET_VAR, ibuf, sizeof(ibuf))) < 0)
	{
		DBGPRINT(("wfi_iovar_getint : IOVAR[%s] execution failed.\n", name));
	    return error;
	}

	memcpy(var, ibuf, sizeof(int));

	return 0;
}

int
wfi_iovar_getbuf(char *name, void *buf, int buflen)
{
	char *ibuf;
	int error;
	uint len;
	int buf_len =  (buflen + strlen(name)+1 + 0x3) & ~0x3;

	ibuf = (char *)malloc(buf_len);
	len = wfi_iovar_mkbuf(name, NULL, 0, ibuf, buf_len, &error);
	error = wfi_get(WLC_GET_VAR, (void *)ibuf, buf_len);
	if (!error)
		memcpy(buf, ibuf, buflen);
	else
		DBGPRINT(("wfi_iovar_getbuf: IOVAR[%s] execution failed. error=%d\n", name, error));

	free (ibuf);
	return error;
}

int
wfi_iovar_setbuf(char *iovar, void *param, int paramlen)
{
	int err;
	int iolen;
	char *bufptr;
	int buf_len = (paramlen + strlen(iovar)+1 + 0x3) & ~0x3;

	bufptr = (char *)malloc(buf_len);
	iolen = wfi_iovar_mkbuf(iovar, param, paramlen, bufptr, buf_len, &err);
	if (err)
	{
		free (bufptr);
		return err;
	}

	err = wfi_set(WLC_SET_VAR, bufptr, iolen);
	if (err)
	{
		DBGPRINT(("wfi_iovar_setbuf : IOVAR[%s] execution failed.\n", iovar));
	}
	free (bufptr);
	return err;
}

int
wfi_iovar_setint(char *name, int var)
{
	int len;
	char ibuf[DHD_IOCTL_SMLEN];
	int error;

	len = wfi_iovar_mkbuf(name, (char *)&var, sizeof(var), ibuf, sizeof(ibuf), &error);
	if (error)
		return error;

	if ((error = wfi_set(WLC_SET_VAR, &ibuf, len)) < 0)
	{
		DBGPRINT(("wfi_iovar_setint : IOVAR[%s] execution failed.\n", name));
	    return error;
	}

	return 0;
}
char *
wfi_ether_ntoa(const struct ether_addr *ea, char *buf)
{
	static const char template[] = "%02x:%02x:%02x:%02x:%02x:%02x";
	snprintf(buf, 18, template,
		ea->octet[0]&0xff, ea->octet[1]&0xff, ea->octet[2]&0xff,
		ea->octet[3]&0xff, ea->octet[4]&0xff, ea->octet[5]&0xff);
	return (buf);
}


uint32 wfi_htonl(uint32 intlong)
{
	return htonl(intlong);
}

uint16 wfi_htons(uint16 intshort)
{
	return htons(intshort);
}

uint16 wfi_htons_ptr(uint8 * in, uint8 * out)
{
	uint16 v;
	uint8 *c;
	c = (uint8 *)&v;
	c[0] = in[0];
	c[1] = in[1];
	v = htons(v);
	out[0] = c[0];
	out[1] = c[1];
	return v;
}

uint32 wfi_htonl_ptr(uint8 * in, uint8 * out)
{
	uint32 v;
	uint8 *c;
	c = (uint8 *)&v;
	c[0] = in[0];
	c[1] = in[1];
	c[2] = in[2];
	c[3] = in[3];
	v = htonl(v);
	out[0] = c[0];
	out[1] = c[1];
	out[2] = c[2];
	out[3] = c[3];
	return v;
}

uint32 wfi_ntohl(uint8 *a)
{
	uint32 v;
	v = (a[0] << 24) + (a[1] << 16) + (a[2] << 8) + a[3];
	return v;
}

uint16 wfi_ntohs(uint8 *a)
{
	uint16 v;
	v = (a[0]<<8) + a[1];
	return v;
}
