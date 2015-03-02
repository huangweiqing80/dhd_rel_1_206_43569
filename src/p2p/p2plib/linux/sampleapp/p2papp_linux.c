/* P2P app RTOS supporting functions.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2papp_linux.c,v 1.1 2011-02-09 18:02:34 $
 */
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <net/if.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <syslog.h>


/* P2P API */
#include <BcmP2PAPI.h>
#include <BcmP2PDbg.h>
#include <p2p_app.h>
#include <p2papp_osl.h>
#include "p2plib_osl.h"


#if defined(P2P_USE_POSIX_MQUEUE)
#include <mqueue.h>
#endif /* P2P_USE_POSIX_MQUEUE */

#ifndef P2P_USE_POSIX_MQUEUE
#include <p2papp_queue.h>
#include <sys/socket.h>
static P2PQueue* mq;
static pthread_mutex_t mq_mutex;
#else
#define EVENT_QUEUE_NAME		"/p2pappevent"
#define EVENT_QUEUE_DEPTH		16
static mqd_t mq;
#endif /* !P2P_USE_POSIX_MQUEUE */
static int msgsize = 0;

#define P2P_CONSOLE_LOG(a)		p2papp_console_log a
extern int p2papp_console_log(char *fmt, ...);

/* Init OS support functions */
int
p2papp_osl_init(void)
{
	return BCMP2P_SUCCESS;
}

/* Deinit OS support functions */
void
p2papp_osl_deinit(void)
{
}

/****************************************************************************
* Function:   p2papp_read_line
*
* Purpose:    Read user entered string from STDIN with timeout.
*
* Parameters: buf        (out) Buffer to store user entered string.
*             buf_size   (in)  Size of 'buf'.
*             bytes_read (out) Number of bytes read.
*             timeout_us (in)  Timeout value(usec) to wait for user input.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
int
p2papp_read_line(char *buf, int buf_size, int *bytes_read, long timeout_us)
{
	fd_set		read_set;
	int		retval;
	struct timeval	tv;

	*bytes_read = 0;

	memset(&tv, 0, sizeof(tv));
	tv.tv_usec = timeout_us;

	/* Watch stdin (fd 0) to see when it has input. */
	FD_ZERO(&read_set);
	FD_SET(0, &read_set);

	retval = select(1, &read_set, NULL, NULL, &tv);
	if (retval == -1) {
		P2P_CONSOLE_LOG(("%s: select read ERROR %d\n", __FUNCTION__, errno));
		if (errno != EINTR)
			return (BCMP2P_ERROR);
	}
	else if (retval != 0) {
		*bytes_read = read(0, buf, buf_size);
		buf[*bytes_read - 1] = '\0';
	}

	return (BCMP2P_SUCCESS);
}

/* Create event queue */
void p2papp_eventq_create(size_t eventsize)
{
#ifndef P2P_USE_POSIX_MQUEUE
	pthread_mutex_init(&mq_mutex, NULL);
	initP2PQueue(&mq);
	msgsize = eventsize;
#else
	struct mq_attr attr;

	/* event queue attributes */
	memset(&attr, 0, sizeof(attr));
	attr.mq_maxmsg = EVENT_QUEUE_DEPTH;
	attr.mq_msgsize = eventsize;
	msgsize = eventsize;

	/* create event queue */
	mq = mq_open(EVENT_QUEUE_NAME,
		O_RDWR | O_NONBLOCK | O_CREAT,
		S_IRWXU | S_IRWXG, &attr);
	if (mq == (mqd_t)-1)
		printf("p2papp: failed to create event queue\n");
#endif /* !P2P_USE_POSIX_MQUEUE */
}

/* Delete event queue */
void p2papp_eventq_delete(void)
{
#ifndef P2P_USE_POSIX_MQUEUE
		pthread_mutex_lock(&mq_mutex);
		deleteP2PQueue(&mq);
		pthread_mutex_unlock(&mq_mutex);
		pthread_mutex_destroy(&mq_mutex);
#else
		mq_close(mq);
		mq_unlink(EVENT_QUEUE_NAME);
#endif /* !P2P_USE_POSIX_MQUEUE */
}

/* Add event to event queue */
int p2papp_eventq_send(char *event)
{
	int rc = 0;
#ifndef P2P_USE_POSIX_MQUEUE
	pthread_mutex_lock(&mq_mutex);
	pushFrontP2PQueue(&mq, event, msgsize);
	pthread_mutex_unlock(&mq_mutex);
#else
	rc = mq_send(mq, event, msgsize, 0);
#endif /* !P2P_USE_POSIX_MQUEUE */

	return rc;
}

/* Retrieve event from event queue */
int p2papp_eventq_receive(char *event)
{
#ifdef P2P_USE_POSIX_MQUEUE
	unsigned int msg_prio;
#endif
	int rc;

#ifndef P2P_USE_POSIX_MQUEUE
	pthread_mutex_lock(&mq_mutex);
	rc = popLastP2PQueue(&mq, event, msgsize);
	pthread_mutex_unlock(&mq_mutex);
#else
	rc = mq_receive(mq, event, msgsize, &msg_prio);
#endif /* !P2P_USE_POSIX_MQUEUE */

	return rc;
}

static int
p2papp_get_dev_type(char *name, void *buf, int len)
{
	int s;
	int ret;
	struct ifreq ifr;
	struct ethtool_drvinfo info;

	/* open socket to kernel */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		printf("%s: socket error\n", __FUNCTION__);
		return (-1);
	}

	/* get device type */
	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (caddr_t)&info;
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	if ((ret = ioctl(s, SIOCETHTOOL, &ifr)) < 0) {

		/* print a good diagnostic if not superuser */
		if (errno == EPERM)
		{
			printf("%s: ioctl error\n", __FUNCTION__);
			close(s);
			return (-1);
		}

		*(char *)buf = '\0';
	} else {
		strncpy(buf, info.driver, len);
	}

	close(s);
	return ret;
}

/* Get the wireless network interface name */
int
p2papp_get_wlan_ifname(char *dst_name, unsigned int max_name_len)
{
#define P2PAPP_DEV_TYPE_LEN 3
	char proc_net_dev[] = "/proc/net/dev";
	FILE *fp;
	char buf[1000], *c, *name;
	char dev_type[P2PAPP_DEV_TYPE_LEN];
	int status;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));

	if (!(fp = fopen(proc_net_dev, "r")))
	{
		printf("%s: fopen error\n", __FUNCTION__);
		return -1;
	}

	/* eat first two lines */
	if (!fgets(buf, sizeof(buf), fp) ||
		!fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		c = buf;
		while (isspace(*c))
		c++;
		if (!(name = strsep(&c, ":")))
			continue;
		strncpy(ifr.ifr_name, name, IFNAMSIZ);
		/* filter the virtual interfaces (wl0.1) etc, but accept
		 *  interface ethX, wlanX etc
		 */
		if ((!(!strncmp(name, "wl", 2) && (strchr(name, '.') != NULL))) &&
			p2papp_get_dev_type(name, dev_type, P2PAPP_DEV_TYPE_LEN) >= 0 &&
			!strncmp(dev_type, "wl", 2))
		{
			strncpy(dst_name, name, max_name_len);
			break;
		}
		ifr.ifr_name[0] = '\0';
	}

	printf("%s: wl ifname=%s\n", __FUNCTION__, ifr.ifr_name);
	if (ifr.ifr_name[0] == '\0')
	{
		status = -1;
	}
	else
	{
		status = 0;
	}

	fclose(fp);
	return status;
}

/* Syslog log timestamp base time */
struct timeval p2papp_time_base;

/* Subtract timetamp B from timestamp A (A = A - B) */
void
p2papp_subtract_timestamp(struct timeval *a, struct timeval *b)
{
	if (a->tv_usec < b->tv_usec) {
		a->tv_sec--;
		a->tv_usec += 1000000L;
	}
	a->tv_usec -= b->tv_usec;
	a->tv_sec -= b->tv_sec;
}

/* Initialze the Syslog Log output */
void
p2papp_log_init(void)
{
	/* Record the starting timestamp for our p2p_tslog() timestamps */
	gettimeofday(&p2papp_time_base, NULL);
}

/* Syslog Log output callback fn */
void
p2papp_log_print(void *pCallbackContext, void *pReserved,
	BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp, char *logStr)
{
	struct timeval now;
	char separator;

	(void) pCallbackContext;
	(void) pReserved;

	if (level == BCMP2P_LOG_ERR)
		separator = 'e';
	else if (level == BCMP2P_LOG_INFO)
		separator = 'i';
	else if (level == BCMP2P_LOG_VERB)
		separator = 'v';
	else
		separator = '.';

	gettimeofday(&now, NULL);
	p2papp_subtract_timestamp(&now, &p2papp_time_base);
	syslog(LOG_INFO, "%05lu%c%03lu %s", now.tv_sec % 10000, separator,
		now.tv_usec / 1000, logStr);
}

/* Execute a shell command */
void p2papp_system(const char *command)
{
	system(command);
}

/* Return current time string in format - "Wed Jun 30 21:49:08 1993\n" */
char *p2papp_ctime(void)
{
	struct timeval timeofday;

	/* Print the date to allow correlating the HSL logs with the UCC logs */
	gettimeofday(&timeofday, NULL);
	return ctime(&timeofday.tv_sec);
}
