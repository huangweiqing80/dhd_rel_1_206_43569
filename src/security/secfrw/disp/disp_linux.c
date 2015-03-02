/*
 * disp_linux.c
 * Linux specific dispatcher functions
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: disp_linux.c,v 1.6 2010-12-11 00:06:34 $
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <errno.h>

#include <typedefs.h>
#include <bcmendian.h>
#include <bcmsec_types.h>
#include <proto/ethernet.h>
#include <proto/802.11.h>
#include <bcmseclib_api.h>
#include <dispatcher.h>

#include <bcm_osl.h>
#include <bcm_lbuf.h>
#include <bcm_llist.h>
#include <debug.h>
#include <bcmseclib_timer.h>


/* forward */
static bool disp_ctx_cmpfn(void * lh, void *arg);

#define RECV_PKT_TOTAL_LEN	1800

/* Local to this file:
 * Store registration info here
 * When descriptor becomes readable
 * consult table for function to call
 */
typedef struct fwd_list {
	struct fwd_list *next;
	int (*pdispfn)(void *ctx, void *pkt, int len); /* forward pkt */
	void *ctx;	/* arg for pdispfn */
} fwd_list_t;

typedef struct disp_tbl {
	struct disp_tbl *next;
	int fd;
	char ifname[IFNAMSIZ];
	uint16 proto;
	fwd_list_t *fwdlist;	/* list of cb fn's to call when we've got a packet */

	/* Two levels of function calls:
	 * function to read from descriptor
	 * function to forward message to processing code elsewhere
	 */
	void (*precvfn)(void *arg);	/* read from descriptor */
	void (*pcfgdispfn)(void *pkt);			/* cfg packets ONLY */

}disp_tbl_t;

static disp_tbl_t *dispatch_table;

/* Set true when desired to terminate select loop */
bool disp_quit_loop;

/* Set true when dispatching loop needs to be interrupted */
bool disp_intr_loop;

/* Stuff for handling SOCK_DGRAM sockets
 * Used in setting up the cfg path
 */
#define DISP_CFG_UDP_PORT		38000

static
struct sock_cfg {
	int client_fd;
	int server_fd;
	struct sockaddr_in to_addr;
}disp_cfg_sock;

/* forward decls */
int open_socket(void *ifarg, uint16 proto);
void disp_recv_msg(void *arg);
int disp_open_cfgpath(struct sock_cfg *pcfg);
void disp_recv_cfgmsg(void *arg);
void disp_close_cfgpath(struct sock_cfg *pcfg);
int open_datagram_server_socket();
int open_datagram_client_socket();

/* Success: Returns a handle used for subsequent de-registration
 * Failure: returns NULL
 * Registers a callback fn for receiving frames of protocol <proto>
 * on interface <ifname>.
 */

void * disp_register(void *ctx, char *ifname, PDISPFN dfn, int type )
{
	uint16 proto;

	switch (type) {
		case DISP_REG_EVENTS:
			proto = ETHER_TYPE_BRCM;
			return disp_register_proto(ctx, ifname, dfn, proto);
			break;
		case DISP_REG_8021X:
			proto = ETHER_TYPE_802_1X;
			return disp_register_proto(ctx, ifname, dfn, proto);
			break;
		/* more to come */
		default:
			PRINT_ERR(("%s: unrecognized type %d for registration\n",
				__FUNCTION__, type));
			return NULL;
			break;
	}
	/* not reached */
}
/* Changes forthcoming:
 * Only register one socket per protocol
 * Create a list of registrants per protocol
 * The first registrant causes the socket to be created and gets put on the
 * list. Subsequent registrants just get put on the list.
 *
 * CB function for any particular socket will, when it's underlying socket
 * has packets, walk that list and call each registered function in turn.
 *
 * De-registration is the reverse:
 * just delete registrants from list until the last one is requested to be
 * deleted at which time the socket will be closed too.
 */
void *
disp_register_proto(void *ctx, char *ifname, PDISPFN fn, uint16 proto)
{
	disp_tbl_t * new, *ptbl;
	int fd;
	struct ifreq ifr;
	fwd_list_t *pnewfl;

	if (dispatch_table == NULL) {
		PRINT_ERR(("%s: dispatcher not initialized!\n", __FUNCTION__));
		return NULL;
	}

	/* Begin NEW */
	/* Walk the dispatch table. If ifname, proto are already registered
	 * we won't open another socket, we'll only add the new registrant to
	 * our dispatch list
	 */

	for (ptbl = dispatch_table; ptbl; ptbl = ptbl->next) {
		/* found: add to ptbl->fwdlist and return */
		if (proto == ptbl->proto && !strcmp(ptbl->ifname, ifname)) {

			pnewfl = (fwd_list_t *)malloc(sizeof(fwd_list_t));
			if (!pnewfl) {
				PRINT_ERR(("%s: failed to allocate new fwdlist member\n",
				__FUNCTION__));
				return NULL;
			}
			memset(pnewfl, 0, sizeof(fwd_list_t));

			pnewfl->pdispfn = fn;
			pnewfl->ctx = ctx;
			pnewfl->next = ptbl->fwdlist;
			ptbl->fwdlist = pnewfl;
			return ptbl;

		}

	}

	/* NOT found: create a socket etc */


	/* End NEW */

	/* Need a new socket */
	/* open raw socket for proto */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	fd = open_socket(&ifr, proto);
	if (fd < 0) {
		PRINT_ERR(("%s: Failed to open raw socket for ifname %s proto %d\n",
					__FUNCTION__, ifname, proto));
		return NULL;
	}

	/* allocate new member for dispatch_table */
	new = (disp_tbl_t *)malloc(sizeof(disp_tbl_t));
	if (new == NULL) {
		PRINT_ERR((
			"%s: Failed to allocate new dispatch table member, bailing\n",
			__FUNCTION__));
		return NULL;
	}
	pnewfl = (fwd_list_t *)malloc(sizeof(fwd_list_t));
	if (pnewfl == NULL) {
		PRINT_ERR((
			"%s: Failed to allocate new dispatch table member fwdlist, bailing\n",
			__FUNCTION__));
		return NULL;
	}


	memset(new, 0, sizeof(disp_tbl_t));
	memset(pnewfl, 0, sizeof(fwd_list_t));
	pnewfl->ctx = ctx;
	pnewfl->pdispfn = fn;
	new->fwdlist = pnewfl;

	new->fd = fd;
	new->precvfn = disp_recv_msg;
	strncpy(new->ifname, ifname, IFNAMSIZ);
	new->proto = proto;

	/* add to dispatch_table */
	new->next = dispatch_table;
	dispatch_table = new;

	/* Points to a dispatch table entry which may have multiple registrants */
	return new;
}

/* The handle may point to a member with multiple registrants
 * The ctx arg is for disambiguation.
 */
/* Returns success (zero) or failure (non-zero) */
int disp_unregister(void *handle, void *ctx)
{
	disp_tbl_t *pprev, *plist;
	disp_tbl_t *pcand = (disp_tbl_t *)handle;
	disp_tbl_t **head = &dispatch_table;
	fwd_list_t *pfl = NULL;

	PRINT(("%s: request to delete handle %p ctx %p\n", __FUNCTION__, handle, ctx));
	if (dispatch_table == NULL) {
		PRINT_ERR(("%s: dispatcher not initialized!\n", __FUNCTION__));
		return -1;
	}

	/* walk the list, find the entry */
	for (plist = *head, pprev = NULL; plist; ) {
		if (plist == pcand) {

			/* walk the fwd table list, find ours */
			pfl = bcm_llist_del_membercmp(&pcand->fwdlist, ctx, disp_ctx_cmpfn);
			if (pfl == NULL) {
				PRINT_ERR(("%s: requested to delete ctx %p handle %p: not found\n",
							__FUNCTION__, ctx, handle));
				return -2;
			}

			free(pfl);
			/* Not the last one, done */
			if (pcand->fwdlist)
				return 0;

			/* first entry? */
			if (pprev == NULL)
				*head = plist->next;
			else
				pprev->next = plist->next;

			/* close fd for deleted member */
			close(pcand->fd);
			/* free member */
			free(pcand);
			/* cannot reliably continue processing the dispatch loop */
			disp_intr_loop = TRUE;
			return 0;

		}
		/* advance */
		pprev = plist;
		plist = plist->next;
	}

	/* REFERENCE */
	/* not found */
	PRINT(("%s: member %p not found in list %p\n",
		__FUNCTION__, pcand, *head));
	return -1;
}

/* Perform any necessary initialization (startup only)
 * success: return zero
 * failure: return non-zero
 */
int disp_lib_init(PCFGDISPFN dispfn)
{
	int status = 0;

	if (dispatch_table != NULL) {
		PRINT_ERR((
			"%s: Not in initial state: dispatch_table not null, bailing\n",
			__FUNCTION__));
		return -1;
	}

	/* may be restarted */
	disp_quit_loop = FALSE;

	/* setup config path */
	if (disp_open_cfgpath(&disp_cfg_sock)) {
		status = -1;
		goto err_cleanup;
	}

	/* register a handler function
	 * In this case it's the configuration function
	 * to process the configuration message
	 */

	dispatch_table = (disp_tbl_t *)malloc(sizeof(disp_tbl_t));
	if (dispatch_table == NULL) {
		PRINT_ERR((
			"%s: Failed to malloc cfg member for dispatch_table, bailing\n",
			__FUNCTION__));
		status = -1;
		goto err_cleanup;
	}
	memset(dispatch_table, 0, sizeof(disp_tbl_t));
	dispatch_table->next = NULL;
	dispatch_table->fd = disp_cfg_sock.server_fd;
	/* "well known" entry point for configuration */
	dispatch_table->pcfgdispfn = dispfn;
	dispatch_table->precvfn = disp_recv_cfgmsg;

	return status;

err_cleanup:
	/* free descriptor if necessary */
	disp_close_cfgpath(&disp_cfg_sock);
	return status;
}

/* Perform any necessary cleanup for program termination
 * success: return zero
 * failure: return non-zero
 */
int disp_lib_deinit(void)
{
	disp_tbl_t *plist = dispatch_table;

	if (dispatch_table == NULL) {
		PRINT_ERR(("%s: dispatcher not initialized!\n", __FUNCTION__));
		return -1;
	}

	/* will leak descriptors and memory! */
	if (plist->next != NULL) {
		PRINT_ERR(("%s: context de-init incomplete!\n", __FUNCTION__));
		return -1;
	}

	/* clear out the config path */
	disp_close_cfgpath(&disp_cfg_sock);
	free(plist);
	dispatch_table = NULL;
	disp_quit_loop = TRUE;

	return 0;
}

/* Entry point for [re] configuration (from outside)
 * Forwards the msg via the platform dependent method
 * uses the [write] udp socket descriptor opened by init
 */
int disp_lib_cfg(char *msg, int len)
{
	int bytes_sent;
	struct sock_cfg *p = &disp_cfg_sock;

	bytes_sent = sendto(p->client_fd, msg, len, 0,
		(struct sockaddr *)&p->to_addr, sizeof(p->to_addr));
	if (bytes_sent < 0) {
		PRINT_ERR(("%s: sendto config descriptor failed\n", __FUNCTION__));
		return -1;
	}
	return 0;
}

/*
 * Called when a raw socket descriptor is readable
 * Read the message from the descriptor
 * Allocate a PKT, copy message into it
 * Send PKT along with the registered callback function
 */
void
disp_recv_msg(void *arg)
{
	disp_tbl_t *p = (disp_tbl_t *)arg;
	void *pkt;
	int len;
	fwd_list_t *pfl;

	pkt = PKTGET(NULL, RECV_PKT_TOTAL_LEN, FALSE);
	if (pkt == NULL) {
		PRINT_ERR(("%s: failed to allocate receive buffer, bailing\n", \
				   __FUNCTION__));
		goto DONE;
	}
	PKTPULL(NULL, pkt, TXOFF);
	len = recv(p->fd, PKTDATA(NULL, pkt), PKTLEN(NULL, pkt), 0);
	if (len <= 0) {
		PRINT_ERR(("%s: Error reading raw descriptor %d\n", \
				   __FUNCTION__, p->fd));
		goto DONE;
	}
	PKTSETLEN(NULL, pkt, len);

	/* Walk the fwd_list, send a copy to all registrants */
	for (pfl = p->fwdlist; pfl; pfl = pfl->next) {
		/* send it along */
		if (pfl->pdispfn == NULL) {
			PRINT_ERR(("%s: null entry in valid fwd list member, ptbl %p pfl %p pfl->ctx %p\n", p, pfl, pfl->ctx));
			continue;
		}
		(*pfl->pdispfn)(pfl->ctx, PKTDATA(NULL, pkt), PKTLEN(NULL, pkt));
	}

DONE:
	if (NULL != pkt)
		PKTFREE(NULL, pkt, FALSE);
}

/* Run the dispatcher: a select loop.
 * This needs to be in a separate thread.
 * It returns only if:
 * -- the dispatcher is signalled to quit
 * -- an unrecoverable error condition is encountered
 */
int disp_lib_run()
{
	int status;
	fd_set rdfdset;
	disp_tbl_t *ptbl = dispatch_table;
	int width = 0;
	exp_time_t timeout_setting;
	struct timeval tv;
	bool timeout;

	for ( ; ; ) {

		/* dispatch_table NULL */
		if (dispatch_table == NULL) {
			PRINT_ERR((
				"%s: dispatch_table uninitialized or corrupted, bailing\n", __FUNCTION__));
			status = -1;
			break;
		}

		/* walk the list of registered descriptors & callbacks
		 * setup readfd arg appropriately
		 */
		FD_ZERO(&rdfdset);
		for (ptbl = dispatch_table; ptbl; ptbl = ptbl->next) {
			if (ptbl->fd < 0) {
				PRINT_ERR(("%s: invalid fd in table entry, bailing\n", __FUNCTION__));
				status = -1;
				break;
			}
			FD_SET(ptbl->fd, &rdfdset);
			/* establish max fd value */
			if (ptbl->fd > width)
				width = ptbl->fd;
		}

		/* Check the timer list (soonest to expire is head)
		 * Create timeout value for select if appropriate
		 */
		memset(&tv, 0, sizeof(tv));
		timeout = bcmseclib_get_timeout(&timeout_setting);
		if (timeout) {
			tv.tv_sec = timeout_setting.sec;
			tv.tv_usec = timeout_setting.usec;
		}

		PRINT_TRACE(("%s: Entering select\n", __FUNCTION__));
		PRINT_TRACE(("timeout tv_sec %d tv_usec %d\n", tv.tv_sec,
				tv.tv_usec));
		/* listen to data availible on all sockets */
		status = select(width + 1,
				(void *)&rdfdset, NULL, NULL,
				(timeout ? &tv : NULL));


		/* Error? */
		if (status < 0) {
			PRINT_ERR(("%s: select returned error %d errno %d\n",
				__FUNCTION__, status, errno));
			break;
		}


		/* Timeout ? */
		bcmseclib_process_timer_expiry();

		/* walk list of registered descriptors
		 * if FD_ISSET() process ...
		 */
		for (ptbl = dispatch_table, disp_intr_loop = FALSE;
			 ptbl && !disp_intr_loop;
			 ptbl = ptbl->next)
		{
			if (FD_ISSET(ptbl->fd, &rdfdset)) {
				(*ptbl->precvfn)(ptbl);
			}
		}

		/* Set by cfg message processing */
		if (disp_quit_loop == TRUE) {
			PRINT(("%s: received termination message\n", __FUNCTION__));
			status = 0;
			break;
		}

	} /* END select loop */

	/* only get here if:
	 * -- instructed to quit
	 * -- unrecoverable error
	 */
	PRINT(("Select loop terminating: status %d\n", status));
	return 0;
}

/* Open a raw socket for proto <proto> */
int
open_socket(void *ifarg, uint16 proto)
{
	struct ifreq *ifr = (struct ifreq *)ifarg;
	int fd, err;
	struct sockaddr_ll sll;

	fd = socket(PF_PACKET, SOCK_RAW, htons(proto));
	if (fd < 0) {
		PRINT_ERR(("Cannot create socket %d\n", fd));
		return -1;
	}

	err = ioctl(fd, SIOCGIFINDEX, ifr);
	if (err < 0) {
		PRINT_ERR(("%s: Cannot get index %d\n", __FUNCTION__, err));
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(proto);
	sll.sll_ifindex = ifr->ifr_ifindex;
	err = bind(fd, (struct sockaddr *)&sll, sizeof(sll));
	if (err < 0) {
		PRINT_ERR(("%s: Cannot bind socket %d\n", __FUNCTION__, err));
		return -1;
	}

	return fd;
}

/* Read cfg message from descriptor
 * forward to registered callback function
 */
void
disp_recv_cfgmsg(void *arg)
{
	disp_tbl_t *p = (disp_tbl_t *)arg;
	void *pkt;
	int len;

	pkt = PKTGET(NULL, RECV_PKT_TOTAL_LEN, FALSE);
	if (pkt == NULL) {
		PRINT_ERR(("%s: failed to allocate receive buffer, bailing\n", __FUNCTION__));
		return;
	}
	PKTPULL(NULL, pkt, TXOFF);

	len = recvfrom(p->fd, PKTDATA(NULL, pkt), PKTLEN(NULL, pkt), 0, NULL, 0);
	if (len <= 0) {
		PRINT_ERR(("%s: Error reading config descriptor\n", __FUNCTION__));
		PKTFREE(NULL, pkt, FALSE);
		return;
	}
	PKTSETLEN(NULL, pkt, len);

	/*
	dispatch_table->pdispfn = cfg_process_cfgmsg;
	*/
	/* Send it along */
	(*p->pcfgdispfn)(pkt);
}


/* For the configuration path
 * We use a udp (datagram) socket pair
 * open a descriptor for
 * writing (client) -- incoming requests write to this
 * reading (server) -- select loop pends on this
 */
int
disp_open_cfgpath(struct sock_cfg *pcfg)
{
	struct sockaddr_in *paddr = &pcfg->to_addr;
	int cli_fd, srv_fd;

	/* Use loopback address for sendto */
	bzero((char *) paddr, sizeof(struct sockaddr_in));
	paddr->sin_family      = AF_INET;
	paddr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	paddr->sin_port        = htons(DISP_CFG_UDP_PORT);

	/* open client socket */
	cli_fd = open_datagram_client_socket();
	if (cli_fd < 0) {
		PRINT_ERR((
			"%s: failed to open datagram client socket, bailing\n", __FUNCTION__));
		goto err_exit0;
	}


	/* open server socket */
	srv_fd = open_datagram_server_socket();
	if (srv_fd <  0) {
		PRINT_ERR((
			"%s: failed to open datagram server socket, bailing\n", __FUNCTION__));
		goto err_exit1;
	}

	pcfg->client_fd = cli_fd;
	pcfg->server_fd = srv_fd;
	return 0;

err_exit1:
	if (srv_fd >= 0)
		close(srv_fd);
err_exit0:
	if (cli_fd >= 0)
		close(cli_fd);

	return -1;
}

void
disp_close_cfgpath(struct sock_cfg *pcfg)
{
	if (pcfg->client_fd >= 0)
		close(pcfg->client_fd);
	if (pcfg->server_fd >= 0)
		close(pcfg->server_fd);

	memset(pcfg, 0, sizeof(struct sock_cfg));
}

/* Routines for handling SOCK_DGRAM sockets */
int
open_datagram_client_socket()
{
	int	fd;
	struct sockaddr_in cli_addr;

	/* datagram socket */
	if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		PRINT_ERR(("%s: failed to open datagram socket\n", __FUNCTION__));
		return -1;
	}

	/* any local address for client  */
	bzero((char *) &cli_addr, sizeof(cli_addr));
	cli_addr.sin_family      = AF_INET;
	cli_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	cli_addr.sin_port        = htons(0);
	if (bind(fd, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0) {
		PRINT_ERR(("%s: bind to local address failed\n", __FUNCTION__));
		close(fd);
		return -1;
	}

	return fd;
}

int
open_datagram_server_socket()
{
	int fd;
	struct sockaddr_in serv_addr;

	/* create datagram socket */
	if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		PRINT_ERR(("%s: failed to open datagram socket", __FUNCTION__));
		return -1;
	}

	/* any local address for us  */
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family      = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port        = htons(DISP_CFG_UDP_PORT);

	if (bind(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		PRINT_ERR(("%s: bind to local address failed\n", __FUNCTION__));
		close(fd);
		return -1;
	}

	return fd;
}

static
bool disp_ctx_cmpfn(void * lh, void *arg)
{
	fwd_list_t *pfl = (fwd_list_t *)lh;

	return (pfl->ctx == arg);
}
