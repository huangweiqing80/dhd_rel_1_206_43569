/*
 * P2P Library Low level OS-specific Layer - generic RTOS version
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2posl_linux.c,v 1.59 2011-01-08 01:42:01 $
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <asm/errno.h>
#include <sys/timeb.h>
#include <sys/time.h>

#include <p2plib_api.h>
#include <p2plib_int.h>
#include <p2plib_osl.h>
#include <BcmP2PAPI.h>
#include <p2posl_linux.h>
#include <p2posl.h>
#include <p2plib_generic_osl.h>
#include <bcmutils.h>
#include <bcmseclib_timer.h>


/* for debugging - exit on system failure */
#define EXIT_ON_SYSTEM_FAILURE 0


/* thread commands sent by pipe */
typedef enum {
	THREAD_EXIT,
	THREAD_CONTINUE
} THREAD_COMMAND;


/*
 * Counting semaphore implementation compatible with src/include/osl_ext.h's
 * semaphores.
 */
/* Create a semaphore */
p2posl_sem_t*
p2posl_sem_create(const char* name)
{
	p2posl_sem_t* sem;
	int ret1, ret2;

	sem = P2PAPI_MALLOC(sizeof(*sem));
	if (sem == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2posl_sem_create: %s malloc fail\n",
			sem->dbg_name));
		return NULL;
	}

	ret1 = pthread_mutex_init(&sem->lock, NULL);
	ret2 = pthread_cond_init(&sem->wait_until_count_nonzero, NULL);
	if (ret1 != 0 || ret2 != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2posl_sem_create: %s init fail\n",
			sem->dbg_name));
		P2PAPI_FREE(sem);
		return NULL;
	}

	sem->count = 0;
	sem->num_waiters = 0;
	sem->dbg_name = (char*) name;
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "p2posl_sem_create: %s\n",
		sem->dbg_name));
	return sem;
}

/* Delete a semaphore */
int
p2posl_sem_delete(p2posl_sem_t* sem)
{
	int ret1, ret2;

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "p2posl_sem_delete: %s\n",
		sem->dbg_name));
	ret1 = pthread_mutex_destroy(&sem->lock);
	ret2 = pthread_cond_destroy(&sem->wait_until_count_nonzero);
	P2PAPI_FREE(sem);
	return (ret1 | ret2);
}

/* Resets semaphore count. */
int
p2posl_sem_reset(p2posl_sem_t *sem)
{
	int ret;

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "p2posl_sem_reset: %s cnt=%d nw=%d\n",
		sem->dbg_name, sem->count, sem->num_waiters));

	/* Enter critical section */
	ret = pthread_mutex_lock(&sem->lock);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2posl_sem_reset: lock error %d\n", ret));
		return ret;
	}

	sem->num_waiters = 0;
	sem->count = 0;

	/* Exit critical section */
	pthread_mutex_unlock(&sem->lock);

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "p2posl_sem_reset: exit\n"));
	return 0;
}

/* Increments semaphore count.  Unblocks one thread waiting on a sem_wait(). */
int
p2posl_sem_signal(p2posl_sem_t *sem)
{
	int ret;
#if P2PLOGGING
	struct timespec abs_time;
	clock_gettime(CLOCK_REALTIME, &abs_time);
#endif /* P2PLOGGING */

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "p2posl_sem_signal: %s\n",
		sem->dbg_name));
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2posl_sem_signal: enter, cnt=%d nw=%d curr time=%u.%u\n",
		sem->count, sem->num_waiters, abs_time.tv_sec, abs_time.tv_nsec));

	/* Enter critical section */
	ret = pthread_mutex_lock(&sem->lock);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2posl_sem_signal: lock error %d\n", ret));
		return ret;
	}
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "p2posl_sem_signal: mutex locked\n"));

	if (sem->num_waiters > 0)
		pthread_cond_signal(&sem->wait_until_count_nonzero);

	sem->count++;

	/* Exit critical section */
	pthread_mutex_unlock(&sem->lock);

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2posl_sem_signal: exit, cnt=%d\n", sem->count));
	return 0;
}

/* Decrements semaphore count. If count is < 0 then blocks the caller for up
 * to timeout_ms milliseconds or until another thread calls sem_give().
 * - If timeout_ms is 0, then waits forever.
 * - When unblocked due to a sem_signal(), returns P2PAPI_OSL_SUCCESS.
 * - When unblocked due to a timeout, returns P2PAPI_OSL_TIMEOUT.
 */
P2POSL_STATUS
p2posl_sem_wait(p2posl_sem_t* sem, int timeout_ms,
	BCMP2P_LOG_LEVEL timeout_log_level)
{
	int ret;
	P2POSL_STATUS status = P2POSL_SUCCESS;
	struct timespec abs_time;

	/* Calculate the absolute time of the timeout */
	if (0 != clock_gettime(CLOCK_REALTIME, &abs_time)) {
		return (P2POSL_ERROR);
	}
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "p2posl_sem_wait: %s\n",
		sem->dbg_name));
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2posl_sem_wait: enter, cnt=%d nw=%d curr time=%u.%u\n",
		sem->count, sem->num_waiters, abs_time.tv_sec, abs_time.tv_nsec));
	abs_time.tv_sec += timeout_ms / 1000;
	abs_time.tv_nsec += (timeout_ms % 1000) * 1000000;
	if (abs_time.tv_nsec > 1000000000) {
		abs_time.tv_sec++;
		abs_time.tv_nsec -= 1000000000;
	}
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"    timeout=%u.%09u\n", abs_time.tv_sec, abs_time.tv_nsec));

	/* Enter critical section */
	ret = pthread_mutex_lock(&sem->lock);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2posl_sem_wait: lock failed\n"));
		return (P2POSL_ERROR);
	}
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "p2posl_sem_wait: mutex locked\n"));
	sem->num_waiters++;

	/* Wait until the count is above 0, then atomically release the lock
	 * and wait for the condition variable to be signaled.
	 */
	while (sem->count == 0) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2posl_sem_wait: wait, cnt=%d\n", sem->count));

		/* Atomically release the mutex and wait on the cond variable */
/*
		ret = pthread_cond_wait(&sem->wait_until_count_nonzero, &sem->lock);
*/
		ret = pthread_cond_timedwait(&sem->wait_until_count_nonzero,
			&sem->lock, &abs_time);
		/* When pthread_cond_wait returns, the mutex is locked again */

		if (ret == ETIMEDOUT) {
			BCMP2PLOG((timeout_log_level, TRUE,
				"p2posl_sem_wait: timed out, cnt=%d\n", sem->count));
			status = P2POSL_TIMEOUT;
			break;
		} else if (ret != 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2posl_sem_wait: error %d\n", ret));
			status = P2POSL_ERROR;
			break;
		} else {
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"p2posl_sem_wait: done, cnt=%d\n", sem->count));
		}
//		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 400); /* TEMP */
	}

	sem->num_waiters--;
	if (ret == 0)
		sem->count--;

	/* Exit critical section */
	pthread_mutex_unlock(&sem->lock);

#if P2PLOGGING
	clock_gettime(CLOCK_REALTIME, &abs_time);
#endif /* P2PLOGGING */
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2posl_sem_wait: exit, ret=%d cnt=%d time=%u.%09u\n",
		ret, sem->count, abs_time.tv_sec, abs_time.tv_nsec));

	return status;
}


/* Initialize the Group Owner Negotiation handshake thread synchronization
 * mechanism.
 */
static int
p2posl_init_go_negotiation(p2papi_osl_instance_t *osl_hdl)
{
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_osl_init_go_neg\n"));
	osl_hdl->go_negotiation_sem = p2posl_sem_create("go_neg_sem");
	return BCMP2P_SUCCESS;
}


/* Initialize the OSL */
P2PWL_BOOL
p2posl_init(void)
{
	/* Seed the random number generator */
	srandom(time(0) ^ getpid());
	return TRUE;
}

/* Deinitialize the OSL */
P2PWL_BOOL
p2posl_deinit(void)
{
	return TRUE;
}

#ifdef TARGETENV_android
static int
init_apsta_mode(p2posl_wl_hdl_t* wl)
{
	int result, val;

	result = p2pwl_iovar_get_bss(wl, "apsta", &val, sizeof(val), 0);
	if (result != 0) {
		goto fail;
	}

	if (val == 0) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "---wl mpc 0\n"));
		val = 0;
		result = p2pwl_iovar_set_bss(wl, "mpc", &val, sizeof(val), 0);
		if (result != 0) {
			goto fail;
		}

		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "---wl down\n"));
		result = p2posl_wl_ioctl_bss(wl, WLC_DOWN, NULL, 0, TRUE, 0);
		if (result != 0) {
			goto fail;
		}

		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "---wl apsta 1\n"));
		val = 1;
		result = p2pwl_iovar_set_bss(wl, "apsta", &val, sizeof(val), 0);
		if (result != 0) {
			goto fail;
		}

		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "---wl up\n"));
		result = p2posl_wl_ioctl_bss(wl, WLC_UP, NULL, 0, TRUE, 0);
		if (result != 0) {
			goto fail;
		}
		val = -1;
		p2posl_wl_ioctl_bss(wl, WLC_GET_UP, &val, sizeof(val), FALSE, 0);
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "---wl isup: %d\n", val));
	}

	return 0;

fail:
	BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_enter_ap_mode failed!\n"));
	return -1;
}
#endif /* TARGETENV_android */

/* Open a new instance of the OSL.
 * Returns a ptr to the allocated and initialized OSL data, or NULL if error.
 */
void*
p2posl_open(void* app_hdl, const char *if_name, const char *primary_if_name)
{
	p2papi_osl_instance_t *osl_hdl = NULL;
	p2posl_wl_hdl_t *wl = NULL;

	(void) if_name;

	/* Allocate storage for the OSL instance data */
	osl_hdl = P2PAPI_MALLOC(sizeof(*osl_hdl));
	memset(osl_hdl, 0, sizeof(*osl_hdl));
	if (osl_hdl == NULL) {
		P2PERR("p2posl_open: osl_hdl mem alloc failed\n");
		goto error_exit;
	}

	/* Allocate storage for the WL driver handle instance data */
	wl = P2PAPI_MALLOC(sizeof(*wl));
	memset(wl, 0, sizeof(*wl));
	if (wl == NULL) {
		P2PERR("p2posl_open: wl mem alloc failed\n");
		goto error_exit;
	}

	/* Initialize the OSL instance data's WL driver handle */
	strncpy(wl->primary_if_name, primary_if_name, sizeof(wl->primary_if_name));
	wl->primary_if_name[sizeof(wl->primary_if_name) - 1] = '\0';
	memset(&wl->primary_ifr, 0, sizeof(wl->primary_ifr));
	strncpy(wl->primary_ifr.ifr_name, wl->primary_if_name,
		sizeof(wl->primary_ifr.ifr_name));

	wl->wl_magic = P2PAPI_WL_HDL_MAGIC_NUMBER;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2posl_open: pri_ifname=%s\n",
		wl->primary_ifr.ifr_name));

	if (0 != pthread_mutex_init(&wl->ioctl_mutex, NULL)) {
		P2PERR("p2posl_open: wl mutex init error\n");
		goto error_exit;
	}
	if ((wl->wl_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		P2PERR1("p2p_osl_open: socket error %d\n", wl->wl_sock);
		goto error_exit;
	}
	P2PAPI_WL_CHECK_HDL(wl);

	/* Initialize the other OSL instance data */
	if (0 != pthread_mutex_init(&osl_hdl->instance_data_mutex, NULL)) {
		P2PERR("p2posl_open: mutex init error\n");
		goto error_exit;
	}
	osl_hdl->osl_magic = P2PAPI_OSL_HDL_MAGIC_NUMBER;
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	p2posl_init_go_negotiation(osl_hdl);

	osl_hdl->escan_sem = p2posl_sem_create("escan_sem");

	osl_hdl->bss_create_sem = p2posl_sem_create("bss_create_sem");
	osl_hdl->tx_af_sem = p2posl_sem_create("tx_af_sem");
	osl_hdl->secure_join_sem = p2posl_sem_create("secure_join_sem");
	osl_hdl->client_assoc_sem = p2posl_sem_create("client_assoc_sem");


	/* Save the WL handle and the app handle in the OSL data */
	osl_hdl->wl = wl;
	osl_hdl->app_hdl = app_hdl;

	/* At this point all lower OSL data initialization is complete. */
	P2PLOG3("p2posl_open: hdl=%p osl_hdl=%p wl=%p\n", app_hdl, osl_hdl, wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    app_hdl=%p osl_magic=0x%x wl_magic=0x%x\n",
		osl_hdl->app_hdl, osl_hdl->osl_magic, wl->wl_magic));

#ifdef TARGETENV_android
	if (init_apsta_mode(wl) == -1)
		goto error_exit;
#endif

	return osl_hdl;

error_exit:
	if (wl)
		P2PAPI_FREE(wl);
	if (osl_hdl)
		P2PAPI_FREE(osl_hdl);
	return NULL;
}


/* Open the ETHER_TYPE_BRCM raw socket for receiving packets */
static int
p2papi_linux_brcm_open(p2papi_osl_instance_t *osl_hdl)
{
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	osl_hdl->brcm_sock = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_BRCM));
	if (osl_hdl->brcm_sock < 0) {
		P2PERR("open socket error!!\n");
		return -1;
	}
	P2PLOG1("p2papi_linux_brcm_open: socket %d opened\n", osl_hdl->brcm_sock);

	return osl_hdl->brcm_sock;
}

/* Close the ETHER_TYPE_BRCM raw socket for receiving packets */
static int
p2papi_linux_brcm_close(p2papi_osl_instance_t *osl_hdl)
{
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	/* Close the brcm socket used to receive raw frames */
	if (osl_hdl->brcm_sock != -1) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_linux_brcm_close: closing brcm_sock\n"));
		close(osl_hdl->brcm_sock);
		osl_hdl->brcm_sock = -1;
	}

	/* Close the pipe used to signal the event receive thread to stop */
	if (osl_hdl->fd_pipe[0] != -1) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_linux_brcm_close: closing pipe 0\n"));
		close(osl_hdl->fd_pipe[0]);
		osl_hdl->fd_pipe[0] = -1;
	}
	if (osl_hdl->fd_pipe[1] != -1) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_linux_brcm_close: closing pipe 1\n"));
		close(osl_hdl->fd_pipe[1]);
		osl_hdl->fd_pipe[1] = -1;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_linux_brcm_close: done\n"));
	return 0;
}

/* Raw frame rx thread for receiving action frames and WL driver events */
static void
p2papi_linux_rx_thread(void *arg)
{
	p2papi_osl_instance_t *osl_hdl = (p2papi_osl_instance_t*) arg;
	int recv_bytes;
	uint8 rxbuf[2048];
	exp_time_t timeout_setting;
	struct timeval tv;
	BCMP2P_BOOL b_timeout;
	p2papi_instance_t* hdl = (p2papi_instance_t*) osl_hdl->app_hdl;

	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	osl_hdl->rx_thread_running = TRUE;
	P2PLOG("p2papi_linux_rx_thread: begin\n");

	while (1) {
		fd_set	rfds;	/* fds for select */
		int	last_fd;
		int	ret;

		if (P2PAPI_OSL_CHECK_HDL(osl_hdl) == FALSE) {
			P2PERR("p2papi_rx_thread: osl_hdl is not valid. Break ~!!");
			break;
		}

		FD_ZERO(&rfds);
		FD_SET(osl_hdl->fd_pipe[0], &rfds);
		FD_SET(osl_hdl->brcm_sock, &rfds);
		last_fd = MAX(osl_hdl->fd_pipe[0], osl_hdl->brcm_sock);

		memset(&tv, 0, sizeof(tv));
		b_timeout = bcmseclib_get_timeout_ex(hdl->timer_mgr, &timeout_setting);
		if (b_timeout) {
			tv.tv_sec = timeout_setting.sec;
			tv.tv_usec = timeout_setting.usec;
		}

		/* wait on brcm socket and pipe */
		ret = select(last_fd+1, &rfds, NULL, NULL,
		             b_timeout ? &tv : NULL);
		/* error processing */
		if (ret < 0) {
			if (errno != EINTR && errno != EAGAIN)
				continue;
			P2PERR("unhandled signal on brcm socket");
			break;
		}

		/* check pipe for whether to end this thread */
		if (P2PAPI_OSL_CHECK_HDL(osl_hdl) == FALSE) {
			P2PERR("p2papi_rx_thread: osl_hdl is not valid. Break ~!!");
			break;
		}
		if (FD_ISSET(osl_hdl->fd_pipe[0], &rfds)) {
			recv_bytes = read(osl_hdl->fd_pipe[0], rxbuf, sizeof(rxbuf));
			if (recv_bytes == -1) {
				P2PERR1("p2papi_rx_thread: read failed on fd_pipe: %d\n",
					recv_bytes);
			}
			if (recv_bytes == sizeof(THREAD_COMMAND)) {
				THREAD_COMMAND *cmd = (THREAD_COMMAND *)rxbuf;
				if (*cmd == THREAD_EXIT) {
					P2PLOG("p2papi_rx_thread: received exit from pipe");
					break;
				} else if (*cmd == THREAD_CONTINUE) {
					P2PLOG("p2papi_rx_thread: received continue from pipe");
					continue;
				}
			}
		}

		/* Process timers. */
		bcmseclib_process_timer_expiry_ex(hdl->timer_mgr);

		/* check brcm socket for rx data */
		if (FD_ISSET(osl_hdl->brcm_sock, &rfds)) {
/*			P2PVERB("p2papi_rx_thread: brcm sock recv()\n"); */
			recv_bytes = recv(osl_hdl->brcm_sock, rxbuf, sizeof(rxbuf), 0);
/*			P2PVERB1("p2papi_rx_thread: recv_bytes=%d\n", recv_bytes); */
			if (recv_bytes == -1) {
				P2PERR1("p2papi_rx_thread: recv failed: %d\n", recv_bytes);
			}
			/* process rx frames for Wifi Action Frames */
			osl_hdl->rx_frame_cb(osl_hdl->rx_frame_cb_param, rxbuf,
				recv_bytes);
		}
	}  /* end-while(1) */

	P2PLOG("p2papi_linux_rx_thread: end\n");
	osl_hdl->rx_thread_running = FALSE;
}

/* Start the raw frame receiver/manager which allows us to receive Wifi
 * action frames and WL driver dongle events.
 */
int p2posl_start_raw_rx_mgr(P2POSL_HDL oslHdl,
	p2posl_rx_frame_hdlr_t rx_frame_cb, void *rx_frame_cb_param)
{
	p2papi_osl_instance_t *osl_hdl = (p2papi_osl_instance_t*) oslHdl;

	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2posl_start_raw_rx_mgr\n"));
	osl_hdl->rx_frame_cb = rx_frame_cb;
	osl_hdl->rx_frame_cb_param = rx_frame_cb_param;
	osl_hdl->rx_thread_running = FALSE;

	/* Open the brcm socket used to receive raw frames */
	osl_hdl->brcm_sock = p2papi_linux_brcm_open(osl_hdl);
	if (osl_hdl->brcm_sock < 0) {
		P2PERR("brcm socket open failed");
		return BCME_ERROR;
	}

	/* Open the pipe used to signal the raw receive thread to stop */
	osl_hdl->fd_pipe[0] = -1;
	osl_hdl->fd_pipe[1] = -1;
	if (0 != pipe(osl_hdl->fd_pipe)) {
		P2PERR1("pipe: %s", strerror(errno));
		goto CLEANUP;
	}

	/* Create the raw receive thread */
	if (p2posl_create_thread(p2papi_linux_rx_thread, osl_hdl,
		&osl_hdl->rx_thread_hdl) != 0) {
		P2PERR("event thread creation failed\n");
		goto CLEANUP;
	}

	return BCME_OK;

CLEANUP:
	/* Close the brcm socket used to receive raw frames */
	close(osl_hdl->brcm_sock);
	osl_hdl->brcm_sock = -1;

	/* Close the pipe used to signal the raw receive thread to stop */
	close(osl_hdl->fd_pipe[0]);
	close(osl_hdl->fd_pipe[1]);
	osl_hdl->fd_pipe[0] = -1;
	osl_hdl->fd_pipe[1] = -1;

	return BCME_ERROR;
}

/* Stop the raw frame receiver/manager */
int
p2posl_stop_raw_rx_mgr(P2POSL_HDL oslHdl)
{
	p2papi_osl_instance_t *osl_hdl = (p2papi_osl_instance_t*) oslHdl;
	int i;
	THREAD_COMMAND cmd;
	int write_bytes;

	P2PLOG("p2posl_stop_raw_rx_mgr\n");
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	/* Signal the event thread to end */
	cmd = THREAD_EXIT;
	write_bytes = write(osl_hdl->fd_pipe[1], &cmd, sizeof(cmd));
	if (write_bytes != sizeof(cmd)) {
		P2PERR1("p2posl_stop_raw_rx_mgr: write failed on fd_pipe: %d\n",
			write_bytes);
	}
	P2PLOG("stop_raw_rx: signaled event thread to end\n");

	/* Wait up to 1000ms for the event thread to end */
	for (i = 0; i < 5; i++) {
		if (!osl_hdl->rx_thread_running) {
			P2PLOG("stop_raw_rx: event thread ended\n");
			break;
		}
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 200);
	}

	p2papi_linux_brcm_close(osl_hdl);
	P2PLOG("stop_raw_rx: done\n");

	return BCME_OK;
}

/* timer refresh */
int
p2posl_timer_refresh(P2POSL_HDL oslHdl)
{
	p2papi_osl_instance_t *osl_hdl = (p2papi_osl_instance_t*) oslHdl;
	THREAD_COMMAND cmd;
	int write_bytes;

	P2PLOG("p2posl_timer_refresh\n");
	P2PAPI_OSL_CHECK_HDL(osl_hdl);

	/* signal the event thread to refresh timers */
	cmd = THREAD_CONTINUE;
	write_bytes = write(osl_hdl->fd_pipe[1], &cmd, sizeof(cmd));
	if (write_bytes != sizeof(cmd)) {
		P2PERR1("p2posl_timer_refresh: write failed on fd_pipe: %d\n",
			write_bytes);
	}
	P2PLOG("p2posl_timer_refresh: signaled event thread to refresh\n");

	return BCME_OK;
}

/* Close an instance of the OSL and free the OSL data */
void
p2posl_close(void* osl_handle)
{
	p2papi_osl_instance_t *osl_hdl = (p2papi_osl_instance_t*) osl_handle;
	p2posl_wl_hdl_t *wl;

	if (osl_hdl && P2PAPI_OSL_CHECK_HDL(osl_hdl)) {
		if (osl_hdl->go_negotiation_sem != NULL) {
			p2posl_sem_delete(osl_hdl->go_negotiation_sem);
			osl_hdl->go_negotiation_sem = NULL;
		}
		if (osl_hdl->escan_sem != NULL) {
			p2posl_sem_delete(osl_hdl->escan_sem);
			osl_hdl->escan_sem = NULL;
		}
		if (osl_hdl->bss_create_sem != NULL) {
			p2posl_sem_delete(osl_hdl->bss_create_sem);
			osl_hdl->bss_create_sem = NULL;
		}
		if (osl_hdl->tx_af_sem != NULL) {
			p2posl_sem_delete(osl_hdl->tx_af_sem);
			osl_hdl->tx_af_sem = NULL;
		}
		if (osl_hdl->secure_join_sem != NULL) {
			p2posl_sem_delete(osl_hdl->secure_join_sem);
			osl_hdl->secure_join_sem = NULL;
		}
		if (osl_hdl->client_assoc_sem != NULL) {
			p2posl_sem_delete(osl_hdl->client_assoc_sem);
			osl_hdl->client_assoc_sem = NULL;
		}

		wl = osl_hdl->wl;
		if (wl) {
			close(wl->wl_sock);
			P2PAPI_FREE(wl);
		}

		osl_hdl->osl_magic = 0;
		P2PAPI_FREE(osl_hdl);
	} else {
		P2PERR1("p2papi_osl_close: bad osl_hdl %p\n", osl_hdl);
	}
}

/* Sleep */
void
p2posl_sleep_ms(unsigned int ms)
{
	usleep(ms * 1000);
}


static void
p2posl_wl_printlasterror(void *wl, char *prefix)
{
	char error_str[128];

	if (p2pwl_iovar_get_bss(wl, "bcmerrorstr", error_str, sizeof(error_str), 0) != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "Unable to get bcmerrorstr\n"));
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "%s%s\n", prefix, error_str));
	}
}

/* Lock/Unlock a P2P Library instance for mutually exclusive access to its
 * ioctl_mutex.  Returns 0 if successful.
 */
int
p2posl_ioctl_lock(P2PWL_HDL wlHdl)
{
	int retval = -1;
	p2posl_wl_hdl_t *wl = (p2posl_wl_hdl_t*) wlHdl;

	if (P2PAPI_WL_CHECK_HDL(wl))
	{
		retval = pthread_mutex_lock(&wl->ioctl_mutex);
	}

	return retval;
}

int
p2posl_ioctl_unlock(P2PWL_HDL wlHdl)
{
	int retval = -1;
	p2posl_wl_hdl_t *wl = (p2posl_wl_hdl_t*) wlHdl;

	if (P2PAPI_WL_CHECK_HDL(wl))
	{
		retval = pthread_mutex_unlock(&wl->ioctl_mutex);
	}

	return retval;
}

/* Common core code for invoking a WL driver ioctl */

int
p2posl_wl_ioctl_core(p2posl_wl_hdl_t *wl, int bsscfg_idx, int cmd, void *buf, int len,
	P2PWL_BOOL set)
{
	struct ifreq *ifr = NULL;
	int s;
	wl_ioctl_t ioc;
	int ret = -1;
        char *logstring = NULL;

	s = wl->wl_sock;

/*
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"@@@p2posl_wl_ioctl_core: wl=%p pri=%s virt=%s curr=%s\n",
		wl, wl->primary_ifr.ifr_name, wl->virtual_ifr.ifr_name,
		wl->current_ifr->ifr_name));
*/

	/* Do the ioctl, check results */
	ioc.cmd = cmd;
	ioc.buf = buf;
	ioc.len = len;
	ioc.set = set;
	ret = p2posl_ioctl_lock(wl);
	if (ret == 0)
	{
		if (bsscfg_idx == 0) {
			logstring = "(on primary ifr)\n";
			ifr = &wl->primary_ifr;
		} else if (bsscfg_idx == wl->connection_bssidx) {
			logstring = "(on connection ifr)\n";
			ifr = &wl->connection_ifr;
		} else if (bsscfg_idx == wl->discovery_bssidx) {
			logstring = "(on discovery ifr)\n";
			ifr = &wl->discovery_ifr;
		} else {
			logstring = "(on unknown ifr %d)\n",
			ifr = NULL;
		}

		if (ifr != NULL)
		{
			ifr->ifr_data = (caddr_t) &ioc;
			ret = ioctl(s, SIOCDEVPRIVATE, ifr);
		}

		p2posl_ioctl_unlock(wl);
	}
	else
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		          "p2posl_wl_ioctl_core: failed to iocl_mutex lock!\n"));

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "   %s\n", logstring));
/*
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"wl_ioctl: s=%d cmd=%d buf=%p len=%d set=%d wl=%p, ret=%d\n",
		s, cmd, buf, len, set, wl, ret));
*/

	/* ignore allowable failures */
	if (ret < 0 &&
		!(cmd == WLC_GET_BSSID ||
		(cmd == WLC_SET_VAR && strcmp(buf, "bsscfg:auth_wpa") == 0) ||
		(cmd == WLC_GET_VAR && strcmp(buf, "p2p_ops") == 0) ||
		cmd == WLC_SET_PLCPHDR ||
		(cmd == WLC_SET_VAR && strcmp(buf, "bsscfg:closednet") == 0) ||
		((cmd == WLC_SET_VAR || cmd == WLC_GET_VAR) &&
		strcmp(buf, "maxassoc") == 0) ||
		(cmd == WLC_SET_VAR && strcmp(buf, "ap_isolate") == 0) ||
		(cmd == WLC_GET_VAR && strcmp(buf, "chanspec") == 0) ||
		cmd == WLC_GET_ASSOCLIST ||
		cmd == WLC_GET_SPECT_MANAGMENT ||
		cmd == WLC_SCAN_RESULTS)) {
#if EXIT_ON_SYSTEM_FAILURE
		printf("ioctl failed: ");
		if (cmd == WLC_GET_VAR)
			printf("WLC_GET_VAR %s\n", (char *)buf);
		else if (cmd == WLC_SET_VAR)
			printf("WLC_SET_VAR %s\n", (char *)buf);
		else
			printf("IOCTL %d\n", cmd);
		exit(1);
#endif /* EXIT_ON_SYSTEM_FAILURE */

		if (errno == ENODEV) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"wl_ioctl: Cannot find WIFI Device. Quit and check!\n"));
			exit(1);
		}

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"wl_ioctl: WLC ioctl %d returned error %d\n", cmd, errno));
		p2posl_wl_printlasterror(wl, "  bcmerrorstr=");
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"  sock=%d buf=%p len=%d set=%d wl=%p, ret=%d\n",
			s, buf, len, set, wl, errno));

		if (ifr != NULL)
		    BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"  pri/dis/con ifidx=%d/%d/%d ifnames=%s/%s/%s, ioctl ifname=%s\n",
			wl->primary_bssidx, wl->discovery_bssidx, wl->connection_bssidx,
			wl->primary_ifr.ifr_name, wl->discovery_ifr.ifr_name,
			wl->connection_ifr.ifr_name, ifr->ifr_name));
		else
                   BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
                        "  pri/dis/con ifidx=%d/%d/%d ifnames=%s/%s/%s, bad bsscfg_idx %d\n",
                        wl->primary_bssidx, wl->discovery_bssidx, wl->connection_bssidx,
                        wl->primary_ifr.ifr_name, wl->discovery_ifr.ifr_name,
                        wl->connection_ifr.ifr_name, bsscfg_idx));

		if (ret == BCME_UNSUPPORTED) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "Unsupported ioctl %d\n", cmd));
			exit(BCME_UNSUPPORTED);
		} else if (cmd == WLC_SET_VAR) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    WLC_SET_VAR %s\n", buf));
		} else if (cmd == WLC_GET_VAR) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    WLC_GET_VAR %s\n", buf));
		}
		if (cmd != WLC_GET_MAGIC) {
			ret = -2;
		}
	}


	return ret;
}



/* Remember the BSSCFG index for the discovery or connection BSS */
int
p2posl_save_bssidx(void* wlHdl, int usage, int bssidx)
{
	p2posl_wl_hdl_t *wl = (p2posl_wl_hdl_t*) wlHdl;
	int bss_usage = (p2papi_bsscfg_type_t)usage;

	P2PAPI_WL_CHECK_HDL(wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2posl_save_bssidx: usage=%d bssidx=%d\n", bss_usage, bssidx));

	if (bss_usage == P2PAPI_BSSCFG_DEVICE)
		wl->discovery_bssidx = bssidx;
	else if (bss_usage == P2PAPI_BSSCFG_CONNECTION)
		wl->connection_bssidx = bssidx;
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2posl_save_bssidx: unknown usage!\n"));

	return 0;
}

/* Remember the BSSCFG OS interface name for the discovery or connection BSS */
int
p2posl_save_bssname(void* wlHdl, int bsscfg_usage, char* ifname)
{
	p2posl_wl_hdl_t *wl = (p2posl_wl_hdl_t*) wlHdl;

	P2PAPI_WL_CHECK_HDL(wl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2posl_save_bssname: usage=%d ifname=%s\n", bsscfg_usage, ifname));

	if (bsscfg_usage == P2PAPI_BSSCFG_DEVICE) {
		strncpy(wl->discovery_ifr.ifr_name, ifname,
			sizeof(wl->discovery_ifr.ifr_name));
	}
	else if (bsscfg_usage == P2PAPI_BSSCFG_CONNECTION) {
		strncpy(wl->connection_ifr.ifr_name, ifname,
			sizeof(wl->connection_ifr.ifr_name));
	}
	else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2posl_save_bssname: unknown bsscfg usage!\n"));
	}

	return 0;
}

/* Invoke a WL driver ioctl on a selected BSSCFG */
int
p2posl_wl_ioctl_bss(void* wlHdl, int cmd, void *buf, int len, P2PWL_BOOL set,
	int bsscfg_idx)
{
	p2posl_wl_hdl_t *wl = (p2posl_wl_hdl_t*) wlHdl;

	P2PAPI_WL_CHECK_HDL(wl);

	return p2posl_wl_ioctl_core(wl, bsscfg_idx, cmd, buf, len, set);

}


/* Lock/Unlock a P2P Library instance for mutually exclusive access to its
 * data.  Returns 0 if successful.
 */
int
p2posl_data_lock(void* oslHdl)
{
	p2papi_osl_instance_t *osl_hdl = (p2papi_osl_instance_t*) oslHdl;

	/* Currently there are no timeouts on the lock */
	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	return pthread_mutex_lock(&osl_hdl->instance_data_mutex);
}

int
p2posl_data_unlock(void* oslHdl)
{
	p2papi_osl_instance_t *osl_hdl = (p2papi_osl_instance_t*) oslHdl;

	P2PAPI_OSL_CHECK_HDL(osl_hdl);
	return pthread_mutex_unlock(&osl_hdl->instance_data_mutex);
}

int
p2posl_create_thread(void (*in_thread_fn)(void*), void* in_arg,
	p2posl_thread_t* io_thread_hdl)
{
	int ret;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
/*	pthread_attr_setstacksize(&attr, 128*1024); */
	pthread_attr_setstacksize(&attr, 64*1024);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	/*	Create the thread detached, so that it cleans up its
	 *	own memory when it exits.
	 */
	ret = pthread_create(io_thread_hdl, &attr,
		(void* (*)(void*)) in_thread_fn, in_arg);
	pthread_attr_destroy(&attr);

	return ret;
}



/* Wait for a thread to exit */
int
p2posl_wait_for_thread_exit(p2posl_thread_t thread_hdl)
{
	if (thread_hdl)
		return pthread_join(thread_hdl, NULL);
	else
		return BCME_ERROR;
}

/* Check if a WL driver handle is valid */
bool
p2posl_wl_chk_hdl(void* wl_hdl, const char *file, int line)
{
	p2posl_wl_hdl_t* wl = (p2posl_wl_hdl_t*) wl_hdl;

	if (wl == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "NULL wl hdl at %s:%d\n", file, line));
		return FALSE;
	}

	if (wl->wl_magic != P2PAPI_WL_HDL_MAGIC_NUMBER) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "Bad wl hdl %p magic=0x%x at %s:%d\n",
			wl, wl->wl_magic, file, line));
		return FALSE;
	}

	return TRUE;
}


#if P2PLOGGING
/*
 * Logging functions
 */
static struct timeval p2posl_time_base;

/* Subtract timetamp B from timestamp A (A = A - B) */
static void
subtract_timestamp(struct timeval *a, struct timeval *b)
{
	if (a->tv_usec < b->tv_usec) {
		a->tv_sec--;
		a->tv_usec += 1000000L;
	}
	a->tv_usec -= b->tv_usec;
	a->tv_sec -= b->tv_sec;
}

/* Initialize the timestamping mechanism used for timestamped logs */
void
p2posl_init_timestamp(void)
{
	/* Record the starting timestamp for our p2p_tslog() timestamps */
	gettimeofday(&p2posl_time_base, NULL);
}

/* Get the current time and print a timestamp relative to the time
 * p2posl_init_timestamp() was called.
 */
void
p2posl_print_timestamp(BCMP2P_LOG_LEVEL level, FILE *stream)
{
	struct timeval now;
	char separator;

	if (level == BCMP2P_LOG_ERR)
		separator = 'e';
	else if (level == BCMP2P_LOG_INFO)
		separator = 'i';
	else if (level == BCMP2P_LOG_VERB)
		separator = 'v';
	else
		separator = '.';

	gettimeofday(&now, NULL);
	subtract_timestamp(&now, &p2posl_time_base);
	fprintf(stream, "%05lu%c%03lu ", now.tv_sec % 100000, separator,
		now.tv_usec / 1000);
/*
	syslog(LOG_INFO, "%04lu%c%03lu ", now.tv_sec % 10000, separator,
		now.tv_usec / 1000);
*/
}
#endif /* P2PLOGGING */


/* Debug: Get the OS network interface name used for p2posl_wl_ioctl() for the
 * given BSSCFG.
 */
char*
p2posl_get_netif_name_bss(void* wlHdl, int bssidx)
{
	p2posl_wl_hdl_t *wl = (p2posl_wl_hdl_t*) wlHdl;
	struct  ifreq *ifr = NULL;

	if (wl) {
		if (bssidx == 0)
			ifr = &wl->primary_ifr;
		else if (bssidx == wl->connection_bssidx)
			ifr = &wl->connection_ifr;
		else if (bssidx == wl->discovery_bssidx)
			ifr = &wl->discovery_ifr;

		if (ifr)
			return ifr->ifr_name;
	}
	return "";
}

char*
p2posl_get_netif_name_prefix(void* wlHdl)
{
	p2posl_wl_hdl_t *wl = (p2posl_wl_hdl_t*) wlHdl;

	if (wl && wl->wl_magic == P2PAPI_WL_HDL_MAGIC_NUMBER) {
		return " -i ";
	}
	return "";
}

/* Do any necessary OS-specific configuration to prepare the P2P network
 * interface to run in AP mode.
 */
void
p2posl_set_netif_for_ap_mode(void* wlHdl, bool run_or_stop, char *ifname)
{
	(void) wlHdl;
	(void) run_or_stop;
	(void) ifname;
}

/* Do any necessary OS-specific configuration to prepare the P2P network
 * interface to run in STA mode.
 */
void
p2posl_set_netif_for_sta_mode(void* wlHdl, bool run_or_stop, char *ifname)
{
	(void) wlHdl;
	(void) run_or_stop;
	(void) ifname;
}


/* Bring up an OS wireless network interface */
int
p2posl_ifup(const char* ifname, void *hdl)
{
	int ret;
	char cmd[80];
	char *path = "";
	int i;

	/* NOTE: it should be possible to move the "ifconfig" and "route" actions
	 * here into a system network interface startup script. eg.
	 * /etc/sysconfig/network-scripts/ifup-wl0.1
	 */
#ifdef TARGETENV_android
	path = "/system/bin/";
#elif defined(TARGETENV_BCMSTB)
	path = "/bin/";
#else
	path = "/sbin/";
#endif /* TARGETENV_android */

	snprintf(cmd, sizeof(cmd), "%sifconfig %s up\n", path, ifname);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2posl_ifup: %s\n", cmd));
	for (i = 0; i < 20; i++) {
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 50);
		ret = system(cmd);
		if (ret == 0)
			break;
	}
	if (ret == -1) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2posl_ifup failed: %s\n", cmd));
		return -1;
	}

	snprintf(cmd, sizeof(cmd), "%sifconfig %s\n", path, ifname);
	for (i = 0; i < 20; i++) {
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 50);
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2posl_ifup: %s\n", cmd));
		ret = system(cmd);
		if (ret == 0)
			break;
	}
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2posl_ifup %s failed to come up\n", ifname));
#if EXIT_ON_SYSTEM_FAILURE
		printf("%s failed to come up\n", ifname);
		exit(1);
#endif /* EXIT_ON_SYSTEM_FAILURE */
	}

#ifdef TARGETENV_android
	/* For Android
	  Android "route" command (Cupcake, Donut, Eclair so far) doesn't support the
	  command below.

	  route add -host 255.255.255.255 <if_name>

	  It has to be enhanced to support this or you may have to
	  use busybox route. Refer to PR: 80786 for more information.
	*/
	BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "\n*** WARNING!!! The command add -host"
	"may not be successful in Android.\n If you are facing routing issues, refer"
	"to the PR:80786. \n"));
#endif /* TARGETENV_android */

	snprintf(cmd, sizeof(cmd), "%sroute add -host 255.255.255.255 %s\n",
		path, ifname);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_linux_ifup: %s\n", cmd));
	ret = system(cmd);
	if (ret == -1) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2posl_ifup failed: %s\n", cmd));
		return -1;
	}


	return 0;
}

/* Bring down an OS wireless network interface */
int
p2posl_ifdown(const char* ifname)
{
	int ret;
	char cmd[80];

#ifdef TARGETENV_android
	snprintf(cmd, sizeof(cmd), "/system/bin/route del -host 255.255.255.255 %s\n",
		ifname);
#elif defined(TARGETENV_BCMSTB)
	snprintf(cmd, sizeof(cmd), "/bin/route del -host 255.255.255.255 %s\n",
		ifname);
#else
	snprintf(cmd, sizeof(cmd), "/sbin/route del -host 255.255.255.255 %s\n",
		ifname);
#endif /* TARGETENV_android */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_linux_ifdown: %s\n", cmd));
	ret = system(cmd);
	if (ret == -1) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2posl_ifdown failed: %s\n", cmd));
	}

#ifdef TARGETENV_android
	snprintf(cmd, sizeof(cmd), "/system/bin/ifconfig %s down\n", ifname);
#elif defined(TARGETENV_BCMSTB)
	snprintf(cmd, sizeof(cmd), "/bin/ifconfig %s down\n", ifname);
#else
	snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s 0.0.0.0 down\n", ifname);
#endif /* TARGETENV_android */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_linux_ifdown: %s\n", cmd));
	ret = system(cmd);
	if (ret == -1) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2posl_ifdown failed: %s\n", cmd));
		return -1;
	}

	return 0;
}


/* Format a bsscfg indexed iovar buffer */
int
p2posl_bssiovar_mkbuf(const char *iovar, int bssidx, void *param,
	int paramlen, void *bufptr, int buflen, int *perr)
{
	return p2pwl_common_bssiovar_mkbuf(iovar, bssidx, param, paramlen, bufptr,
		buflen, perr);
}

/* Check if an AP BSS is up */
bool
p2posl_bss_isup(P2PWL_HDL wl, int bsscfg_idx)
{
	return p2pwl_common_bss_isup(wl, bsscfg_idx);
}


/* Get clock time since process start in millisec */
unsigned int
p2posl_gettime(void)
{
	struct timespec abs_time;

	/* Calculate the absolute time of the timeout */
	clock_gettime(CLOCK_REALTIME, &abs_time);

	return abs_time.tv_sec * 1000 + abs_time.tv_nsec/1000000;
}

/* Diff newtime and oldtime in ms */
unsigned int
p2posl_difftime(unsigned int newtime, unsigned int oldtime)
{
	return (unsigned int)(-1) - oldtime + newtime + 1;
}
