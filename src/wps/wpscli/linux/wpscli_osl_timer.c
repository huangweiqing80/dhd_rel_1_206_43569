/*
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wpscli_osl_timer.c 475022 2014-05-02 23:21:49Z $
 *
 * Description: Implement Linux timer functions
 *
 */
#include <typedefs.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

unsigned long wpscli_current_time()
{
	struct timeval now;

	gettimeofday(&now, NULL);

	return now.tv_sec;
}

void wpscli_sleep(unsigned long milli_seconds)
{
	struct timespec ts; 
		  struct timespec rem; 

		  ts.tv_sec  = milli_seconds / 1000; 
		  ts.tv_nsec = (milli_seconds - (ts.tv_sec * 1000)) * 1000000; 
		  while (1) 
		  { 
				  if (nanosleep(&ts, &rem) < 0) 
				  { 
						  if (errno == EINTR) 
						  { 
								  ts = rem; 
								  continue; 
						  } 
				  } 
				  break; 
		  } 
}
