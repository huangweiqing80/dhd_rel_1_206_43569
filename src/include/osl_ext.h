/*
 * OS Abstraction Layer Extension - the APIs defined by the "extension" API
 * are only supported by a subset of all operating systems.
 *
 * Copyright (C) 2014, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * $Id: osl_ext.h 475758 2014-05-06 22:12:37Z $
 */

#ifndef _osl_ext_h_
#define _osl_ext_h_




#if defined(TARGETOS_symbian)
	#include <e32def.h>
	#include <symbian_osl_ext.h>
#elif defined(THREADX)
	#include <threadx_osl_ext.h>
#else
	#include <hndrte_osl_ext.h>
	#define OSL_EXT_DISABLED
#endif


#include <osl.h>

#ifdef __cplusplus
extern "C" {
#endif




typedef enum osl_ext_status_t
{
	OSL_EXT_SUCCESS,
	OSL_EXT_ERROR,
	OSL_EXT_TIMEOUT

} osl_ext_status_t;
#define OSL_EXT_STATUS_DECL(status)	osl_ext_status_t status;

#define OSL_EXT_TIME_FOREVER ((osl_ext_time_ms_t)(-1))
typedef unsigned int osl_ext_time_ms_t;

typedef unsigned int osl_ext_event_bits_t;

typedef unsigned int osl_ext_interrupt_state_t;


typedef enum
{
	
	OSL_EXT_TIMER_MODE_ONCE,

	
	OSL_EXT_TIMER_MODE_REPEAT

} osl_ext_timer_mode_t;


typedef void* osl_ext_timer_arg_t;
typedef void (*osl_ext_timer_callback)(osl_ext_timer_arg_t arg);





typedef void* osl_ext_task_arg_t;


typedef void (*osl_ext_task_entry)(osl_ext_task_arg_t arg);


typedef enum
{
	OSL_EXT_TASK_IDLE_PRIORITY,
	OSL_EXT_TASK_LOW_PRIORITY,
	OSL_EXT_TASK_LOW_NORMAL_PRIORITY,
	OSL_EXT_TASK_NORMAL_PRIORITY,
	OSL_EXT_TASK_HIGH_NORMAL_PRIORITY,
	OSL_EXT_TASK_HIGHEST_PRIORITY,
	OSL_EXT_TASK_TIME_CRITICAL_PRIORITY,

	
	OSL_EXT_TASK_NUM_PRIORITES
} osl_ext_task_priority_t;


#ifndef OSL_EXT_DISABLED








osl_ext_status_t osl_ext_sem_create(char *name, int init_cnt, osl_ext_sem_t *sem);


osl_ext_status_t osl_ext_sem_delete(osl_ext_sem_t *sem);


osl_ext_status_t osl_ext_sem_give(osl_ext_sem_t *sem);


osl_ext_status_t osl_ext_sem_take(osl_ext_sem_t *sem, osl_ext_time_ms_t timeout_msec);





osl_ext_status_t osl_ext_mutex_create(char *name, osl_ext_mutex_t *mutex);


osl_ext_status_t osl_ext_mutex_delete(osl_ext_mutex_t *mutex);


osl_ext_status_t osl_ext_mutex_acquire(osl_ext_mutex_t *mutex, osl_ext_time_ms_t timeout_msec);


osl_ext_status_t osl_ext_mutex_release(osl_ext_mutex_t *mutex);





osl_ext_status_t
osl_ext_timer_create(char *name, osl_ext_time_ms_t timeout_msec, osl_ext_timer_mode_t mode,
                 osl_ext_timer_callback func, osl_ext_timer_arg_t arg, osl_ext_timer_t *timer);


osl_ext_status_t osl_ext_timer_delete(osl_ext_timer_t *timer);


osl_ext_status_t
osl_ext_timer_start(osl_ext_timer_t *timer,
	osl_ext_time_ms_t timeout_msec, osl_ext_timer_mode_t mode);


osl_ext_status_t
osl_ext_timer_stop(osl_ext_timer_t *timer);


osl_ext_time_ms_t osl_ext_time_get(void);





#define osl_ext_task_create(name, stack, stack_size, priority, func, arg, task) \
	   osl_ext_task_create_ex((name), (stack), (stack_size), (priority), 0, (func), \
	   (arg), (task))

osl_ext_status_t osl_ext_task_create_ex(char* name,
	void *stack, unsigned int stack_size, osl_ext_task_priority_t priority,
	osl_ext_time_ms_t timslice_msec, osl_ext_task_entry func, osl_ext_task_arg_t arg,
	osl_ext_task_t *task);


osl_ext_status_t osl_ext_task_delete(osl_ext_task_t *task);



osl_ext_task_t *osl_ext_task_current(void);



osl_ext_status_t osl_ext_task_yield(void);



osl_ext_status_t osl_ext_task_enable_stack_check(void);





osl_ext_status_t osl_ext_queue_create(char *name,
	void *queue_buffer, unsigned int queue_size,
	osl_ext_queue_t *queue);


osl_ext_status_t osl_ext_queue_delete(osl_ext_queue_t *queue);


osl_ext_status_t osl_ext_queue_send(osl_ext_queue_t *queue, void *data);


osl_ext_status_t osl_ext_queue_send_synchronous(osl_ext_queue_t *queue, void *data);


osl_ext_status_t osl_ext_queue_receive(osl_ext_queue_t *queue,
                 osl_ext_time_ms_t timeout_msec, void **data);


osl_ext_status_t osl_ext_queue_count(osl_ext_queue_t *queue, int *count);





osl_ext_status_t osl_ext_event_create(char *name, osl_ext_event_t *event);


osl_ext_status_t osl_ext_event_delete(osl_ext_event_t *event);


osl_ext_status_t osl_ext_event_get(osl_ext_event_t *event,
	osl_ext_event_bits_t requested,	osl_ext_time_ms_t timeout_msec,
	osl_ext_event_bits_t *event_bits);


osl_ext_status_t osl_ext_event_set(osl_ext_event_t *event,
	osl_ext_event_bits_t event_bits);





osl_ext_interrupt_state_t osl_ext_interrupt_disable(void);



void osl_ext_interrupt_restore(osl_ext_interrupt_state_t state);

#endif	

#ifdef __cplusplus
}
#endif

#endif	
