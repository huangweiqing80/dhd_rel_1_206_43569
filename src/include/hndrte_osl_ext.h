/*
 * Hndrte OS Support Extension Layer
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 * $Id:$
 */


#ifndef _hndrte_osl_ext_h_
#define _hndrte_osl_ext_h_

#ifdef __cplusplus
extern "C" {
#endif



#include <typedefs.h>





#define osl_ext_sem_t
#define OSL_EXT_SEM_DECL(sem)


#define osl_ext_mutex_t
#define OSL_EXT_MUTEX_DECL(mutex)


#define osl_ext_timer_t
#define OSL_EXT_TIMER_DECL(timer)


#define osl_ext_task_t
#define OSL_EXT_TASK_DECL(task)


#define osl_ext_queue_t
#define OSL_EXT_QUEUE_DECL(queue)


#define osl_ext_event_t
#define OSL_EXT_EVENT_DECL(event)




#define osl_ext_sem_create(name, init_cnt, sem)		(OSL_EXT_SUCCESS)
#define osl_ext_sem_delete(sem)				(OSL_EXT_SUCCESS)
#define osl_ext_sem_give(sem)				(OSL_EXT_SUCCESS)
#define osl_ext_sem_take(sem, timeout_msec)		(OSL_EXT_SUCCESS)

#define osl_ext_mutex_create(name, mutex)		(OSL_EXT_SUCCESS)
#define osl_ext_mutex_delete(mutex)			(OSL_EXT_SUCCESS)
#define osl_ext_mutex_acquire(mutex, timeout_msec)	(OSL_EXT_SUCCESS)
#define osl_ext_mutex_release(mutex)			(OSL_EXT_SUCCESS)

#define osl_ext_timer_create(name, timeout_msec, mode, func, arg, timer) \
	(OSL_EXT_SUCCESS)
#define osl_ext_timer_delete(timer)			(OSL_EXT_SUCCESS)
#define osl_ext_timer_start(timer, timeout_msec, mode)	(OSL_EXT_SUCCESS)
#define osl_ext_timer_stop(timer)			(OSL_EXT_SUCCESS)
#define osl_ext_time_get()				(0)

#define osl_ext_task_create(name, stack, stack_size, priority, func, arg, task) \
	(OSL_EXT_SUCCESS)
#define osl_ext_task_delete(task)			(OSL_EXT_SUCCESS)
#define osl_ext_task_current()				(NULL)
#define osl_ext_task_yield()				(OSL_EXT_SUCCESS)
#define osl_ext_task_enable_stack_check()		(OSL_EXT_SUCCESS)

#define osl_ext_queue_create(name, queue_buffer, queue_size, queue) \
	(OSL_EXT_SUCCESS)
#define osl_ext_queue_delete(queue)			(OSL_EXT_SUCCESS)
#define osl_ext_queue_send(queue, data)			(OSL_EXT_SUCCESS)
#define osl_ext_queue_send_synchronous(queue, data)	(OSL_EXT_SUCCESS)
#define osl_ext_queue_receive(queue, timeout_msec, data) \
	(OSL_EXT_SUCCESS)
#define osl_ext_queue_count(queue, count)		(OSL_EXT_SUCCESS)

#define osl_ext_event_create(name, event)		(OSL_EXT_SUCCESS)
#define osl_ext_event_delete(event)			(OSL_EXT_SUCCESS)
#define osl_ext_event_get(event, requested, timeout_msec, event_bits) \
	(OSL_EXT_SUCCESS)
#define osl_ext_event_set(event, event_bits)		(OSL_EXT_SUCCESS)

#define osl_ext_interrupt_disable(void)
#define osl_ext_interrupt_restore(state)

#ifdef __cplusplus
	}
#endif

#endif  
