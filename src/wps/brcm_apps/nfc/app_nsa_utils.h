/*
 * NSA generic application utility functions
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: $
 */
#ifndef APP_NSA_UTILS_H
#define APP_NSA_UTILS_H

/* self sufficiency */
/* for printf */
#include <stdio.h>
/* for BD_ADDR and DEV_CLASS */
#include "bt_types.h"
/* for scru_dump_hex */
#include "bsa_trace.h"

/* Macro to retrieve the number of elements in a statically allocated array */
#define APP_NUM_ELEMENTS(__a) ((int)(sizeof(__a)/sizeof(__a[0])))

/* Macro to print an error message */
#define APP_ERROR0(format)                                                      \
do {                                                                            \
    app_print_error("%s: " format "\n", __func__);                                \
} while (0)

#define APP_ERROR1(format, ...)                                                 \
do {                                                                            \
    app_print_error("%s: " format "\n", __func__, __VA_ARGS__);                   \
} while (0)

#ifdef APP_TRACE_NODEBUG

#define APP_DEBUG0(format) do {} while (0)
#define APP_DEBUG1(format, ...) do {} while (0)
#define APP_DUMP(prefix, pointer, length) do {} while (0)

#else /* APP_TRACE_NODEBUG */

/* Macro to print a debug message */
#define APP_DEBUG0(format)                                                      \
do {                                                                            \
    app_print_debug("%s: " format "\n", __func__);                              \
} while (0)

#define APP_DEBUG1(format, ...)                                                 \
do {                                                                            \
    app_print_debug("%s: " format "\n", __func__, __VA_ARGS__);                 \
} while (0)

#define APP_DUMP(prefix, pointer, length)                                         \
do                                                                              \
{                                                                               \
    scru_dump_hex(pointer, prefix, length, TRACE_LAYER_NONE, TRACE_TYPE_DEBUG); \
} while (0)

#endif /* !APP_TRACE_NODEBUG */

/* Macro to print an information message */
#define APP_INFO0(format)                                                       \
do {                                                                            \
    app_print_info(format "\n");                                                \
} while (0)

#define APP_INFO1(format, ...)                                                  \
do {                                                                            \
    app_print_info(format "\n", __VA_ARGS__);                                   \
} while (0)

/* This function is used to get readable string from Class of device */
char *app_get_cod_string(const DEV_CLASS class_of_device);

/*
 * Wait for a choice from user
 * Parameters: The string to print before waiting for input
 * Returns: The number typed by the user, or -1 if the value type was not parsable
 *
 */
int app_get_choice(const char *querystring);

/*
 * Ask the user to enter a string value
 * Parameters: querystring: to print before waiting for input
 *                  str: the char buffer to fill with user input
 *                  len: the length of the char buffer
 * Returns: The length of the string entered not including last NULL char
 *             negative value in case of error
 */
int app_get_string(const char *querystring, char *str, int len);

/*
 * This function is used to print an application information message
 * Parameters: format: Format string
 *                  optional parameters
 * Returns: void
 */
void app_print_info(char *format, ...);

/*
 * This function is used to print an application debug message
 * Parameters: format: Format string
 *                  optional parameters
 * Returns: Svoid
 */
void app_print_debug(char *format, ...);

/*
 * This function is used to print an application error message
 * Parameters: format: Format string
 *                  optional parameters
 * Returns: void
 */
void app_print_error(char *format, ...);

/*
 * Retrieve the size of a file identified by descriptor
 * Parameters: fd: File descriptor
 * Returns: File size if successful or negative error number
 */
int app_file_size(int fd);

#endif /* APP_NSA_UTILS_H */
