/*
 * Broadcom P2P Library Sample App command line interface.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2p_app_cli.c,v 1.20 2011-02-09 18:06:23 $
 */


/* ---- Include Files ---------------------------------------------------- */

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

/* P2P API */
#include <BcmP2PAPI.h>
#include <BcmP2PDbg.h>
#include <p2p_app.h>
#include <p2papp_osl.h>


/* ---- Public Variables ------------------------------------------------- */
/* ---- Private Constants and Types -------------------------------------- */

#define P2P_CONSOLE_LOG(a)		p2papp_console_log a

#define CLI_MAX_INPUT_LENGTH		64

#define STDIN_READ_TIMEOUT_USEC		130000

/* Generic command line argument handler */
typedef int (p2papp_cmd_func_t)(int argc, char* argv[]);
typedef struct p2papp_cmd_t {
	const char		*name;
	const char		*help;
	const char		*usage;
	p2papp_cmd_func_t	*func;
} p2papp_cmd_t;


/* ---- Private Function Prototypes -------------------------------------- */

#ifndef SOFTAP_ONLY
static p2papp_cmd_t* find_cmd(char* name);
static int do_cmd(int argc, char* argv[]);
static int usage_cmd(int argc, char* argv[]);
static int help_cmd(int argc, char* argv[]);
static int version_cmd(int argc, char* argv[]);
static int discovery_cmd(int argc, char* argv[]);
static int listen_cmd(int argc, char* argv[]);
static int discovered_devices_cmd(int argc, char* argv[]);
static int group_formation_cmd(int argc, char* argv[]);
static int list_peers_cmd(int argc, char* argv[]);
static int status_cmd(int argc, char* argv[]);
static int operating_chan_cmd(int argc, char* argv[]);
static int intent_cmd(int argc, char* argv[]);
static int listen_chan_cmd(int argc, char* argv[]);
static int disconnect_cmd(int argc, char* argv[]);
static int wps_pin_cmd(int argc, char* argv[]);
static int wps_generate_pin_cmd(int argc, char* argv[]);
static int wps_select_config_method_cmd(int argc, char* argv[]);
static int dev_addr_cmd(int argc, char* argv[]);
static int int_addr_cmd(int argc, char* argv[]);
static int create_group_cmd(int argc, char* argv[]);
static int provision_discovery_cmd(int argc, char* argv[]);
static int persistent_cmd(int argc, char* argv[]);
static int reset_cmd(int argc, char* argv[]);
static int ssid_cmd(int argc, char* argv[]);
static int group_id_cmd(int argc, char* argv[]);
static int enable_ping_cmd(int argc, char* argv[]);
static int intra_bss_cmd(int argc, char* argv[]);
static int concurrent_cmd(int argc, char* argv[]);
static int invitation_cmd(int argc, char* argv[]);
static int service_discovery_cmd(int argc, char* argv[]);
static int client_discovery_cmd(int argc, char* argv[]);
static int passphrase_cmd(int argc, char* argv[]);
static int generate_passphrase_cmd(int argc, char* argv[]);

#endif /* not SOFTAP_ONLY */

/* ---- Private Variables ------------------------------------------------ */

#ifndef SOFTAP_ONLY
static p2papp_cmd_t p2papp_cmds[] =
{
	{
		"create_group",
		"Create standalone group owner",
		"create_group [ssid]",
		create_group_cmd
	},
	{
		"dev_addr",
		"Get P2P device address",
		"dev_addr",
		dev_addr_cmd
	},
	{
		"disconnect",
		"Disconnect from current P2P Group",
		"disconnect",
		disconnect_cmd
	},
	{
		"discovery",
		"Disable/enable device discovery",
		"discovery (0|1)",
		discovery_cmd
	},
	{
		"discovery_results",
		"Display discovered devices",
		"discovery_results",
		discovered_devices_cmd
	},
	{
		"enable_ping",
		"Disable/enable post connection ping.",
		"enable_ping (0|1)",
		enable_ping_cmd
	},
	{
		"group_formation",
		"Form group with selected peer",
		"group_formation (mac-addr|device-name)",
		group_formation_cmd
	},
	{
		"group_id",
		"Get group id",
		"group_id",
		group_id_cmd
	},
	{
		"help",
		"Display command usage",
		"help",
		help_cmd
	},
	{
		"intent",
		"Get/Set GO intent value - used to indicate the desire of the P2P "
		"Device to be the P2P Group Owner",
		"intent [num]",
		intent_cmd
	},
	{
		"int_addr",
		"Get P2P interface address",
		"int_addr",
		int_addr_cmd
	},
	{
		"list_peers",
		"Display a list on connected P2P devices",
		"list_peers",
		list_peers_cmd
	},
	{
		"listen",
		"Disable/enable listen mode",
		"listen (0|1)",
		listen_cmd
	},
	{
		"listen_chan",
		"Get/Set the channel used by to be discoverable.",
		"listen_chan [chan_num]",
		listen_chan_cmd
	},
	{
		"op_chan",
		"Get/Set operating channel",
		"op_chan [chan_num]",
		operating_chan_cmd
	},
	{
		"persistent",
		"Get/Set the persistent group .",
		"persistent [0 | 1]",
		persistent_cmd
	},
	{
		"prov_dis",
		"Send provision discovery",
		"prov_dis (mac-addr|device-name)",
		provision_discovery_cmd
	},
	{
		"reset",
		"Reset all the P2P parameters to device defaults including but not "
		"limited to removal of persistent group and stored credentials",
		"reset",
		reset_cmd
	},
	{
		"ssid",
		"Get the group owner SSID",
		"ssid",
		ssid_cmd
	},
	{
		"status",
		"Display P2P device status",
		"status",
		status_cmd
	},
	{
		"ver",
		"Display version information",
		"ver",
		version_cmd
	},
	{
		"wps_pin",
		"Get/Set WPS pin",
		"wps_pin [pin]",
		wps_pin_cmd
	},
	{
		"wps_gen_pin",
		"Generate random WPS pin",
		"wps_gen_pin",
		wps_generate_pin_cmd
	},
	{
		"wps_select_method",
		"Select the WPS method",
		"wps_select_method (display | label | keyboard)",
		wps_select_config_method_cmd
	},
	{
		"intra_bss",
		"Set the intra-BSS",
		"intra_bss [0 | 1]",
		intra_bss_cmd
	},
	{
		"concurrent",
		"Set concurrent capability",
		"concurrent [0 | 1]",
		concurrent_cmd
	},
	{
		"invitation",
		"Set invitation capability",
		"invitation [0 | 1]",
		invitation_cmd
	},
	{
		"service_discovery",
		"Set service discovery capability",
		"service_discovery [0 | 1]",
		service_discovery_cmd
	},
	{
		"client_discovery",
		"Set client discovery capability",
		"client_discovery [0 | 1]",
		client_discovery_cmd
	},
	{
		"passphrase",
		"Get/Set passphrase",
		"passphrase [8-64 characters]",
		passphrase_cmd
	},
	{
		"generate_passphrase",
		"Generate random passphrase",
		"generate_passphrase (length 8-64 characters)",
		generate_passphrase_cmd
	},

	{ NULL, NULL, NULL }
};
#endif /* not SOFTAP_ONLY */


/* ---- Functions -------------------------------------------------------- */

int
p2papp_console_log(char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vfprintf(stderr, fmt, args);
	va_end(args);

	return (ret);
}

/****************************************************************************
* Function:   p2papp_read_console_input
*
* Purpose:    Read user entered string from STDIN. Block until string entered.
*
* Parameters: buf        (out) Buffer to store user entered string.
*             buf_size   (in)  Size of 'buf'.
*             bytes_read (out) Number of bytes read.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
int p2papp_read_console_input(char *buf, int buf_size, int *bytes_read)
{
	return (p2papp_read_line(buf, buf_size, bytes_read, 0));
}

/****************************************************************************
* Function:   p2papp_read_console_input_timeout
*
* Purpose:    Read user entered string from STDIN. Block until timeout
*
* Parameters: buf        (out) Buffer to store user entered string.
*             buf_size   (in)  Size of 'buf'.
*             bytes_read (out) Number of bytes read.
*             timeout    (in)  timeout in seconds
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
int p2papp_read_console_input_timeout(char *buf, int buf_size, int *bytes_read,
	int timeout)
{
	return (p2papp_read_line(buf, buf_size, bytes_read, timeout*1000L*1000));
}

/****************************************************************************
* Function:   p2papp_cli
*
* Purpose:    Command line interface for P2P application. Reads and executes
*             commands entered by user.
*
* Parameters: argv     (out) Array of pointers to parsed command line tokens.
*             max_args (in)  Size of 'argv'.
*             argcp    (out) Number of parsed string tokens.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
int
p2papp_cli(char **argv, int max_args, int *argcp, BCMP2P_BOOL non_blocking)
{
	static char		line[CLI_MAX_INPUT_LENGTH];
	int 			argc;
	char 			*token;
	int			status;
	int			bytes_read;
	static BCMP2P_BOOL	first_time = TRUE;

	if (first_time) {
		first_time = FALSE;
		P2P_CONSOLE_LOG(("> "));
	}

	argc = 0;

	status = p2papp_read_line(line, sizeof(line), &bytes_read, STDIN_READ_TIMEOUT_USEC);
	if (status != BCMP2P_SUCCESS) {
		goto exit;
	}

	if (bytes_read > 0) {
		while ((argc < (max_args - 1)) &&
		       ((token = strtok(argc ? NULL : line, " \t\n")) != NULL)) {
			argv[argc++] = token;
		}
		argv[argc] = NULL;

		/* Ignore if only whitespace entered. */
		if (argc > 0) {
			if (strcmp(argv[0], "quit") == 0 || strcmp(argv[0], "exit") == 0) {
				/* Return error to signal that application should quit. */
				status = BCMP2P_ERROR;
				goto exit;
			}

#ifndef SOFTAP_ONLY
			status = do_cmd(argc, argv);

			if (status == BCMP2P_INVALID_PARAMS) {
				usage_cmd(argc, argv);
			}
			else if (status != BCMP2P_UNKNOWN_CMD) {
				/* User entered command already processed. */
				argc = 0;
			}
#endif /* not SOFTAP_ONLY */
		}
		P2P_CONSOLE_LOG(("> "));
	}

exit:
	*argcp = argc;
	return (status);
}

#ifndef SOFTAP_ONLY
/****************************************************************************
* Function:   find_cmd
*
* Purpose:    Search the commands table for a matching command name.
*
* Parameters: name (in) Name of command to search for.
*
* Returns:    Return the matching command or NULL if no match found.
*****************************************************************************
*/
static p2papp_cmd_t *
find_cmd(char* name)
{
	p2papp_cmd_t *cmd = NULL;

	/* Search for a matching name */
	for (cmd = p2papp_cmds; cmd->name && strcmp(cmd->name, name); cmd++)
		;

	if (cmd->name == NULL)
		cmd = NULL;

	return cmd;
}

/****************************************************************************
* Function:   do_cmd
*
* Purpose:    Execute specified command.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
do_cmd(int argc, char* argv[])
{
	p2papp_cmd_t	*cmd = NULL;
	int		err = BCMP2P_SUCCESS;

	/* search for command */
	cmd = find_cmd(*argv);

	if (cmd != NULL) {
		/* do command */
		err = (*cmd->func)(argc, argv);
	}
	else {
	     err = BCMP2P_UNKNOWN_CMD;
	}

	return err;
}

/****************************************************************************
* Function:   usage_cmd
*
* Purpose:    Display the usage syntax for the specified command.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
usage_cmd(int argc, char* argv[])
{
	p2papp_cmd_t *cmd;

	for (cmd = p2papp_cmds; cmd->name; cmd++) {
		if (strcmp(cmd->name, *argv) == 0) {
			P2P_CONSOLE_LOG(("%s:\n\t%s\n\tUsage: %s\n",
			                 cmd->name, cmd->help, cmd->usage));
		}
	}

	return (BCMP2P_SUCCESS);
}

/****************************************************************************
* Function:   help_cmd
*
* Purpose:    Display the usage syntax for all commands.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
help_cmd(int argc, char* argv[])
{
	p2papp_cmd_t *cmd;

	for (cmd = p2papp_cmds; cmd->name; cmd++) {
		P2P_CONSOLE_LOG(("%s:\n\t%s\n\tUsage: %s\n\n",
		                 cmd->name, cmd->help, cmd->usage));
	}

	return (BCMP2P_SUCCESS);
}

/****************************************************************************
* Function:   version_cmd
*
* Purpose:    Display the P2P version info.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
version_cmd(int argc, char* argv[])
{
	P2P_CONSOLE_LOG(("P2P API version: %d\n", BRCMP2P_VERSION));
	return (BCMP2P_SUCCESS);
}

/****************************************************************************
* Function:   discovery_cmd
*
* Purpose:    Disable/enable device discovery.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
discovery_cmd(int argc, char* argv[])
{
	BCMP2P_BOOL	enable;
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc != 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	enable = atoi(*argv);
	if (enable) {
		if (p2papi_is_discovery_enabled(p2papp_dev_hdl)) {
			P2P_CONSOLE_LOG(("Discovery already on\n"));
		} else {
			status = p2papp_enable_discovery(BCMP2P_FALSE, 0);
		}
	}
	else {
		status = p2papp_disable_discovery();
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   discovered_devices_cmd
*
* Purpose:    Display discovered devices.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
discovered_devices_cmd(int argc, char* argv[])
{
	p2papp_print_peers_list("", FALSE);

	return (BCMP2P_SUCCESS);
}

/****************************************************************************
* Function:   group_formation_cmd
*
* Purpose:    Form group with selected peer.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
group_formation_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status;

	if (argc != 2) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	status = p2papp_connect(argv[1]);

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   list_peers_cmd
*
* Purpose:    Display list of connected P2P devices.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
list_peers_cmd(int argc, char* argv[])
{
	p2papp_print_peer_names("", FALSE);

	return (BCMP2P_SUCCESS);
}

/****************************************************************************
* Function:   status_cmd
*
* Purpose:    Display P2P device status.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
status_cmd(int argc, char* argv[])
{
	p2papp_display_status();

	return (BCMP2P_SUCCESS);
}

/****************************************************************************
* Function:   operating_chan_cmd
*
* Purpose:    Get/Set the operating channel number.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
operating_chan_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	int		chan;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the operating channel. */

		/* Parse operating channel. */
		chan = atoi(*argv);

		/* Validate channel. */
		if (chan < 0) {
			status = BCMP2P_INVALID_PARAMS;
			goto exit;
		}

		BCMP2PSetOperatingChannel(p2papp_dev_hdl,
			BCMP2P_DEFAULT_OP_CHANNEL_CLASS, chan);
	}
	else {
		BCMP2P_CHANNEL channel;
		/* Get the operating channel. */
		BCMP2PGetOperatingChannel(p2papp_dev_hdl,
			&channel.channel_class, &channel.channel);
		P2P_CONSOLE_LOG(("Operating channel: %d:%d\n",
			channel.channel_class, channel.channel));
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   intent_cmd
*
* Purpose:    Get/Set the GO intent value. Relative value between 0 and 15 used
*             to indicate the desire of the P2P Device to be the P2P Group Owner,
*             with a larger value indicating a higher desire.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
intent_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	int		intent;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the intent value. */

		/* Parse intent value. */
		intent = atoi(*argv);

		/* Validate channel. */
		if ((intent < 0) || (intent > 15)) {
			status = BCMP2P_INVALID_PARAMS;
			goto exit;
		}

		BCMP2PSetIntent(p2papp_dev_hdl, intent);
	}
	else {
		/* Get the intent value. */
		P2P_CONSOLE_LOG(("Intent value: %d\n", BCMP2PGetIntent(p2papp_dev_hdl)));
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   intent_cmd
*
* Purpose:    Set the GO intent value. Relative value between 0 and 15 used to
*             indicate the desire of the P2P Device to be the P2P Group Owner,
*             with a larger value indicating a higher desire.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
listen_chan_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	int		chan;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the listen channel. */

		/* Parse listen channel. */
		chan = atoi(*argv);

		/* Validate channel. */
		if (chan < 0) {
			status = BCMP2P_INVALID_PARAMS;
			goto exit;
		}

		p2papp_set_listen_channel(chan);
	}
	else {
		/* Get the listen channel. */
		P2P_CONSOLE_LOG(("Listen channel: %d\n", p2papp_get_listen_channel()));
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   disconnect_cmd
*
* Purpose:    Disconnect from current P2P group.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
disconnect_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;

	status = p2papp_disconnect();

	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   wps_pin_cmd
*
* Purpose:    G/Set the WPS pin.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
wps_pin_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the WPS pin. */
		status = BCMP2PSetWPSPin(p2papp_dev_hdl, *argv);
	}
	else {
		/* Get the WPS pin. */
		P2P_CONSOLE_LOG(("WPS pin: %s\n", BCMP2PGetWPSPin(p2papp_dev_hdl)));
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   wps_generate_pin_cmd
*
* Purpose:    Generate random WPS pin.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
wps_generate_pin_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	BCMP2P_WPS_PIN pin;

	/* Generate random PIN. */
	BCMP2PRandomWPSPin(p2papp_dev_hdl, &pin);
	BCMP2PSetWPSPin(p2papp_dev_hdl, pin);

	/* Get the WPS pin. */
	P2P_CONSOLE_LOG(("WPS pin: %s\n", pin));

	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   dev_addr_cmd
*
* Purpose:    Get device address.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
dev_addr_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS		status;
	BCMP2P_ETHER_ADDR	dev_addr;

	status = BCMP2PGetDevAddr(p2papp_dev_hdl, &dev_addr);
	P2P_CONSOLE_LOG(("Device address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	                 dev_addr.octet[0], dev_addr.octet[1],
	                 dev_addr.octet[2], dev_addr.octet[3],
	                 dev_addr.octet[4], dev_addr.octet[5]));

	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));

	return (status);
}

/****************************************************************************
* Function:   int_addr_cmd
*
* Purpose:    Get interface address.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
int_addr_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS		status;
	BCMP2P_ETHER_ADDR	int_addr;

	status = BCMP2PGetIntAddr(p2papp_dev_hdl, &int_addr);
	P2P_CONSOLE_LOG(("Device address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	                 int_addr.octet[0], int_addr.octet[1],
	                 int_addr.octet[2], int_addr.octet[3],
	                 int_addr.octet[4], int_addr.octet[5]));

	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));

	return (status);
}

/****************************************************************************
* Function:   listen_cmd
*
* Purpose:    Disable/enable listen mode.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
listen_cmd(int argc, char* argv[])
{
	BCMP2P_BOOL	enable;
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc != 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	enable = atoi(*argv);
	if (enable) {
		if (p2papi_is_discovery_enabled(p2papp_dev_hdl)) {
			P2P_CONSOLE_LOG(("Discovery already on\n"));
		} else {
			status = p2papp_enable_discovery(BCMP2P_TRUE, 0);
		}
	}
	else {
		status = p2papp_disable_discovery();
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   create_group_cmd
*
* Purpose:    Create standalone group owner.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
create_group_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	char		*ssid = NULL;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}


	if (argc == 1) {
		/* Create group with specified SSID. */
		ssid = argv[0];
	}

	status = p2papp_create_group(ssid);

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   wps_select_config_method_cmd
*
* Purpose:    Select the WPS method (Label, display, or keypad).
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
wps_select_config_method_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS		status;
	BCMP2P_WPS_CONFIG_METHODS config;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc != 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (strcmp(argv[0], "label") == 0)
		config = BCMP2P_WPS_LABEL;
	else if (strcmp(argv[0], "display") == 0)
		config = BCMP2P_WPS_DISPLAY;
	else if (strcmp(argv[0], "keypad") == 0)
		config = BCMP2P_WPS_KEYPAD;
	else if (strcmp(argv[0], "pbc") == 0)
		config = BCMP2P_WPS_PUSHBUTTON;
	else {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	status = BCMP2PSelectWpsConfigMethod(p2papp_dev_hdl, config);

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   provision_discovery_cmd
*
* Purpose:    Send provision discovery command to peer device.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
provision_discovery_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status;

	if (argc != 2) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	status = p2papp_send_provision_discovery(argv[1], BCMP2P_WPS_DISPLAY);


exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   persistent_cmd
*
* Purpose:    G/Set the persistent group flag.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
persistent_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	BCMP2P_BOOL	is_persistent;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the persistent value. */

		/* Parse listen channel. */
		is_persistent = atoi(*argv);

		/* Validate channel. */
		if (!((is_persistent == 0) || (is_persistent == 1))) {
			status = BCMP2P_INVALID_PARAMS;
			goto exit;
		}

		p2papp_enable_persistent = is_persistent;
		BCMP2PEnablePersistent(p2papp_dev_hdl, is_persistent);
	}
	else {
		/* Get the listen channel. */
		P2P_CONSOLE_LOG(("Persistent: %d\n", p2papp_enable_persistent));
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   reset_cmd
*
* Purpose:    Reset all the P2P parameters to device defaults including but not
*             limited to removal of persistent group and stored credentials.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
reset_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS status;
	status = p2papp_device_reset();

	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   ssid_cmd
*
* Purpose:    Get the group owner SSID.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
ssid_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;

	P2P_CONSOLE_LOG(("SSID: %s\n", p2papp_ssid));
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));

	return (status);
}

/****************************************************************************
* Function:   group_id_cmd
*
* Purpose:    Get the group id.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
group_id_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS		status;
	BCMP2P_ETHER_ADDR	dev_addr;
	char			ssid[BCMP2P_MAX_SSID_LEN + 1];

	status = p2papp_get_group_id(&dev_addr, ssid);

	if (status == BCMP2P_SUCCESS) {
		P2P_CONSOLE_LOG(("%02x:%02x:%02x:%02x:%02x:%02x %s\n",
		                 dev_addr.octet[0], dev_addr.octet[1],
		                 dev_addr.octet[2], dev_addr.octet[3],
		                 dev_addr.octet[4], dev_addr.octet[5], ssid));
	}

	return (status);
}

/****************************************************************************
* Function:   enable_ping_cmd
*
* Purpose:    Disable/enable post connection ping command.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
enable_ping_cmd(int argc, char* argv[])
{
	BCMP2P_BOOL	enable;
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc != 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	enable = atoi(*argv);
	status = p2papp_enable_connect_ping(enable);

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   intra_bss_cmd
*
* Purpose:    Set the intra-BSS capability.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
intra_bss_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	BCMP2P_BOOL	is_enable;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the value. */

		is_enable = atoi(*argv);

		if (!((is_enable == 0) || (is_enable == 1))) {
			status = BCMP2P_INVALID_PARAMS;
			goto exit;
		}

		BCMP2PEnableIntraBss(p2papp_dev_hdl, is_enable);
	}
	else {
		/* Get the value. */
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   concurrent_cmd
*
* Purpose:    Set the concurrent capability.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
concurrent_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	BCMP2P_BOOL	is_enable;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the value. */

		is_enable = atoi(*argv);

		if (!((is_enable == 0) || (is_enable == 1))) {
			status = BCMP2P_INVALID_PARAMS;
			goto exit;
		}

		BCMP2PEnableConcurrent(p2papp_dev_hdl, is_enable);
	}
	else {
		/* Get the value. */
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   invitation_cmd
*
* Purpose:    Set the invitation capability.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
invitation_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	BCMP2P_BOOL	is_enable;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the value. */

		is_enable = atoi(*argv);

		if (!((is_enable == 0) || (is_enable == 1))) {
			status = BCMP2P_INVALID_PARAMS;
			goto exit;
		}

		BCMP2PEnableInvitation(p2papp_dev_hdl, is_enable);
	}
	else {
		/* Get the value. */
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   service_discovery_cmd
*
* Purpose:    Set the service discovery capability.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
service_discovery_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	BCMP2P_BOOL	is_enable;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the value. */

		is_enable = atoi(*argv);

		if (!((is_enable == 0) || (is_enable == 1))) {
			status = BCMP2P_INVALID_PARAMS;
			goto exit;
		}

		BCMP2PEnableServiceDiscovery(p2papp_dev_hdl, is_enable);
	}
	else {
		/* Get the value. */
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   client_discovery_cmd
*
* Purpose:    Set the client discovery capability.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
client_discovery_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;
	BCMP2P_BOOL	is_enable;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the value. */

		is_enable = atoi(*argv);

		if (!((is_enable == 0) || (is_enable == 1))) {
			status = BCMP2P_INVALID_PARAMS;
			goto exit;
		}

		BCMP2PEnableClientDiscovery(p2papp_dev_hdl, is_enable);
	}
	else {
		/* Get the value. */
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   passphrase_cmd
*
* Purpose:    G/Set the passphrase.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
passphrase_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}

	if (argc == 1) {
		/* Set the passphrase. */
		BCMP2PUpdateWPAKey(p2papp_dev_hdl, NULL, *argv);
	}
	else {
		BCMP2P_PASSPHRASE passphrase;
		/* Get the passphrase. */
		BCMP2PGetGOCredentials(p2papp_dev_hdl, NULL, NULL, (BCMP2P_UINT8 *)&passphrase);
		P2P_CONSOLE_LOG(("passphrase: %s\n", passphrase));
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}

/****************************************************************************
* Function:   generate_passphrase
*
* Purpose:    Generate random passphrase.
*
* Parameters: argc (in) Number of elements in 'argv' array.
*             argv (in) Command to execute, and optional parameters.
*
* Returns:    BCMP2P_STATUS on success, else error code.
*****************************************************************************
*/
static int
generate_passphrase_cmd(int argc, char* argv[])
{
	BCMP2P_STATUS	status = BCMP2P_SUCCESS;

	/* Skip command name. */
	argc--;
	argv++;

	if (argc > 1) {
		status = BCMP2P_INVALID_PARAMS;
		goto exit;
	}
	if (argc == 1) {
		BCMP2P_PASSPHRASE passphrase;
		/* Generate random passphrase. */
		BCMP2PRandomPassphrase(p2papp_dev_hdl, atoi(*argv), &passphrase);
		BCMP2PUpdateWPAKey(p2papp_dev_hdl, NULL, (char *)&passphrase);

		/* Get the passphrase. */
		P2P_CONSOLE_LOG(("passphrase: %s\n", passphrase));
	}
	else {
		status = BCMP2P_INVALID_PARAMS;
	}

exit:
	P2P_CONSOLE_LOG(("%s (%d)\n", BCMP2PStatusCodeToStr(status), status));
	return (status);
}
#endif /* not SOFTAP_ONLY */
