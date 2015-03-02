/*
 * wl mfp command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_mfp.c 458728 2014-02-27 18:15:25Z $
 */

#ifdef WIN32
#include <windows.h>
#endif

#include <wlioctl.h>


/* Because IL_BIGENDIAN was removed there are few warnings that need
 * to be fixed. Windows was not compiled earlier with IL_BIGENDIAN.
 * Hence these warnings were not seen earlier.
 * For now ignore the following warnings
 */
#ifdef WIN32
#pragma warning(push)
#pragma warning(disable : 4244)
#pragma warning(disable : 4761)
#endif

#include <bcmutils.h>
#include <bcmendian.h>
#include "wlu_common.h"
#include "wlu.h"

static int wl_mfp_config(void *wl, cmd_t *cmd, char **argv);
static int wl_mfp_sha256(void *wl, cmd_t *cmd, char **argv);
static int wl_mfp_sa_query(void *wl, cmd_t *cmd, char **argv);
static int wl_mfp_disassoc(void *wl, cmd_t *cmd, char **argv);
static int wl_mfp_deauth(void *wl, cmd_t *cmd, char **argv);
static int wl_mfp_assoc(void *wl, cmd_t *cmd, char **argv);
static int wl_mfp_auth(void *wl, cmd_t *cmd, char **argv);
static int wl_mfp_reassoc(void *wl, cmd_t *cmd, char **argv);

static cmd_t wl_mfp_cmds[] = {
	{ "mfp_config", wl_mfp_config, -1, WLC_SET_VAR,
	"Config PMF capability\n"
	"\tusage: wl mfp 0/disable, 1/capable, 2/requred" },
	{ "mfp_sha256", wl_mfp_sha256, WLC_GET_VAR, WLC_SET_VAR,
	"Config SHA256 capability\n"
	"\tusage: wl sha256 0/disable, 1/enable" },
	{ "mfp_sa_query", wl_mfp_sa_query, -1, WLC_SET_VAR,
	"Send a sa query req/resp to a peer\n"
	"\tusage: wl mfp_sa_query flag action id" },
	{ "mfp_disassoc", wl_mfp_disassoc, WLC_GET_VAR, WLC_SET_VAR,
	"send bogus disassoc\n"
	"\tUsage: wl mfp_disassoc"},
	{ "mfp_deauth", wl_mfp_deauth, WLC_GET_VAR, WLC_SET_VAR,
	"send bogus deauth\n"
	"\tUsage: wl mfp_dedauth"},
	{ "mfp_assoc", wl_mfp_assoc, WLC_GET_VAR, WLC_SET_VAR,
	"send assoc\n"
	"\tUsage: wl mfp_assoc"},
	{ "mfp_auth", wl_mfp_auth, WLC_GET_VAR, WLC_SET_VAR,
	"send auth\n"
	"\tUsage: wl mfp_auth"},
	{ "mfp_reassoc", wl_mfp_reassoc, WLC_GET_VAR, WLC_SET_VAR,
	"send reassoc\n"
	"\tUsage: wl mfp_reassoc"},
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_mfp_module_init(void)
{
	/* get the global buf */
	buf = wl_get_buf();

	/* register mfp commands */
	wl_module_cmds_register(wl_mfp_cmds);
}

static int
wl_mfp_config(void *wl, cmd_t *cmd, char **argv)
{
	int argc;
	int err = 0;
	int flag = 0;
	const char *cmdname = "mfp";

	UNUSED_PARAMETER(cmd);

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	if (argc > 1 && argv[1]) {
		flag = htod32(atoi(argv[1]));
		*(int *)buf = flag;
	}

	err = wlu_iovar_set(wl, cmdname, buf, 256);

	return (err);

}

static int
wl_mfp_sha256(void *wl, cmd_t *cmd, char **argv)
{
	int argc;
	int err = 0;
	int flag = 0;
	const char *cmdname = "mfp_sha256";

	UNUSED_PARAMETER(cmd);

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	if (argc > 1 && argv[1]) {
		flag = htod32(atoi(argv[1]));
		*(int *)buf = flag;
		err = wlu_iovar_set(wl, cmdname, buf, 256);
	} else {
		/* get */
		err = wlu_iovar_getint(wl, cmdname, &flag);
		if (err == BCME_OK)
			printf("%d\n", flag);
	}

	return (err);

}

static int
wl_mfp_sa_query(void *wl, cmd_t *cmd, char **argv)
{
	wl_sa_query_t * query;
	int argc;
	int err = 0;

	UNUSED_PARAMETER(cmd);

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	if ((query = (wl_sa_query_t *) malloc(sizeof(wl_sa_query_t))) == NULL) {
		printf("unable to allocate frame \n");
		return BCME_NOMEM;
	}
	memset(query, 0, sizeof(wl_sa_query_t));

	/* add the flag */
	if (argc > 1 && argv[1]) {
		query->flag = htod32(atoi(argv[1]));
	}

	/* add the action */
	if (argc > 2 && argv[2]) {
		query->action = htod32(atoi(argv[2]));
	}

	/* add the id */
	if (argc > 3 && argv[3]) {
		query->id = htod32(atoi(argv[3]));
	}

	err = wlu_var_setbuf(wl, "mfp_sa_query", query, sizeof(wl_sa_query_t));

	free(query);

	return (err);

}

static int
wl_mfp_disassoc(void *wl, cmd_t *cmd, char **argv)
{
	const char *cmdname = "mfp_disassoc";
	int argc;
	int	flag;
	char varbuf[256];
	int err;

	UNUSED_PARAMETER(cmd);
	memset(varbuf, 0, 256);

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	/* add the action */
	if (argc > 1 && argv[1]) {
		flag = htod32(atoi(argv[1]));
		*(int *)varbuf = flag;
	}
	if (argc > 2 && argv[2]) {
		flag = htod32(atoi(argv[2]));
		*(int *)(varbuf + sizeof(flag)) = flag;
	}

	err = wlu_iovar_set(wl, cmdname, varbuf, 256);

	return err;
}

static int
wl_mfp_deauth(void *wl, cmd_t *cmd, char **argv)
{
	const char *cmdname = "mfp_deauth";
	int argc;
	int	flag;
	char varbuf[256];
	int err;

	UNUSED_PARAMETER(cmd);

	memset(varbuf, 0, 256);

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	/* add the action */
	if (argc > 1 && argv[1]) {
		flag = htod32(atoi(argv[1]));
		*(int *)varbuf = flag;
	}
	if (argc > 2 && argv[2]) {
		flag = htod32(atoi(argv[2]));
		*(int *)(varbuf + sizeof(flag)) = flag;
	}

	err = wlu_iovar_set(wl, cmdname, varbuf, 256);

	return err;
}

static int
wl_mfp_assoc(void *wl, cmd_t *cmd, char **argv)
{
	const char *cmdname = "mfp_assoc";
	int argc;
	int	flag;
	char varbuf[256];
	int err;

	UNUSED_PARAMETER(cmd);
	memset(varbuf, 0, 256);

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	/* add the action */
	if (argc > 1 && argv[1]) {
		flag = htod32(atoi(argv[1]));
		*(int *)varbuf = flag;
	}
	if (argc > 2 && argv[2]) {
		flag = htod32(atoi(argv[2]));
		*(int *)(varbuf + sizeof(int)) = flag;
	}

	err = wlu_iovar_set(wl, cmdname, varbuf, 256);

	return err;
}

static int
wl_mfp_auth(void *wl, cmd_t *cmd, char **argv)
{
	const char *cmdname = "mfp_auth";
	int argc;
	int	flag;
	char varbuf[256];
	int err;

	UNUSED_PARAMETER(cmd);
	memset(varbuf, 0, 256);

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	/* add the action */
	if (argc > 1 && argv[1]) {
		flag = htod32(atoi(argv[1]));
		*(int *)varbuf = flag;
	}
	if (argc > 2 && argv[2]) {
		flag = htod32(atoi(argv[2]));
		*(int *)(varbuf + sizeof(int)) = flag;
	}

	err = wlu_iovar_set(wl, cmdname, varbuf, 256);

	return err;
}

static int
wl_mfp_reassoc(void *wl, cmd_t *cmd, char **argv)
{
	const char *cmdname = "mfp_reassoc";
	int argc;
	int	flag;
	char varbuf[256];
	int err;

	UNUSED_PARAMETER(cmd);
	memset(varbuf, 0, 256);

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	/* add the action */
	if (argc > 1 && argv[1]) {
		flag = htod32(atoi(argv[1]));
		*(int *)varbuf = flag;
	}
	if (argc > 2 && argv[2]) {
		flag = htod32(atoi(argv[2]));
		*(int *)(varbuf + sizeof(int)) = flag;
	}

	err = wlu_iovar_set(wl, cmdname, varbuf, 256);

	return err;
}
