/* cli.c
 * basic testing cli
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
 *
 * $Id: cli.c,v 1.8 2010-08-26 22:19:33 $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <typedefs.h>
#include <bcmsec_types.h>
#include <proto/802.11.h>

#include <bcmseclib_api.h>

#include <debug.h>

#ifdef HSL_INTEGRATION
#include "hslif.h"
#endif

#if defined(CLI_TESTTOOL)
#if defined(CALLABLE_MAIN_API)
#define BCMDRIVER
#include <bcmutils.h>
#include "secfrw_cli.h"
#endif   /* CALLABLE_MAIN_API */
#endif   /* CLI_TESTTOOL */


#define MAX_CFGS	16
#ifndef ARRAYSIZE
#define ARRAYSIZE(a)		(sizeof(a)/sizeof(a[0]))
#endif
#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

struct cfg_info {
	bool inuse;				/* allocated? */
	const char *name;
	struct ctxcbs cbfns;
	bcmseclib_ctx_t * cfg_ctx;	/* ctx returned by init ctx */
	struct sec_args sec_cfg;	/* cfg settings */
	bool cb_init;			/* true -- cb funs init'd */
	int pipefd[2];			/* forward cb info */
};

struct libcfg_info {
	struct maincbs maincbfns;
	pthread_t thread1;		/* dispatcher theread */
	struct cfg_info cfg[MAX_CFGS];
	struct cfg_info *active;
};

#define CBMSGTYPE_CFG	1
/* messages forwarded by cb, received by requestor */
struct cb_msg {
	int msgtype;		/* cfg cb, ... */
	void *ctx;
	clientdata_t *client_data;
	int status;
};

struct input_choice {
	char *str;
	int (*fn)(void *arg);		/* not always a cfg pointer */
	void *arg;
};

/* forward */
#ifdef CLI_TESTTOOL
int print_choices( struct input_choice *ch);
int handle_input_choice(struct input_choice *ch);
static int process_args(int argc, char *argv[]);
#endif
int terminate(void *arg);
int init_top_level(void *arg);
int init_cb_utils(struct cfg_info *cfg);
int forward_cb_message(int fd, char *msg, int len);
int wait_for_cb_message(struct cfg_info *cfg, char *buf, int *buflen);
int deinit_top_level(void *arg);
int init_ctx(void *arg);
int deinit_ctx(void *arg);
int set_ctx_cfg(void *arg);
void cfg_main_callback(int err);
int print_cfgs(void *arg);
int select_cfg(void *arg);

struct cfg_info *cfg_alloc(void);
void cfg_free(struct cfg_info *);

#define MAXLINE	32
static struct libcfg_info topcfg; /* implicitly zero'd by static linkage */

struct input_choice choices[] = {
	{"init", init_top_level, &topcfg},
	{"de-init", deinit_top_level, &topcfg},
	{"init ctx", init_ctx, &topcfg},
	{"de-init ctx", deinit_ctx, &topcfg},
	{"set ctx cfg", set_ctx_cfg, &topcfg},
	{"list cfgs", print_cfgs, &topcfg},
	{"select cfg", select_cfg, &topcfg},
	{"Quit", terminate, NULL},
	{NULL, NULL, NULL},
};

#define is_arg(argv) ((argv)[0] && *(argv)[0] != '-')
#define is_opt(argv) ((argv)[0] && *(argv)[0] == '-')

struct cmd_info;
typedef int (cmd_action_fn)(void *, const struct cmd_info *info, char ***argv);

static cmd_action_fn cmd_usage, cmd_wlan_start, cmd_bt_start,
					 cmd_list_services, cmd_service_opts;
static cmd_action_fn cmd_wpa_psk;
#if defined(WPS)
static cmd_action_fn cmd_wps_sup, cmd_wps_auth;
#endif /* defined(WPS) */
static cmd_action_fn cmd_ssid, cmd_psk, cmd_pin, cmd_wps_sec;

struct cmd_info {
	const char *name;
	cmd_action_fn *action;
	const char *syntax;
	const char *desc;
};

static const struct cmd_info cmd_table[] = {
	{ "?", cmd_usage,
	  "",
	  "Display help." },
	{ "wlan-start", cmd_wlan_start,
	  "-id <name> -a <ifname> [-c <idx>] <service> [service-opts] -wlan-end",
	  "Specify a WLAN configuration context.  Multiple configurations "
	  "supported." },
	{ "bt-start", cmd_bt_start,
	  "-id <name> -a <ifname> -bt-end",
	  "Specify a BTAMP configuration context.  Multiple configurations "
	  "supported." },
	{ "list-services", cmd_list_services,
	  "",
	  "List configuration services." },
	{ "service-opts", cmd_service_opts,
	  "<service>",
	  "List options and arguments for a service." },
};

#define PROG_STR "testcli"

static const char usage_str[] =
"Usage:\n"
"\t" PROG_STR " -?\n"
"\t" PROG_STR " -list-services\n"
"\t" PROG_STR " -service-opts <service>\n"
"\t" PROG_STR " -wlan-start|-bt-start <opts-and-args> -wlan-end|-bt-end"
			  " [...]\n";

static const struct cmd_info service_cmd_table[] = {
#define SVC_CMD_SSID 0
	{ "ssid", cmd_ssid,
	  "<ssid>",
	  "SSID.  Supported formats:\n"
	  "\tASCII (0-32 characters)\n" },
#define SVC_CMD_PSK 1
	{ "psk", cmd_psk,
	  "<psk>",
	  "Pre-Shared Key.  Supported formats:\n"
	  "\tASCII (8-63 characters)\n" },
#define SVC_CMD_PIN 2
	{ "pin", cmd_pin,
	  "<pin>",
	  "WPS device PIN (8 digits).  Use 8-zeros for PBC.\n" },
#define SVC_CMD_WPS_SEC 3
	{ "wps_sec", cmd_wps_sec,
	  "<wps_sec>",
	  "wpa-psk-tkip, wpa-psk-aes, wpa2-psk-tkip, wpa2-psk-aes\n" },
};

#define SVC_CMD(cmd) (&service_cmd_table[(cmd)])

const struct cmd_info *wpa_psk_cmd_list[] =
	{ SVC_CMD(SVC_CMD_SSID), SVC_CMD(SVC_CMD_PSK), NULL };
const struct cmd_info *wps_sup_enr_cmd_list[] =
	{ SVC_CMD(SVC_CMD_SSID), SVC_CMD(SVC_CMD_PIN), NULL };
const struct cmd_info *wps_auth_reg_cmd_list[] =
	{ SVC_CMD(SVC_CMD_SSID), SVC_CMD(SVC_CMD_PSK), SVC_CMD(SVC_CMD_PIN),
	  SVC_CMD(SVC_CMD_WPS_SEC), NULL };

static const struct cmd_info service_table[] = {
	{ "wpa-psk-tkip-sup", cmd_wpa_psk,
	  (char *) wpa_psk_cmd_list,
	  "WPA-PSK (TKIP) supplicant." },
	{ "wpa-psk-tkip-auth", cmd_wpa_psk,
	  (char *) wpa_psk_cmd_list,
	  "WPA-PSK (TKIP) authenticator." },
	{ "wpa2-psk-aes-sup", cmd_wpa_psk,
	  (char *) wpa_psk_cmd_list,
	  "WPA2-PSK (AES) supplicant." },
	{ "wpa2-psk-aes-auth", cmd_wpa_psk,
	  (char *) wpa_psk_cmd_list,
	  "WPA2-PSK (AES) authenticator." },
#if defined(WPS)
	{ "wps-sup-enr", cmd_wps_sup,
	  (char *) wps_sup_enr_cmd_list,
	  "WPS supplicant enrollee." },
	{ "wps-auth-reg", cmd_wps_auth,
	  (char *) wps_auth_reg_cmd_list,
	  "WPS authenticator registrar" },
#endif /* defined(WPS) */
};

/* global fd for cb forward */
int cfg_cb_fd;

struct cfg_info *cfg_alloc(void)
{
	int i;
	for (i=0; i<ARRAYSIZE(topcfg.cfg); i++) {
		if (0 == topcfg.cfg[i].inuse)
			return &topcfg.cfg[i];
	}
	return NULL;
}

void cfg_free(struct cfg_info *cfg)
{
	cfg->inuse = 0;
}

#ifdef CLI_TESTTOOL
#if defined(CALLABLE_MAIN_API)

#define NUM_ARGS	16
int
secfrw_main_str(char *str)
{
	char *argv[NUM_ARGS];
	int argc;
	char *token;

	memset(argv, 0, sizeof(argv));

	argc = 0;
	while ((argc < (NUM_ARGS - 1)) &&
	       ((token = bcmstrtok(&str, " \t\n", NULL)) != NULL)) {
		argv[argc++] = token;
	}
	argv[argc] = NULL;

	return (secfrw_main_args(argc, argv));
}

int
secfrw_main_args(int argc, char **argv)
#else    /* CALLABLE_MAIN_API */
int
main(int argc, char **argv)
#endif   /* CALLABLE_MAIN_API */
{
	int c;
	char line[MAXLINE];
	int status;

	if (0 != process_args(argc, argv))
		return 0;

	/* first cfg is the active default */
	topcfg.active = &topcfg.cfg[0];

	print_choices(choices);

	while (fgets(line, MAXLINE, stdin)) {
		c = strtoul(line, NULL, 10);
		if ( 0 > c || c > ARRAYSIZE(choices) - 2) {
			printf("Illegal choice: try again\n");
			goto reloop;
		}

		printf("Selection: %s\n", choices[c].str);
		status = handle_input_choice(&choices[c]);
		/* terminate */
		if (status < 0)
			break;

reloop:
		print_choices(choices);
	}
	/* exiting */
	printf("quitting\n");
	return 0;
}

int
print_choices( struct input_choice *ch)
{
	int i;
	printf("Enter Selection:\n");
	for ( i = 0; ch[i].str; i++) {
		printf("%d: %s\n", i, ch[i].str);
	}
	if (NULL != topcfg.active) {
		printf("(active cfg: %s)\n", topcfg.active->name);
	} else {
		puts("(no active cfg)");
	}

	return 0;
}

int
handle_input_choice(struct input_choice *ch)
{

	if (ch->fn) {
		return (*ch->fn)(ch->arg);
	}

	return 0;
}

static int
process_args(int argc, char *argv[])
{
	int i, err = 1;
	const struct cmd_info *cmd;

	/* skip program filespec */
	argc--; argv++;

	/* display usage if no args */
	if (argc < 1) {
		cmd_usage(NULL, NULL, &argv);
		goto DONE;
	}

	/* process args */
	while(NULL != *argv) {
		for (i=0; i<ARRAYSIZE(cmd_table); cmd=NULL, i++) {
			cmd = &cmd_table[i];
			if (0 == strcmp(*argv+1, cmd->name))
				break;
		}
		if (NULL == cmd) {
			printf("unexpected %s\n", *argv);
			err = -1;
			goto DONE;
		}
		argv++;
		if (NULL != cmd->action) {
			err = (*cmd->action)(NULL, cmd, &argv);
			if (err)
				goto DONE;
		}
	}

	err = 0;

DONE:
	return err;
}
#endif /* CLI_TESTTOOL */

int
terminate(void *arg)
{
	return -1;
}

void *disp_cfg_thread(void *arg)
{
	printf("%s: %s\n", __FUNCTION__, (char *)arg);
	bcmseclib_run();

	return NULL;
}

/* Init the lib */
int
init_top_level(void *arg)
{
	struct libcfg_info *top = (struct libcfg_info *)arg;
	int status;

	top->maincbfns.main_status = cfg_main_callback;

	status = bcmseclib_init(&top->maincbfns);
	if (status) {
		printf("%s: bcmseclib_init returned error %d\n", __FUNCTION__, status);
		goto done;
	}


	/* create the dispatch thread & run it */
	status = pthread_create( &top->thread1, NULL, disp_cfg_thread, NULL);
	usleep(1000);
	if (status) {
		printf("%s: pthread_create returned error %d\n", __FUNCTION__, status);
		goto done;
	}

done:
	return status;
}

/* deinit the lib */
int
deinit_top_level(void *arg)
{
	printf("%s: \n", __FUNCTION__);

	bcmseclib_deinit();
	return 0;
}

int
print_cfgs(void *arg)
{
	struct libcfg_info *top = arg;
	int i;

	puts("===================\nidx\tid\n===================");
	for (i=0; i<ARRAYSIZE(top->cfg); i++) {
		if (top->cfg[i].inuse) {
			printf("%d\t%s\n", i, top->cfg[i].name);
		}
	}
	puts("===================");
	return 0;
}

int
select_cfg(void *arg)
{
	struct libcfg_info *top = arg;
	char line[MAXLINE];
	int c;

	printf("select cfg index: ");

	while (fgets(line, MAXLINE, stdin)) {
		c = strtoul(line, NULL, 10);
		if ( 0 > c || c > ARRAYSIZE(top->cfg) || 0 == top->cfg[c].inuse) {
			printf("Illegal choice: try again\n");
			goto reloop;
		}

		printf("Selection: %s\n", top->cfg[c].name);
		top->active = &top->cfg[c];
		break;

reloop:
		print_cfgs(arg);
	}
	return 0;
}

/* CB funs registered for
 * top level init status, operational status, cfg status
 */
void
cfg_main_callback(int err)
{
	printf("cfg_main_callback: err %d\n", err);
}

void cfgstatus_cb(void *ctx, clientdata_t * client_data, int status)
{
	struct cb_msg msg;

	if (cfg_cb_fd == 0) {
		printf("%s: descriptor not initialized, bailing\n", __FUNCTION__);
		return;
	}
	memset(&msg, 0, sizeof(msg));

	msg.ctx = ctx;
	msg.client_data = client_data;
	msg.status = status;

	printf("cfgstatus_cb: ctx %p client_data %p status %d\n",
			ctx, client_data, status);

	/* package into message fmt and forward */
	if (forward_cb_message(cfg_cb_fd, (char *)&msg, sizeof(msg))) {
		printf(
			"%s: error forwarding message ctx %p client_data %p status %d\n",
			__FUNCTION__, ctx, client_data, status);
	}

}


/* init a ctx, store the ctx for future reference */
int
init_ctx(void *arg)
{
	struct cfg_info *cfg = ((struct libcfg_info *)arg)->active;
	struct ctxcbs cbfns = {0,};
	int status;
	char buf[128];
	struct cb_msg *pmsg;
	int buflen;

	if (NULL == cfg) {
		puts("No active cfg.  Select one!");
		return 1;
	}

	if (cfg->cb_init == FALSE) {
		if ((status = init_cb_utils(cfg))) {
			printf("%s: error %d initializing cb utils\n",
				__FUNCTION__, status);
			return -1;
		}
	}

	/* init */
	cbfns.cfg_status = cfgstatus_cb;
	/* init a ctx: cfg is our client_data */
	bcmseclib_ctx_init(cfg, &cbfns);
	/* Unpack the message and use contents as appropriate */
	/* ctx pointer comes from cb fun */
	memset(buf, 0, sizeof(buf));
	buflen = sizeof(buf);
	status = wait_for_cb_message(cfg, buf, &buflen);
	if (status < 0) {
		printf("%s: error %d\n", __FUNCTION__, status);
		return 0;
	}

	/* add to cfg */
	pmsg = (struct cb_msg *)buf;
	/* How can this be? */
	if (pmsg->client_data != cfg) {
		printf("%s: cfg cb message not for us cfg %p client_data %p\n",
				__FUNCTION__, cfg, pmsg->client_data);
		return 0;
	}

	if (pmsg->status != 0) {
		printf("%s: cb status %d: failed\n", __FUNCTION__, pmsg->status);
		return 0;
	}
	/* all we wanted/expected from this msg! */
	cfg->cfg_ctx = pmsg->ctx;

	return 0;
}

/* deinit stored ctx */
int
deinit_ctx(void *arg)
{
	struct cfg_info *cfg = ((struct libcfg_info *)arg)->active;
	int status;
	char buf[128];
	struct cb_msg *pmsg;
	int buflen;

	if (NULL == cfg) {
		puts("No active cfg.  Select one!");
		return 1;
	}

	printf("%s(%d) ctx(0x%x): \n", __FUNCTION__, __LINE__, (int)cfg->cfg_ctx);
	bcmseclib_ctx_cleanup(cfg->cfg_ctx);

	/* Unpack the message and use contents as appropriate */
	memset(buf, 0, sizeof(buf));
	buflen = sizeof(buf);
	status = wait_for_cb_message(cfg, buf, &buflen);
	if (status < 0) {
		printf("%s: error %d\n", __FUNCTION__, status);
		return 0;
	}
	pmsg = (struct cb_msg *)buf;
	if (pmsg->client_data != cfg) {
		printf("%s: cfg cb message not for us cfg %p client_data %p\n",
				__FUNCTION__, cfg, pmsg->client_data);
		return 0;
	}
	if (pmsg->status != 0) {
		printf("%s: cb status %d: failed\n", __FUNCTION__, pmsg->status);
		return 0;
	}
	return 0;
}

/* Set cfg for supplied ctx handle */
int
set_ctx_cfg(void *arg)
{
	struct cfg_info *cfg = ((struct libcfg_info *)arg)->active;
	int status;
	char buf[128];
	struct cb_msg *pmsg;
	int buflen;

	if (NULL == cfg) {
		puts("No active cfg.  Select one!");
		return 1;
	}

	bcmseclib_set_config(&cfg->sec_cfg, cfg->cfg_ctx);
	/* Unpack the message and use contents as appropriate */
	memset(buf, 0, sizeof(buf));
	buflen = sizeof(buf);
	status = wait_for_cb_message(cfg, buf, &buflen);
	if (status < 0) {
		printf("%s: error %d\n", __FUNCTION__, status);
		return 0;
	}
	pmsg = (struct cb_msg *)buf;
	if (pmsg->client_data != cfg) {
		printf("%s: cfg cb message not for us cfg %p client_data %p\n",
				__FUNCTION__, cfg, pmsg->client_data);
		return 0;
	}
	if (pmsg->status != 0) {
		printf("%s: cb status %d: failed\n", __FUNCTION__, pmsg->status);
		return 0;
	}
	return 0;
}

/* These utilities use a pipe. Other methods are possible. */
int
init_cb_utils(struct cfg_info *cfg)
{
	if (cfg->cb_init == TRUE) {
		printf("%s: already initialized, bailing\n", __FUNCTION__);
		return 0;
	}

	if (pipe(cfg->pipefd) < 0) {
		printf("%s: failed to init pipe\n", __FUNCTION__);
		return -1;
	}
	cfg->cb_init = TRUE;
	cfg_cb_fd = cfg->pipefd[1];

	return 0;
}

int
forward_cb_message(int fd, char *msg, int len)
{
	int status;

	status = write(fd, msg, len);
	if (status != len) {
		printf("%s: write to descriptor %d failed status %d\n",
			__FUNCTION__, fd,  status);
		return -1;
	}
	return 0;
}

int
wait_for_cb_message(struct cfg_info *cfg, char *buf, int *buflen)
{
	int n;
	int status;
	struct timeval t;
	fd_set rdfdset;
	int width = 0;

	memset(&t, 0, sizeof(t));
	t.tv_sec = 1;
	t.tv_usec = 0;


	FD_ZERO(&rdfdset);
	FD_SET(cfg->pipefd[0], &rdfdset);
	width = cfg->pipefd[0];
	status = select(width + 1, (void *)&rdfdset, NULL, NULL, &t);

	if (status < 0) {
		printf("%s: select returned error %d errno %d\n",
			__FUNCTION__, status, errno);
		return -1;
	}

	if (!FD_ISSET(cfg->pipefd[0], &rdfdset)) {
		printf("%s: ERROR: descriptor not readable\n", __FUNCTION__);
		return -1;
	}

	n = read(cfg->pipefd[0], buf, *buflen);
	if (n <= 0) {
		printf("%s: read from pipe failed status %d\n", __FUNCTION__, n);
		return -1;
	}
	*buflen = n;
	return 0;
}

static int
cmd_usage(void *unused, const struct cmd_info *info, char ***argv)
{
	int i;
	const struct cmd_info *cmd;

	(void)unused;
	(void)info;

	puts(usage_str);
	for (i=0; i<ARRAYSIZE(cmd_table); i++) {
		cmd = &cmd_table[i];
		printf("-%s %s\n%s\n\n", cmd->name, cmd->syntax, cmd->desc);
	}
	return 1;
}

static int
cmd_list_services(void *unused, const struct cmd_info *info, char ***argv)
{
	int i;

	(void)unused;
	(void)info;
	(void)argv;

	for (i=0; i<ARRAYSIZE(service_table); i++) {
		const struct cmd_info *p = &service_table[i];
		printf("%s\n", p->name);
	}
	printf("\n");
	return 1;
}

static int
cmd_service_opts(void *unused, const struct cmd_info *info, char ***argv)
{
	int i;
	const char *svc_name;
	const struct cmd_info **svc_params=NULL;

	(void)unused;
	(void)info;

	if (!is_arg(*argv)) {
		printf("missing arg: service name\n");
		return 1;
	}
	svc_name = **argv;

	/* locate the param list for the service */
	for (i=0; i<ARRAYSIZE(service_table); i++) {
		const struct cmd_info *svc = &service_table[i];
		if (0 == strcmp(svc_name, svc->name)) {
			svc_params = (const struct cmd_info **)svc->syntax;
			break;
		}
	}

	/* service name not found: bail */
	if (NULL == svc_params) {
		printf("bad service name: %s\n", svc_name);
		goto DONE;
	}

	/* got the service param list */
	while (NULL != *svc_params) {
		const struct cmd_info *svc_cmd;
		/* find service param in service command table */
		for (i=0; i<ARRAYSIZE(service_cmd_table); svc_cmd=NULL, i++) {
			svc_cmd = &service_cmd_table[i];
			if (0 == strcmp((*svc_params)->name, svc_cmd->name))
				break;
		}
		/* couldn't find param: bail */
		if (NULL == svc_cmd) {
			printf("internal error: unknown service command %s\n",
				   (*svc_params)->name);
			goto DONE;
		}
		printf("-%s %s\n%s\n\n", svc_cmd->name, svc_cmd->syntax,
			   svc_cmd->desc);
		svc_params++;
	}

DONE:
	return 1;
}

static int
process_wlan_service_args(struct sec_args *cfg, char ***argv)
{
	int i, err = -1;
	char *svc_name;
	const struct cmd_info **svc_param, *svc;
	char **svcarg;

	/* optional -c <idx> */
	if (!strcmp("-c", **argv)) {
		if (!is_arg(*argv+1)) {
			printf("expected -c <idx>\n");
			goto DONE;
		}
		cfg->bsscfg_index = atoi(*(*argv+1));
		*argv+=2;
	}

	/* expecting <service> */
	if (!is_arg(*argv)) {
		printf("expected <service>\n");
		goto DONE;
	}
	svc_name = **argv;
	(*argv)++;

	/* lookup the service param list */
	for (i=0; i<ARRAYSIZE(service_table); svc=NULL, i++) {
		svc = &service_table[i];
		if (0 == strcmp(svc_name, svc->name)) {
			break;
		}
	}

	/* service name not found: bail */
	if (NULL == svc) {
		printf("bad service name: %s\n", svc_name);
		goto DONE;
	}

	/* execute service specific actions */
	if (NULL != svc->action) {
		if ((*svc->action)(cfg, svc, argv))
			goto DONE;
	}

	svc_param = (const struct cmd_info **)svc->syntax;

	/* loop thru all the expected service options and match
	 * them with what was provided
	*/
	for (i=0; NULL != svc_param[i]; i++) {
		svcarg = *argv;
		while (NULL != *svcarg) {
			if (   is_opt(svcarg)
				&& 0 == strcmp(svc_param[i]->name, *svcarg+1))
			{	/* found */
				break;
			}
			svcarg++;
		}
		if (NULL == *svcarg) {
			printf("expected -%s\n", svc_param[i]->name);
			goto DONE;
		}
	}

	/* process argv until we encounter one that isn't in the expected
	 * list
	*/
	svcarg = *argv;
	while (NULL != *svcarg) {
		/* is the option in the list? */
		for (i=0; NULL != svc_param[i]; i++) {
			if (0 == strcmp(*svcarg+1, svc_param[i]->name))
				break;
		}
		/* not found */
		if (NULL == svc_param[i])
			break;
		/* do action */
		svcarg++;
		if (NULL != svc_param[i]->action) {
			if ((*svc_param[i]->action)(cfg, svc_param[i], &svcarg))
				goto DONE;
		}
	}

	*argv = svcarg;

	err = 0;

DONE:
	return err;
}

static int
process_cfg(int service, const char cfg_end[], char ***argv)
{
	int err = -1;
	struct cfg_info *ctx;
	struct sec_args *cfg;

	/* alloc a context */
	ctx = cfg_alloc();
	if (NULL == ctx) {
		printf("exceeded cfg limit\n");
		goto DONE;
	}
	cfg = &ctx->sec_cfg;

	/* initialize stuff given to us */
	cfg->service = service;

	/* initialize optional options */
	cfg->bsscfg_index = 0;

	/* expecting -id <name> */
	if (strcmp("-id", **argv) || !is_arg(*argv+1)) {
		printf("expected -id <name>\n");
		goto DONE;
	}
	ctx->name = *(*argv+1);
	*argv+=2;

	/* expecting -a <name> */
	if (strcmp("-a", **argv) || !is_arg(*argv+1)) {
		printf("expected -a <name>\n");
		goto DONE;
	}
	strncpy(cfg->ifname, *(*argv+1), sizeof(cfg->ifname));
	cfg->ifname[sizeof(cfg->ifname)-1] = '\0';
	*argv+=2;

	if (0 == service) {
		if (process_wlan_service_args(cfg, argv))
			goto DONE;
	}
	else if (1 == service) {
		cfg->role = 2;
		cfg->service = 0;
	}

	/* expecting cfg terminator */
	if (   !is_opt(*argv)
		|| 0 != strcmp(cfg_end, **argv))
	{
		printf("expected %s\n", cfg_end);
		goto DONE;
	}
	*argv+=1;

	/* it's a keeper */
	ctx->inuse = 1;

	err = 0;

DONE:
	return err;
}

static int
cmd_wlan_start(void *unused, const struct cmd_info *info, char ***argv)
{
	return process_cfg(0 /*wlan*/, "-wlan-end", argv);
}

static int
cmd_bt_start(void *unused, const struct cmd_info *info, char ***argv)
{
	return process_cfg(1 /*btamp*/, "-bt-end", argv);
}

static int
cmd_wpa_psk(void *arg, const struct cmd_info *info, char ***argv)
{
	struct sec_args *cfg = arg;

	(void)argv;

	if (0 == strcmp("wpa-psk-tkip-sup", info->name)) {
		cfg->role = 0;
		cfg->WPA_auth = 4;
		cfg->wsec = 2;
	} else if (0 == strcmp("wpa-psk-tkip-auth", info->name)) {
		cfg->role = 1;
		cfg->WPA_auth = 4;
		cfg->wsec = 2;
	} else if (0 == strcmp("wpa2-psk-aes-sup", info->name)) {
		cfg->role = 0;
		cfg->WPA_auth = 0x80;
		cfg->wsec = 4;
	} else if (0 == strcmp("wpa2-psk-aes-auth", info->name)) {
		cfg->role = 1;
		cfg->WPA_auth = 0x80;
		cfg->wsec = 4;
	} else {
		printf("unknown service name %s\n", info->name);
		return 1;
	}
	return 0;
}

#if defined(WPS)

static int
cmd_wps_sup(void *arg, const struct cmd_info *info, char ***argv)
{
	struct sec_args *cfg = arg;

	cfg->role = 3;
	return 0;
}

static int
cmd_wps_auth(void *arg, const struct cmd_info *info, char ***argv)
{
	struct sec_args *cfg = arg;

	cfg->role = 4;
	cfg->key_index = 0;
	return 0;
}
#endif /* defined(WPS) */

static int
cmd_ssid(void *arg, const struct cmd_info *info, char ***argv)
{
	struct sec_args *cfg = arg;
	const char *ssid;
	int len;

	(void)info;

	if (!is_arg(*argv)) {
		printf("expected <ssid> %s\n", **argv);
		return 1;
	}
	ssid = **argv;
	*argv+=1;

	len = MIN(strlen(ssid), sizeof(cfg->ssid));
	if (len > 0)
		memcpy(cfg->ssid, ssid, len);
	cfg->ssid_len = len;

	return 0;
}

static int
cmd_psk(void *arg, const struct cmd_info *info, char ***argv)
{
	struct sec_args *cfg = arg;
	const char *psk;
	int len;

	(void)info;

	if (!is_arg(*argv)) {
		printf("expected <psk>\n");
		return 1;
	}
	psk = **argv;
	*argv+=1;

	len = strlen(psk);
	if (len < 8 || len > 63) {
		printf("passphrase must be between 8 and 63 characters\n");
		return 1;
	}

	cfg->psk_len = len;
	memcpy(cfg->psk, psk, len);

	return 0;
}

static int
cmd_pin(void *arg, const struct cmd_info *info, char ***argv)
{
	struct sec_args *cfg = arg;
	const char *pin;
	int len;

	if (!is_arg(*argv)) {
		printf("expected <pin>\n");
		return 1;
	}
	pin = **argv;
	*argv+=1;

	len = strlen(pin);
	if (len == 0 || len > 8) {
		printf("pin must be between 1 and 8 digits\n");
		return 1;
	}

	strcpy(cfg->pin, pin);

	return 0;
}

// Encryption type
typedef enum {
	BRCM_WPS_ENCRTYPE_NONE,
	BRCM_WPS_ENCRTYPE_WEP,
	BRCM_WPS_ENCRTYPE_TKIP,
	BRCM_WPS_ENCRTYPE_AES
} brcm_wpscli_encrtype;

// Authentication type
typedef enum {
	BRCM_WPS_AUTHTYPE_OPEN,
	BRCM_WPS_AUTHTYPE_SHARED,
	BRCM_WPS_AUTHTYPE_WPAPSK,
	BRCM_WPS_AUTHTYPE_WPA2PSK
} brcm_wpscli_authtype;

static int
cmd_wps_sec(void *arg, const struct cmd_info *info, char ***argv)
{
	struct sec_args *cfg = arg;
	const char *val;

	if (!is_arg(*argv)) {
		printf("expected <wpa_sec>\n");
		return 1;
	}
	val = **argv;
	*argv+=1;

	if (0 == strcmp("wpa-psk-tkip", val)) {
		cfg->WPA_auth = BRCM_WPS_AUTHTYPE_WPAPSK;
		cfg->wsec = BRCM_WPS_ENCRTYPE_TKIP;
	} else
	if (0 == strcmp("wpa-psk-aes", val)) {
		cfg->WPA_auth = BRCM_WPS_AUTHTYPE_WPAPSK;
		cfg->wsec = BRCM_WPS_ENCRTYPE_AES;
	} else
	if (0 == strcmp("wpa2-psk-tkip", val)) {
		cfg->WPA_auth = BRCM_WPS_AUTHTYPE_WPA2PSK;
		cfg->wsec = BRCM_WPS_ENCRTYPE_TKIP;
	} else
	if (0 == strcmp("wpa2-psk-aes", val)) {
		cfg->WPA_auth = BRCM_WPS_AUTHTYPE_WPA2PSK;
		cfg->wsec = BRCM_WPS_ENCRTYPE_AES;
	} else
	if (0 == strcmp("open", val)) {
		cfg->WPA_auth = BRCM_WPS_AUTHTYPE_OPEN;
		cfg->wsec = BRCM_WPS_ENCRTYPE_NONE;
	} else
	if (0 == strcmp("open-wep", val)) {
		cfg->WPA_auth = BRCM_WPS_AUTHTYPE_OPEN;
		cfg->wsec = BRCM_WPS_ENCRTYPE_WEP;
	} else
	if (0 == strcmp("shared-wep", val)) {
		cfg->WPA_auth = BRCM_WPS_AUTHTYPE_SHARED;
		cfg->wsec = BRCM_WPS_ENCRTYPE_WEP;
	} else {
		printf("unknown wpa security type %s\n", val);
		return 1;
	}
	return 0;
}

#ifdef HSL_INTEGRATION
/* Following functions are the interface to HSL */

/* Called from p2papi_open() */
void
hslif_init()
{
	/* first cfg is the active default */
	topcfg.active = &topcfg.cfg[0];

	/* top level */
	init_top_level(&topcfg);
}

/* Called from p2papi_close() */
void
hslif_deinit()
{

	deinit_top_level(&topcfg);
}

/* init a ctx */
void *
hslif_init_ctx()
{
	int status;
	char *funstr = "hslif_init_ctx";

	status = init_ctx(&topcfg);

	if (status) {
		PRINT(("%s: init_ctx failed status %d\n", funstr, status));
		return NULL;
	}

	return topcfg.cfg[0].cfg_ctx;
}

/* deinit a ctx */
void
hslif_deinit_ctx(void *ctx)
{
	deinit_ctx(&topcfg);
}

/* Called to cfg a ctx */
int
hslif_set_cfg(void *ctx, char if_name[], int bsscfg_index, int role, char in_ssid[], int WPA_auth, int wsec, char key[])
{
	struct cfg_info *cfg = &topcfg.cfg[0];
	struct sec_args *sec_cfg = &cfg->sec_cfg;
	char *funstr = "hslif_set_cfg";

	PRINT(("%s: ifname %s, bsscfg_index %d, role %d, ssid %s, wpa_auth %d, wsec %d, key %s\n",
			funstr, if_name, bsscfg_index, role, in_ssid, WPA_auth, wsec, key));
	/* set a cfg */
	memset(sec_cfg, 0, sizeof(struct sec_args));

	memcpy(sec_cfg->ifname, if_name, strlen(if_name) + 1);
	sec_cfg->service = 0;	/* not used? */
	sec_cfg->role = role;		/* auth: 1, supp: 0 */
	sec_cfg->WPA_auth = WPA_auth;
	sec_cfg->wsec = wsec;

	memcpy(sec_cfg->ssid, in_ssid, strlen(in_ssid));
	sec_cfg->ssid_len = strlen(in_ssid);

	memcpy(sec_cfg->psk, key, strlen(key));
	sec_cfg->psk_len = strlen(key);

	sec_cfg->bsscfg_index = bsscfg_index;

	return set_ctx_cfg(&topcfg);
}
#endif /* HSL_INTEGRATION */
