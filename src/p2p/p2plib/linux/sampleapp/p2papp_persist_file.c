/* P2P APP persistent credentials support.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2papp_persist_file.c,v 1.3 2010-12-24 00:59:11 $
 */

/* Implements persistent credentials support using Linux filesystem */

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>

#include "BcmP2PAPI.h"
#include "p2plib_osl.h"


#define FILENAME_SIZE 	128
#ifndef TARGETENV_android
#define PERSIST_DIR	"./persist"		/* directory for persistent data files */
#else
#define PERSIST_DIR	"/data/local/persist"		/* directory for persistent data files */
#endif /* !TARGETENV_android */

static char *get_filename(char *buffer, BCMP2P_ETHER_ADDR *addr)
{
	sprintf(buffer, "%s/%02x%02x%02x%02x%02x%02x", PERSIST_DIR,
		addr->octet[0], addr->octet[1],	addr->octet[2],
		addr->octet[3],	addr->octet[4], addr->octet[5]);
	return buffer;
}

static BCMP2P_ETHER_ADDR *strtoaddr(char *str, BCMP2P_ETHER_ADDR *addr)
{
	if (sscanf(str, "%02x%02x%02x%02x%02x%02x",
		(unsigned int *)&addr->octet[0],
		(unsigned int *)&addr->octet[1],
		(unsigned int *)&addr->octet[2],
		(unsigned int *)&addr->octet[3],
		(unsigned int *)&addr->octet[4],
		(unsigned int *)&addr->octet[5]) == 6) {
		return addr;
	}
	return 0;
}

static BCMP2P_BOOL find_valid_file(BCMP2P_ETHER_ADDR *addr)
{
	BCMP2P_BOOL is_found = BCMP2P_FALSE;
	DIR *dp;
	struct dirent *dir_entry;

	dp = opendir(PERSIST_DIR);
	if (dp == 0)
		return 0;

	while ((dir_entry = readdir(dp))) {
		BCMP2P_ETHER_ADDR temp;
		if (strtoaddr(dir_entry->d_name, &temp)) {
			memcpy(addr, &temp, sizeof(*addr));
			is_found = BCMP2P_TRUE;
			break;
		}
	}

	closedir(dp);
	return is_found;
}

BCMP2P_BOOL p2papp_persist_save(BCMP2P_PERSISTENT *persist)
{
	char fname[FILENAME_SIZE];
	FILE *fp;

#ifdef TARGETENV_android
	char cmd[80];
#endif /* TARGETENV_android */

	if (persist == 0)
		return BCMP2P_FALSE;

#ifndef TARGETENV_android
	/* create directory */
	if (mkdir(PERSIST_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0) {
		/* directory may exist */
		if (errno != EEXIST) {
			printf("%s failed to create dir %s\n", __FUNCTION__, PERSIST_DIR);
		}
	}
#else
	snprintf(cmd, sizeof(cmd), "mkdir %s\n", PERSIST_DIR);
	system(cmd);
#endif /* !TARGETENV_android */

	/* save persistent data in file */
	fp = fopen(get_filename(fname, &persist->peer_dev_addr), "w");
	if (fp == 0)
		return BCMP2P_FALSE;

	fprintf(fp, "%d\n", persist->is_go ? 1 : 0);
	fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x\n",
		persist->peer_dev_addr.octet[0], persist->peer_dev_addr.octet[1],
		persist->peer_dev_addr.octet[2], persist->peer_dev_addr.octet[3],
		persist->peer_dev_addr.octet[4], persist->peer_dev_addr.octet[5]);
	fprintf(fp, "%s\n", persist->ssid);
	fprintf(fp, "%s\n", persist->pmk);
	if (persist->is_go)
		fprintf(fp, "%s\n", persist->passphrase);

	fclose(fp);
	return BCMP2P_TRUE;
}

BCMP2P_BOOL p2papp_persist_delete(BCMP2P_ETHER_ADDR *addr)
{
	char fname[FILENAME_SIZE];

	if (addr == 0)
		return BCMP2P_FALSE;

	/* delete persistent data file */
	if (remove(get_filename(fname, addr)) != 0)
		return BCMP2P_FALSE;

	return BCMP2P_TRUE;
}

BCMP2P_BOOL p2papp_persist_delete_all(void)
{
	BCMP2P_ETHER_ADDR addr;

	while (find_valid_file(&addr)) {
		p2papp_persist_delete(&addr);
	}
	return BCMP2P_TRUE;
}

BCMP2P_PERSISTENT *p2papp_persist_find_addr(BCMP2P_ETHER_ADDR *addr,
	BCMP2P_PERSISTENT *persist)
{
	char fname[FILENAME_SIZE];
	FILE *fp;

	if (addr == 0 || persist == 0)
		return 0;

	/* read persistent data from file */
	fp = fopen(get_filename(fname, addr), "r");
	if (fp == 0)
		return 0;

	if (fscanf(fp, "%d\n", &persist->is_go) != 1)
		goto fail;
	if (fscanf(fp, "%02x:%02x:%02x:%02x:%02x:%02x\n",
		(unsigned int *)&persist->peer_dev_addr.octet[0],
		(unsigned int *)&persist->peer_dev_addr.octet[1],
		(unsigned int *)&persist->peer_dev_addr.octet[2],
		(unsigned int *)&persist->peer_dev_addr.octet[3],
		(unsigned int *)&persist->peer_dev_addr.octet[4],
		(unsigned int *)&persist->peer_dev_addr.octet[5]) != 6)
		goto fail;
	/*if (fscanf(fp, "%s\n", persist->ssid) != 1) note: %s stops at whitespace */
	if (fscanf(fp, "%32[^\n]\n", persist->ssid) != 1)
		goto fail;
	
	if (fscanf(fp, "%s\n", persist->pmk) != 1)
		goto fail;
	if (persist->is_go) {
		if (fscanf(fp, "%s\n", persist->passphrase) != 1)
			goto fail;
	}

	fclose(fp);
	return persist;

fail:
	fclose(fp);
	return 0;
}

BCMP2P_PERSISTENT *p2papp_persist_find_ssid(char *ssid,
	BCMP2P_PERSISTENT *persist)
{
	BCMP2P_PERSISTENT *found = 0;
	DIR *dp;
	struct dirent *dir_entry;

	if (ssid == 0 || persist == 0)
		return 0;

	dp = opendir(PERSIST_DIR);
	if (dp == 0)
		return 0;

	while ((dir_entry = readdir(dp))) {
		BCMP2P_ETHER_ADDR addr;
		BCMP2P_PERSISTENT data;
		if (p2papp_persist_find_addr(
			strtoaddr(dir_entry->d_name, &addr), &data)) {
			if (strncmp((char *)data.ssid, ssid, sizeof(data.ssid)) == 0) {
				memcpy(persist, &data, sizeof(*persist));
				found = persist;
			}
		}
	}

	closedir(dp);
	return found;
}

static char go_ssid[BCMP2P_MAX_SSID_LEN + 1];
const char *p2papp_persist_get_go_ssid(void)
{
	DIR *dp;
	struct dirent *dir_entry;

	memset( go_ssid, 0x00, sizeof(go_ssid));

	dp = opendir(PERSIST_DIR);
	if (dp == 0)
		return NULL;

	while ((dir_entry = readdir(dp))) {
		if (strncmp(dir_entry->d_name, "DIRECT-", 7) == 0) {
			strncpy(go_ssid, dir_entry->d_name, sizeof(go_ssid));
			if (strlen(go_ssid) < BCMP2P_MAX_SSID_LEN) {
				break;
			}
			memset( go_ssid, 0x00, sizeof(go_ssid));
		}
	}

	closedir(dp);

	if (go_ssid[0] != '\0')
	{
		BCMP2PLOG((BCMP2P_LOG_ALWAYS, TRUE, "Found Previous Flames GO SSID %s\n", go_ssid));
		return go_ssid;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "No GO SSID found\n"));
	return NULL;
}

BCMP2P_BOOL p2papp_persist_save_go_ssid(const char *ssid)
{
	/*
	 * use ssid name as file name
	 * for now, we just set a dummy string in the file
	 */
	char fname[80];
	FILE *fp;

#ifdef TARGETENV_android
	char cmd[80];
#endif /* TARGETENV_android */

	if (ssid == NULL)
		return BCMP2P_FALSE;

#ifndef TARGETENV_android
	/* create directory */
	if (mkdir(PERSIST_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0) {
		/* directory may exist */
		if (errno != EEXIST) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "%s failed to create dir %s\n", __FUNCTION__, PERSIST_DIR));
		}
	}
#else
	snprintf(cmd, sizeof(cmd), "mkdir %s\n", PERSIST_DIR);
	system(cmd);
#endif /* !TARGETENV_android */

	sprintf(fname, "%s/%s", PERSIST_DIR, ssid);

	fp = fopen(fname, "w");
	if (fp == 0)
		return BCMP2P_FALSE;

	fprintf(fp, "Persist Group ID %s\n", ssid);
	fclose(fp);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "Saved Flames GO SSID %s\n", ssid));

	return BCMP2P_TRUE;
}
