/*
 * wl bta command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_bta.c 458728 2014-02-27 18:15:25Z $
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

#include <proto/bt_amp_hci.h>

static cmd_func_t wl_HCI_cmd;
static cmd_func_t wl_HCI_ACL_data;
static cmd_func_t wl_get_btamp_log;

static cmd_t wl_bta_cmds[] = {
	{ "HCI_cmd", wl_HCI_cmd, WLC_GET_VAR, WLC_SET_VAR,
	"carries HCI commands to the driver\n"
	"\tusage: wl HCI_cmd <command> <args>" },
	{ "HCI_ACL_data", wl_HCI_ACL_data, WLC_GET_VAR, WLC_SET_VAR,
	"carries HCI ACL data packet to the driver\n"
	"\tusage: wl HCI_ACL_data <logical link handle> <data>" },
	{ "btamp_statelog", wl_get_btamp_log, WLC_GET_VAR, WLC_SET_VAR,
	"Return state transistion log of BTAMP" },
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_bta_module_init(void)
{
	(void)g_swap;

	/* get the global buf */
	buf = wl_get_buf();

	/* register bta commands */
	wl_module_cmds_register(wl_bta_cmds);
}

#define MATCH_OP(op, opstr)	(strlen(op) == strlen(opstr) && strncmp(op, opstr, strlen(op)) == 0)

static int
wl_HCI_cmd(void *wl, cmd_t *cmd, char **argv)
{
	union {
		char buf[HCI_CMD_PREAMBLE_SIZE + HCI_CMD_DATA_SIZE];
		uint32 alignme;
	} cbuf;
	amp_hci_cmd_t *cpkt = (amp_hci_cmd_t *)&cbuf.buf[0];
	char *op;
	uint8 plen;

	UNUSED_PARAMETER(cmd);

	if (!*++argv)
		return BCME_USAGE_ERROR;

	/* recognize and encode operations */
	op = *argv++;
	if (MATCH_OP(op, "Read_Link_Quality")) {
		cpkt->opcode = HCI_Read_Link_Quality;
	} else if (MATCH_OP(op, "Read_Local_AMP_Info")) {
		cpkt->opcode = HCI_Read_Local_AMP_Info;
	} else if (MATCH_OP(op, "Read_Local_AMP_ASSOC")) {
		cpkt->opcode = HCI_Read_Local_AMP_ASSOC;
	} else if (MATCH_OP(op, "Write_Remote_AMP_ASSOC")) {
		cpkt->opcode = HCI_Write_Remote_AMP_ASSOC;
	} else if (MATCH_OP(op, "Create_Physical_Link")) {
		cpkt->opcode = HCI_Create_Physical_Link;
	} else if (MATCH_OP(op, "Accept_Physical_Link_Request")) {
		cpkt->opcode = HCI_Accept_Physical_Link_Request;
	} else if (MATCH_OP(op, "Disconnect_Physical_Link")) {
		cpkt->opcode = HCI_Disconnect_Physical_Link;
	} else if (MATCH_OP(op, "Create_Logical_Link")) {
		cpkt->opcode = HCI_Create_Logical_Link;
	} else if (MATCH_OP(op, "Accept_Logical_Link")) {
		cpkt->opcode = HCI_Accept_Logical_Link;
	} else if (MATCH_OP(op, "Disconnect_Logical_Link")) {
		cpkt->opcode = HCI_Disconnect_Logical_Link;
	} else if (MATCH_OP(op, "Logical_Link_Cancel")) {
		cpkt->opcode = HCI_Logical_Link_Cancel;
	} else if (MATCH_OP(op, "Short_Range_Mode")) {
		cpkt->opcode = HCI_Short_Range_Mode;
	} else if (MATCH_OP(op, "Read_Connection_Accept_Timeout")) {
		cpkt->opcode = HCI_Read_Connection_Accept_Timeout;
	} else if (MATCH_OP(op, "Write_Connection_Accept_Timeout")) {
		cpkt->opcode = HCI_Write_Connection_Accept_Timeout;
	} else if (MATCH_OP(op, "Read_Link_Supervision_Timeout")) {
		cpkt->opcode = HCI_Read_Link_Supervision_Timeout;
	} else if (MATCH_OP(op, "Write_Link_Supervision_Timeout")) {
		cpkt->opcode = HCI_Write_Link_Supervision_Timeout;
	} else if (MATCH_OP(op, "Reset")) {
		cpkt->opcode = HCI_Reset;
	} else if (MATCH_OP(op, "Enhanced_Flush")) {
		cpkt->opcode = HCI_Enhanced_Flush;
	} else if (MATCH_OP(op, "Read_Best_Effort_Flush_Timeout")) {
		cpkt->opcode = HCI_Read_Best_Effort_Flush_Timeout;
	} else if (MATCH_OP(op, "Write_Best_Effort_Flush_Timeout")) {
		cpkt->opcode = HCI_Write_Best_Effort_Flush_Timeout;
	} else if (MATCH_OP(op, "Read_Logical_Link_Accept_Timeout")) {
		cpkt->opcode = HCI_Read_Logical_Link_Accept_Timeout;
	} else if (MATCH_OP(op, "Write_Logical_Link_Accept_Timeout")) {
		cpkt->opcode = HCI_Write_Logical_Link_Accept_Timeout;
	} else if (MATCH_OP(op, "Read_Buffer_Size")) {
		cpkt->opcode = HCI_Read_Buffer_Size;
	} else if (MATCH_OP(op, "Read_Data_Block_Size")) {
		cpkt->opcode = HCI_Read_Data_Block_Size;
	} else if (MATCH_OP(op, "Set_Event_Mask_Page_2")) {
		cpkt->opcode = HCI_Set_Event_Mask_Page_2;
	} else if (MATCH_OP(op, "Flow_Spec_Modify")) {
		cpkt->opcode = HCI_Flow_Spec_Modify;
	} else if (MATCH_OP(op, "Read_Local_Version_Info")) {
		cpkt->opcode = HCI_Read_Local_Version_Info;
	} else if (MATCH_OP(op, "Read_Local_Supported_Commands")) {
		cpkt->opcode = HCI_Read_Local_Supported_Commands;
	} else if (MATCH_OP(op, "Read_Failed_Contact_Counter")) {
		cpkt->opcode = HCI_Read_Failed_Contact_Counter;
	} else if (MATCH_OP(op, "Reset_Failed_Contact_Counter")) {
		cpkt->opcode = HCI_Reset_Failed_Contact_Counter;
	} else {
		printf("unsupported HCI command: %s\n", op);
		return BCME_UNSUPPORTED;
	}

	plen = 0;
	while (*argv && (plen < HCI_CMD_DATA_SIZE)) {
		cpkt->parms[plen++] = (uint8)strtol(*argv++, NULL, 0);
	}
	cpkt->plen = plen;

	return wlu_var_setbuf(wl, cmd->name, cpkt, HCI_CMD_PREAMBLE_SIZE + plen);
}

static int
wl_HCI_ACL_data(void *wl, cmd_t *cmd, char **argv)
{
	amp_hci_ACL_data_t *dpkt;
	uint16 dlen;
	int ret;

	if (!*++argv)
		return BCME_USAGE_ERROR;

	dpkt = (amp_hci_ACL_data_t *) malloc(HCI_ACL_DATA_PREAMBLE_SIZE + 2048);
	if (!dpkt)
		return BCME_NOMEM;

	/* get logical link handle */
	dpkt->handle = (HCI_ACL_DATA_BC_FLAGS | HCI_ACL_DATA_PB_FLAGS);
	dpkt->handle |= (uint16)strtol(*argv++, NULL, 0);

	/* get data */
	dlen = 0;
	while (*argv && (dlen < 2048)) {
		dpkt->data[dlen++] = (uint8)strtol(*argv++, NULL, 0);
	}
	dpkt->dlen = dlen;

	ret = wlu_var_setbuf(wl, cmd->name, dpkt, HCI_ACL_DATA_PREAMBLE_SIZE + dlen);

	free(dpkt);
	return ret;
}

static int
wl_get_btamp_log(void *wl, cmd_t *cmd, char **argv)
{
	int err, i, j;
	char *val_name;
	uint8 *state;
	uint8 idx = 0;
	void *ptr = buf;

	UNUSED_PARAMETER(cmd);

	/* command name */
	val_name = *argv++;

	if (!*argv) {
		if ((err = wlu_var_getbuf_sm (wl, cmd->name, NULL, 0, &ptr)))
			return err;
		state = (uint8 *)ptr;
		idx = *state++;

		for (i = 0; i < BTA_STATE_LOG_SZ; i++, idx--) {
			j = (idx & (BTA_STATE_LOG_SZ - 1));
			switch (state[j]) {
				case HCIReset:
					printf("%2d: HCI Reset\n", state[j]);
					break;
				case HCIReadLocalAMPInfo:
					printf("%2d: HCI Read Local AMPInfo\n", state[j]);
					break;
				case HCIReadLocalAMPASSOC:
					printf("%2d: HCI Read Local AMPASSOC\n", state[j]);
					break;
				case HCIWriteRemoteAMPASSOC:
					printf("%2d: HCI Write Remote AMPASSOC\n", state[j]);
					break;
				case HCICreatePhysicalLink:
					printf("%2d: HCI Create Physical Link\n", state[j]);
					break;
				case HCIAcceptPhysicalLinkRequest:
					printf("%2d: HCI Accept Physical Link Request\n", state[j]);
					break;
				case HCIDisconnectPhysicalLink:
					printf("%2d: HCI Disconnect Physical Link\n", state[j]);
					break;
				case HCICreateLogicalLink:
					printf("%2d: HCI Create Logical Link\n", state[j]);
					break;
				case HCIAcceptLogicalLink:
					printf("%2d: HCI Accept Logical Link\n", state[j]);
					break;
				case HCIDisconnectLogicalLink:
					printf("%2d: HCI Disconnect Logical Link\n", state[j]);
					break;
				case HCILogicalLinkCancel:
					printf("%2d: HCI Logical Link Cancel\n", state[j]);
					break;
				case HCIAmpStateChange:
					printf("%2d: HCI Amp State Change\n", state[j]);
					break;
				default:
					break;
			}
		}
		return 0;
	} else
		err = wlu_iovar_setint(wl, val_name, (int)idx);

	return err;
}
