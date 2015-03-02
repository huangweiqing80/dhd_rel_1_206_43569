/*
 * wl keep_alive command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_keep_alive.c 458728 2014-02-27 18:15:25Z $
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

static cmd_func_t wl_keep_alive;

static cmd_t wl_keep_alive_cmds[] = {
	{"mkeep_alive", wl_mkeep_alive, WLC_GET_VAR, WLC_SET_VAR,
	"Send specified \"mkeep-alive\" packet periodically.\n"
	"\tUsage: wl mkeep_alive <index0-3> <period> <packet>\n"
	"\t\tindex: 0 - 3.\n"
	"\t\tperiod: Re-transmission period in milli-seconds. 0 to disable packet transmits.\n"
	"\t\tpacket: Hex packet contents to transmit. The packet contents should include "
	"the entire ethernet packet (ethernet header, IP header, UDP header, and UDP "
	"payload) specified in network byte order. If no packet is specified, a nulldata frame "
	"will be sent instead.\n"
	"\n\te.g. Send keep alive packet every 30 seconds using id-1:\n"
	"\twl mkeep_alive 1 30000 0x0014a54b164f000f66f45b7e08004500001e000040004011c"
	"52a0a8830700a88302513c413c4000a00000a0d" },
	{"keep_alive", wl_keep_alive, -1, -1,
	"Send specified \"keep-alive\" packet periodically.\n"
	"\tUsage: wl keep_alive <period> <packet>\n"
	"\t\tperiod: Re-transmission period in milli-seconds. 0 to disable packet transmits.\n"
	"\t\tpacket: Hex packet contents to transmit. The packet contents should include "
	"the entire ethernet packet (ethernet header, IP header, UDP header, and UDP "
	"payload) specified in network byte order.\n"
	"\n\te.g. Send keep alive packet every 30 seconds:\n"
	"\twl keep_alive 30000 0x0014a54b164f000f66f45b7e08004500001e000040004011c"
	"52a0a8830700a88302513c413c4000a00000a0d" },
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_keep_alive_module_init(void)
{
	/* get the global buf */
	buf = wl_get_buf();

	/* register keep_alive commands */
	wl_module_cmds_register(wl_keep_alive_cmds);
}

/* Send a periodic keep-alive packet at the specificed interval. */
static int
wl_keep_alive(void *wl, cmd_t *cmd, char **argv)
{
	const char 				*str;
	wl_keep_alive_pkt_t	keep_alive_pkt;
	wl_keep_alive_pkt_t	*keep_alive_pktp;
	int						buf_len;
	int						str_len;
	int						i;
	int 						rc;
	void						*ptr = NULL;


	if (*++argv == NULL) {
	   /*
	   ** Get current keep-alive status.
	   */
		if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return rc;

		keep_alive_pktp = (wl_keep_alive_pkt_t *) ptr;

		printf("Period (msec) :%d\n"
		       "Length        :%d\n"
		       "Packet        :0x",
		       dtoh32(keep_alive_pktp->period_msec),
		       dtoh16(keep_alive_pktp->len_bytes));

		for (i = 0; i < keep_alive_pktp->len_bytes; i++)
			printf("%02x", keep_alive_pktp->data[i]);

		printf("\n");
	}
	else {
		/*
		** Set keep-alive attributes.
		*/

		str = "keep_alive";
		str_len = strlen(str);
		strncpy(buf, str, str_len);
		buf[ str_len ] = '\0';

		keep_alive_pktp = (wl_keep_alive_pkt_t *) (buf + str_len + 1);
		keep_alive_pkt.period_msec = htod32(strtoul(*argv, NULL, 0));
		buf_len = str_len + 1;


		if (keep_alive_pkt.period_msec == 0) {
			keep_alive_pkt.len_bytes = 0;

			buf_len += sizeof(wl_keep_alive_pkt_t);
		}
		else {
			if (NULL != *++argv) {
				keep_alive_pkt.len_bytes =
				htod16(wl_pattern_atoh(*argv, (char *) keep_alive_pktp->data));
				buf_len += (WL_KEEP_ALIVE_FIXED_LEN + keep_alive_pkt.len_bytes);
			}
			else {
				keep_alive_pkt.len_bytes = 0;
				buf_len += WL_KEEP_ALIVE_FIXED_LEN;
			}
		}

		/* Keep-alive attributes are set in local	variable (keep_alive_pkt), and
		 * then memcpy'ed into buffer (keep_alive_pktp) since there is no
		 * guarantee that the buffer is properly aligned.
		 */
		memcpy((char *)keep_alive_pktp, &keep_alive_pkt, WL_KEEP_ALIVE_FIXED_LEN);


		rc = wlu_set(wl,
		            WLC_SET_VAR,
		            buf,
		            buf_len);

	}

	return (rc);
}
