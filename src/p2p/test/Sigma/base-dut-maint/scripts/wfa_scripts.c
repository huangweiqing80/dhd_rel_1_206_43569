/****************************************************************************
 *  (c) Copyright 2007 Wi-Fi Alliance.  All Rights Reserved
 *
 *
 *  LICENSE
 *
 * License is granted only to Wi-Fi Alliance members and designated
 * contractors (“Authorized Licensees”).  Authorized Licensees are granted
 * the non-exclusive, worldwide, limited right to use, copy, import, export
 * and distribute this software:
 * (i) solely for noncommercial applications and solely for testing Wi-Fi
 * equipment; and
 * (ii) solely for the purpose of embedding the software into Authorized
 * Licensee’s proprietary equipment and software products for distribution to
 * its customers under a license with at least the same restrictions as
 * contained in this License, including, without limitation, the disclaimer of
 * warranty and limitation of liability, below.  The distribution rights
 * granted in clause (ii), above, include distribution to third party
 * companies who will redistribute the Authorized Licensee’s product to their
 * customers with or without such third party’s private label. Other than
 * expressly granted herein, this License is not transferable or sublicensable,
 * and it does not extend to and may not be used with non-Wi-Fi applications. 
 * Wi-Fi Alliance reserves all rights not expressly granted herein. 
 *
 * Except as specifically set forth above, commercial derivative works of
 * this software or applications that use the Wi-Fi scripts generated by this
 * software are NOT AUTHORIZED without specific prior written permission from
 * Wi-Fi Alliance. Non-Commercial derivative works of this software for
 * internal use are authorized and are limited by the same restrictions;
 * provided, however, that the Authorized Licensee shall provide Wi-Fi Alliance
 * with a copy of such derivative works under a perpetual, payment-free license
 * to use, modify, and distribute such derivative works for purposes of testing
 * Wi-Fi equipment.
 * Neither the name of the author nor "Wi-Fi Alliance" may be used to endorse
 * or promote products that are derived from or that use this software without
 * specific prior written permission from Wi-Fi Alliance.
 *
 * THIS SOFTWARE IS PROVIDED BY WI-FI ALLIANCE "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE,
 * ARE DISCLAIMED. IN NO EVENT SHALL WI-FI ALLIANCE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, THE COST OF PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ****************************************************************************
 */

/*
 * File: wfa_scripts.c
 *
 * Revision History:
 *
 *
 */

#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
	int  i;
	char *script;
	char cmd[256];

	script = argv[0];

	printf("Hello, world!\n");
	printf("argc=%d\n", argc);
	for (i = 0; i < argc; i++) {
		printf("argv[%d]=%s\n", i, argv[i]);
	}

	if (strstr(script, "getipconfig.sh")) {
		char *tmp_file = argv[1];
		char *intf     = argv[2];
		char *ifconfig = argv[3];

		snprintf(cmd, sizeof(cmd), "echo \"dhcpcli=\" > %s", tmp_file);
		system(cmd);

		snprintf(cmd, sizeof(cmd), "echo -n \"mac=\" >> %s; %s %s | grep HWaddr | cut -f3 -dr >> %s",
		         tmp_file, ifconfig, intf, tmp_file);
		system(cmd);

		snprintf(cmd, sizeof(cmd), "echo -n \"ipaddr=\" >> %s; %s %s | grep \"inet addr\" | cut -f2 -d: >> %s",
		         tmp_file, ifconfig, intf, tmp_file);
		system(cmd);

		snprintf(cmd, sizeof(cmd), "echo -n \"bcast=\" >> %s; %s %s | grep \"inet addr\" | cut -f3 -d: >> %s",
		         tmp_file, ifconfig, intf, tmp_file);
		system(cmd);

		snprintf(cmd, sizeof(cmd), "echo -n \"mask=\" >> %s; %s %s | grep \"inet addr\" | cut -f4 -d: >> %s",
		         tmp_file, ifconfig, intf, tmp_file);
		system(cmd);
	}
	else if (strstr(script, "getpid.sh")) {
		char *in_file  = argv[1];
		char *out_file = argv[2];

		snprintf(cmd, sizeof(cmd), "pid_no=`cat \"%s\" | grep PID | cut -f2 -d'='`;echo PID=$pid_no > %s",
		         in_file, out_file);
		system(cmd);
	}
	else if (strstr(script, "getpstats.sh")) {
		char *in_file  = argv[1];

		snprintf(cmd, sizeof(cmd), "tx=`grep transmitted %s | cut -f1 -d, | cut -f1 -d' '`;echo $tx > /tmp/stpsta.txt",
		         in_file);
		system(cmd);

		snprintf(cmd, sizeof(cmd), "rx=`grep transmitted %s | cut -f2 -d, | cut -f2 -d' '`;echo $rx >> /tmp/stpsta.txt",
		         in_file);
		system(cmd);
	}
	else if (strstr(script, "stoping.sh")) {
		char *in_file  = argv[1];

		snprintf(cmd, sizeof(cmd), "pid_no=`cat \"%s\" | grep PID | cut -f2 -d'='`;kill -2 $pid_no 2>/dev/null",
		         in_file);
	}
	else if (strstr(script, "updatepid.sh")) {
		char *in_file  = argv[1];

		snprintf(cmd, sizeof(cmd), "pid_no=`cat \"/tmp/pingpid.txt\" | grep PID | cut -f2 -d'='`;echo PID=$pid_no >> %s",
		         in_file);
		system(cmd);
	}
	else if (strstr(script, "wfaping.sh")) {
		int i;

		cmd[0] = '\0';
		snprintf(cmd, sizeof(cmd), "/bin/ping ");
		for (i = 1; i < argc; i++) {
			strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 1);
			strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
		}
		strncat(cmd, "&", sizeof(cmd) - strlen(cmd) - 1);
		printf(cmd);
		system(cmd);

		snprintf(cmd, sizeof(cmd), "echo PID=$! > /tmp/pingpid.txt");
	}

	return 0;
}
