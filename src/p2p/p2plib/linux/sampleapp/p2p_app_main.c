#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

/* OS-specific include files */
#include <linux/sockios.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <signal.h>
#include <unistd.h>

extern void p2papp_shutdown(void);
extern int bcmp2p_main(int argc, char* argv[]);
extern int p2papp_disable_sigint(void);

/*
 * Signal handler
 */
static void
signal_hdlr(int sig)
{
	const char *signal_name;

	switch (sig)
	{
		case (SIGINT): signal_name = "Ctrl-C"; break;
		case (SIGABRT): signal_name = "Abort"; break;
		case (SIGTERM): signal_name = "Terminate"; break;
		default: signal_name = "default"; break;
	}
	printf("%s: Signal '%s'\n", __FUNCTION__, signal_name);

	if (sig == SIGINT && p2papp_disable_sigint()) {
		printf("Ignoring SIGINT due to --nosigint cmd line option.\n");
		return;
	}

	p2papp_shutdown();
	exit(0);
}

int
main(int argc, char* argv[])
{
	signal(SIGINT, signal_hdlr);	/* ctrl-C handler */
	signal(SIGABRT, signal_hdlr);	/* Abort handler */
	signal(SIGTERM, signal_hdlr);	/* Termination handler */

	return bcmp2p_main(argc, argv);
}
