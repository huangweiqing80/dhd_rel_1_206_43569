#ifndef _P2PAPP_WFD_H_
#define _P2PAPP_WFD_H_

#include <typedefs.h>
#include <wfd_capdie.h>
#include <wfadisp.h>
#include "BcmP2PAPI.h"

extern char *DEV_TYPE_STR[];
extern BCMP2P_BOOL p2papp_enable_wfdisp;

/* WiFi Display Device Configuration */
extern WFDCAPD_CAP_CONFIG wfd_dev_config;

extern void p2papp_wfd_init();

extern void
p2papp_wfd_form_peer_dev_info(const BCMP2P_UINT8 *peer_ie, BCMP2P_UINT16 peer_ie_len,
	char *wfd_info, int buff_len);

extern void
p2papp_wfd_form_gc_dev_info(BCMP2P_UINT8 *gc_addr, int peer_idx, const BCMP2P_UINT8 *go_ie,
	BCMP2P_UINT16 go_ie_len, char *wfd_info, int buff_len);

extern BCMP2P_BOOL
p2papp_wfd_get_disc_entry_availability(const char *name);

extern BCMP2P_BOOL
p2papp_wfd_get_peer_tdls_avl(const char *name);

extern int
p2papp_wfd_get_rtsp_port();

extern int
p2papp_wfd_get_rtsp_port_mac(uint8 *addr);


void
p2papp_wfd_on_enable_discover();

extern void
p2papp_wfd_on_sta_assoc_disassoc();

extern void
p2papp_wfd_on_connect();

extern void
p2papp_wfd_on_disconnect();

extern void
p2papp_wfd_on_create_link_complete();

extern void
p2papp_wfd_on_sta_assoc_disassoc(BCMP2P_BOOL sta_assoc);

extern void
p2papp_wfd_on_create_group();

extern void
p2papp_wfd_on_send_pdreq();

extern BCMP2P_STATUS
p2papp_wfd_set_rtsp_sess_avl(BCMP2P_BOOL sess_avl);

extern int
p2papp_wfd_get_rtsp_port();

extern BCMP2P_STATUS
p2papp_wfd_get_disc_dev_list(BCMP2P_DISCOVER_ENTRY **peer_list, uint32 *peer_count);

extern BCMP2P_BOOL
p2papp_wfd_get_gc_availability(const char *peer_dev_id, int go_idx);

extern BCMP2P_STATUS
p2papp_wfd_set_rtsp_port(int port);

extern BCMP2P_STATUS
p2papp_wfd_set_connection_type(int connection_type);

extern BCMP2P_STATUS
p2papp_wfd_set_alt_mac(const char *alt_mac);

extern BCMP2P_STATUS
p2papp_wfd_get_alt_mac(const char *name, BCMP2P_ETHER_ADDR *alt_mac_addr);

extern int
p2papp_wfd_get_host_p2p_role();

extern BCMP2P_STATUS
p2papp_wfd_set_dev_type(int dev_type);

#endif  /* _P2PAPP_WFD_H_ */
