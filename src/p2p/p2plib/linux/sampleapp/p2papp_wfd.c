#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <typedefs.h>
#include "p2papp_wfd.h"
#include "p2p_app.h"

WFDCAPD_CAP_CONFIG wfd_dev_config;

extern BCMP2PHandle p2papp_dev_hdl;
extern BCMP2P_BOOL p2papp_is_connected;
extern BCMP2P_DISCOVER_ENTRY p2papp_peers_list[];
extern uint32 p2papp_peer_count;

static WFADISPDEV wfadispdev;

extern void
p2papi_log(BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp,
	const char *fmt, ...);

extern BCMP2P_STATUS
p2papp_get_peer_idx_from_name(const char *name, unsigned int *idx);

/* The strings need to match the WFDCAPD_DEVICE_TYPE definition */
const char *WFD_DEVTYPE_STR[] = {
	"Source",
	"Primary Sink",
	"Secondary Sink",
	"Source and Primary Sink"
};

static char* GetWfdTypeStr(WFDCAPD_DEVICE_TYPE dev_type)
{
	if (dev_type >= 0 && dev_type <= WFDCAPD_DEVICE_TYPE_SRC_PRIM_SINK)
		return WFD_DEVTYPE_STR[dev_type];

	return "Unknown";
}

static void
p2papp_wfd_save_dev_info()
{
	FILE *fp_dev_info;
	char *dev_info_file = "./wfd_info.txt";

	fp_dev_info = fopen(dev_info_file, "r");
	if (fp_dev_info) {
		fclose(fp_dev_info);
		unlink(dev_info_file);
	}

	/* Write rtsp port into a file */
	fp_dev_info = fopen(dev_info_file, "a");
	if (fp_dev_info)
		fprintf(fp_dev_info, 
			"%d %s\n", 
			p2papp_wfd_get_rtsp_port(),
			BCMP2PIsAP(p2papp_dev_hdl)? "go" : "gc");
	
	fclose(fp_dev_info);
}

void
p2papp_wfd_form_peer_dev_info(const BCMP2P_UINT8 *peer_ie, BCMP2P_UINT16 peer_ie_len,
	char *wfd_info, int buff_len)
{
	WFDCAPD_STATUS status;
	WFDCAPD_CAP_CONFIG dev_info;

	if (peer_ie == NULL || peer_ie_len == 0)
		return;

	memset(wfd_info, 0, buff_len);
	
	status = wfd_capdie_get_dev_cfg(peer_ie, 
						peer_ie_len,
						&dev_info);
	if (status == WFDCAPD_SUCCESS) {
		char tdls_str[256];

		sprintf(wfd_info, " WFDisp: %s, rtsp port %d, hdcp enabled %d, sess_avl %d", 
		    GetWfdTypeStr(dev_info.dev_type), 
			dev_info.rtsp_tcp_port, 
			dev_info.content_protected,
			dev_info.sess_avl);

		if (dev_info.tdls_available) {
			uint8 mac[6];

			memcpy(mac, &dev_info.tdls_cfg.assoc_bssid, 6);
			sprintf(tdls_str, "tdls: assoc_bssid %02x:%02x:%02x:%02x:%02x:%02x",
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

			sprintf(wfd_info, "%s, %s", wfd_info, tdls_str);
		}
	}
	else {
		strcpy(wfd_info, " WFDisp: Not supported");
	}
}

void
p2papp_wfd_form_gc_dev_info(BCMP2P_UINT8 *gc_addr, int peer_idx, const BCMP2P_UINT8 *go_ie, BCMP2P_UINT16 go_ie_len,
	char *wfd_info, int buff_len)
{
	WFDCAPD_STATUS status;
	wfd_capdie_dev_cfg_info_t sess_cfg_list[8];
	WFDCAPD_UINT8 entry_num;
	char gc_addr_str[20];
	int i;

	strcpy(wfd_info, "");
	return;

	status = wfd_capdie_get_group_sess_info(go_ie, go_ie_len, sess_cfg_list, sizeof(sess_cfg_list), &entry_num);
	if (status != WFDCAPD_SUCCESS) {
		p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_wfd_form_gc_dev_info: Exiting. status %d\n", status);
		return;
	}

	sprintf(wfd_info, "%s", "WFDisp: N/A");
	for (i = 0; i < entry_num; i++) {
		wfd_capdie_dev_cfg_info_t *dev_cfg = &sess_cfg_list[i];
		if (memcmp(gc_addr, dev_cfg->peer_addr, 6) == 0) {
			p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_wfd_form_gc_dev_info: dev_cfg->wfd_cfg.dev_type %d\n", dev_cfg->wfd_cfg.dev_type);

			sprintf(gc_addr_str, "%02x:%02x:%02x:%02x:%02x:%02x", gc_addr[0], gc_addr[1], gc_addr[2], gc_addr[3], gc_addr[4], gc_addr[5]);

			sprintf(wfd_info, " WFDisp: %s, hdcp enabled %d, sess_avl %d, group gc avl %d",
				GetWfdTypeStr(dev_cfg->wfd_cfg.dev_type), 
				dev_cfg->wfd_cfg.content_protected,
				dev_cfg->wfd_cfg.sess_avl,
				p2papp_wfd_get_gc_availability(gc_addr_str, peer_idx));
		}
		break;
	}
}

BCMP2P_BOOL
p2papp_wfd_get_gc_availability(const char *peer_dev_id, int go_idx)
{
	BCMP2P_BOOL avl = BCMP2P_TRUE;  /* Assume GC available by default */
	WFDCAPD_STATUS status;
	wfd_capdie_dev_cfg_info_t sess_cfg_list[8];
	WFDCAPD_UINT8 entry_num;
	int i;
 	BCMP2P_DISCOVER_ENTRY	*peer;
	BCMP2P_UINT8 peer_mac_addr[6];

	printf("p2papp_wfd_get_gc_availability. Entered. peer_dev_id  %s\n", peer_dev_id);

	/* Convert mac address format */
	if (p2papp_macaddr_aton(peer_dev_id, peer_mac_addr) != BCMP2P_SUCCESS) {
	  printf("Wrong mac format\n");
	  return BCMP2P_FALSE;
	}

	/* sanity check */
	if (go_idx > p2papp_peer_count)
	{
		p2papi_log(BCMP2P_LOG_ERR, TRUE, "p2papp_wfd_get_gc_availability: "
		           "bad go_idx:%d > peer_vcount:%d\n", go_idx, p2papp_peer_count);
		return BCMP2P_FALSE;
	}
	
	/* point to the entry */
	peer = &p2papp_peers_list[go_idx];
	if (!peer)
	  printf("Failed to find GO %d int the discover entry list\n", go_idx);

	/* Get GO group sess info */
	status = wfd_capdie_get_group_sess_info(peer->ie_data, peer->ie_data_len, sess_cfg_list, sizeof(sess_cfg_list), &entry_num);
	  
	if (status != WFDCAPD_SUCCESS) {
	 //p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_wfd_get_gc_availability: Exiting. status %d\n", status);
	  printf("p2papp_wfd_get_gc_availability: Exiting. status %d\n", status);
	  return avl;
	}
	    
	for (i = 0; i < entry_num; i++) {
		wfd_capdie_dev_cfg_info_t *dev_cfg = &sess_cfg_list[i];
		if (memcmp(peer_mac_addr, dev_cfg->peer_addr, 6) == 0) {
			avl = dev_cfg->wfd_cfg.sess_avl? BCMP2P_TRUE : BCMP2P_FALSE;
			printf("GC is found in sess info. avl %d\n", avl);
		}
		break;
	}

	return avl;
}

BCMP2P_BOOL
p2papp_wfd_get_disc_entry_availability(const char *name)
{
	BCMP2P_BOOL ret = BCMP2P_TRUE;  // Session available by default
	BCMP2P_DISCOVER_ENTRY *peer;
	unsigned int	peer_idx;

	if (name == NULL)
		return ret;

	p2posl_data_lock(p2papp_dev_hdl);

	printf("p2papp_wfd_get_disc_entry_availability: name %s\n", name);
	if (p2papp_get_peer_idx_from_name(name, &peer_idx) == BCMP2P_SUCCESS) {
	  printf("p2papp_wfd_get_disc_entry_availability: name %s, peer_idx %d\n", name, peer_idx);
	        WFADISPCONNECTSTATUS ok;
		WFDCAPD_STATUS status;
		peer = &p2papp_peers_list[peer_idx];
		status = WFADispOkToConnectWithPeer(&wfadispdev, peer->ie_data, peer->ie_data_len, &ok);
		if (status == WFDCAPD_SUCCESS)
		  ret = WFADISP_OK == ok ? BCMP2P_TRUE : BCMP2P_FALSE;
	}
	else
	  printf("p2papp_wfd_get_disc_entry_availability: Not found\n");

	p2posl_data_unlock(p2papp_dev_hdl);
	return ret;
}

BCMP2P_BOOL
p2papp_wfd_get_peer_tdls_avl(const char *name)
{
	WFDCAPD_STATUS status;
	WFDCAPD_CAP_CONFIG dev_info;
	BCMP2P_BOOL ret = BCMP2P_FALSE;  /* TDLS NOA by default */
	BCMP2P_DISCOVER_ENTRY *peer;
	unsigned int	peer_idx;

	if (name == NULL) {
		printf("p2papp_wfd_get_peer_tdls_avl: Peer address is NULL\n");
		return ret;
	}

	p2posl_data_lock(p2papp_dev_hdl);

	if (p2papp_get_peer_idx_from_name(name, &peer_idx) != BCMP2P_SUCCESS) {
		printf("p2papp_wfd_get_peer_tdls_avl: peer %s not found in discover list\n", name);
		goto exit;
	}

	peer = &p2papp_peers_list[peer_idx];

	status = wfd_capdie_get_dev_cfg(peer->ie_data, peer->ie_data_len, &dev_info);
	printf("p2papp_wfd_get_peer_tdls_avl: dev_info.preferred_connection %d.\n", dev_info.preferred_connection);
	if (status == WFDCAPD_SUCCESS)
		ret = dev_info.preferred_connection == WFDCAPD_CONNECTION_TDLS? BCMP2P_TRUE : BCMP2P_FALSE;

exit:
	p2posl_data_unlock(p2papp_dev_hdl);
	return ret;
}

int
p2papp_wfd_get_rtsp_port()
{
	WFDCAPD_STATUS status;
	uint32 num_peers = 0;
	BCMP2P_PEER_INFO info[16];
	WFDCAPD_CAP_CONFIG dev_info;
	BCMP2P_PEER_INFO *last_peer;

	/* If local device is a source, use local device's port number */
	if (wfd_dev_config.dev_type == WFDCAPD_DEVICE_TYPE_SRC)
		return wfd_dev_config.rtsp_tcp_port;

	memset(info, 0, sizeof(info));
	if (BCMP2PGetPeerInfo(p2papp_dev_hdl, &info[0], sizeof(info), &num_peers) != BCMP2P_SUCCESS)
		return 0;

	/* Point to the latest associated peer */
	last_peer = &info[num_peers-1];
	if (last_peer->ie_data_len == 0)
		return 0;
	
	/* If peer device is a source, use peer's port number */
	status = wfd_capdie_get_dev_cfg(last_peer->ie_data, 
						last_peer->ie_data_len,
						&dev_info);

	return (status == WFDCAPD_SUCCESS)? dev_info.rtsp_tcp_port : 0;
}

int
p2papp_wfd_get_rtsp_port_mac(uint8 *addr)
{
	WFDCAPD_STATUS status;
	uint32 num_peers = 0;
	BCMP2P_PEER_INFO info[16];
	WFDCAPD_CAP_CONFIG dev_info;
	BCMP2P_PEER_INFO *last_peer;
	int i;

	/* If local device is a source, use local device's port number */
	if (wfd_dev_config.dev_type == WFDCAPD_DEVICE_TYPE_SRC)
		return wfd_dev_config.rtsp_tcp_port;

	memset(info, 0, sizeof(info));
	if (BCMP2PGetPeerInfo(p2papp_dev_hdl, &info[0], sizeof(info), &num_peers) != BCMP2P_SUCCESS)
		return 0;

	/* Find the associated peer */
	last_peer = NULL;
	for(i=0;i<num_peers;i++)
	{
		last_peer = &info[i];

		if (memcmp(addr, last_peer->mac_address, sizeof(last_peer->mac_address)) == 0)
		{
			/* use peer's port number */
			status = wfd_capdie_get_dev_cfg(last_peer->ie_data,
								last_peer->ie_data_len,
								&dev_info);
			if ((status == WFDCAPD_SUCCESS) && (dev_info.rtsp_tcp_port != 0))
			{
				return dev_info.rtsp_tcp_port;
			}
			else
			{
				p2papi_log(BCMP2P_LOG_MED, TRUE,
				      "BAD status:%d or port:%d\n", status, dev_info.rtsp_tcp_port);
			}
			break;
		}
	}

	return 0;
}

static void
upd_ies(BCMP2P_BOOL set_immed)
{
#define ADD_MGMT_IE(FLAG,INFO,SET_IMMED) \
	do { \
		if (NULL != INFO.blob && 0 != INFO.blob_bytes) \
			BCMP2PAddMgmtCustomIE(p2papp_dev_hdl, (FLAG), INFO.blob, INFO.blob_bytes, SET_IMMED); \
	} while(0)
#define ADD_ACTF_IE(FLAG,INFO) \
	do { \
		if (NULL != INFO.blob && 0 != INFO.blob_bytes) \
			BCMP2PAddAcfCustomIE(p2papp_dev_hdl, (FLAG), INFO.blob, INFO.blob_bytes); \
	} while(0)

	WFDCAPD_STATUS status;
	WFADISPIEBUF info[]={0};

	/* get the IEs */
	status = WFADispGetIes(&wfadispdev, info);
	if (WFDCAPD_SUCCESS != status) 
		return;

	/* add new */
	ADD_MGMT_IE(BCMP2P_MGMT_IE_FLAG_BEACON, info->beacon, set_immed);
	ADD_MGMT_IE(BCMP2P_MGMT_IE_FLAG_PRBREQ, info->prbreq, set_immed);
	ADD_MGMT_IE(BCMP2P_MGMT_IE_FLAG_PRBRSP, info->prbrsp, set_immed);
	ADD_MGMT_IE(BCMP2P_MGMT_IE_FLAG_ASSOCREQ, info->assocreq, set_immed);
	ADD_MGMT_IE(BCMP2P_MGMT_IE_FLAG_ASSOCRSP, info->assocrsp, set_immed);
	ADD_ACTF_IE(BCMP2P_ACF_IE_FLAG_GONREQ, info->gonreq);
	ADD_ACTF_IE(BCMP2P_ACF_IE_FLAG_GONRSP, info->gonrsp);
	ADD_ACTF_IE(BCMP2P_ACF_IE_FLAG_GONCONF, info->gonconf);
	ADD_ACTF_IE(BCMP2P_ACF_IE_FLAG_INVREQ, info->invreq);
	ADD_ACTF_IE(BCMP2P_ACF_IE_FLAG_INVRSP, info->invrsp);
	ADD_ACTF_IE(BCMP2P_ACF_IE_FLAG_PDREQ, info->pdreq);
	ADD_ACTF_IE(BCMP2P_ACF_IE_FLAG_PDRSP, info->pdrsp);

	/* free */
	(void)WFADispFreeIeBuf(info);

#undef ADD_MGMT_IE
#undef ADD_ACTF_IE
}

void
p2papp_wfd_init()
{
	BCMP2P_ETHER_ADDR p2p_dev_addr;

	wfd_capdie_open();

	/* initialize a WFA Display device */

	/* Set alternative mac address to host wlan device address */
	BCMP2PGetDevAddr(p2papp_dev_hdl, &p2p_dev_addr);
	memcpy(&wfd_dev_config.alt_mac, &p2p_dev_addr, sizeof(BCMP2P_ETHER_ADDR));

	if (WFDCAPD_SUCCESS == WFADispInitDevice(&wfadispdev, &wfd_dev_config))
		upd_ies(BCMP2P_FALSE);
}

void
p2papp_wfd_reset_all_go_ies()
{
	BCMP2P_STATUS status;
	uint32 i, num_peers = 0;
	BCMP2P_PEER_INFO info[8];

	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_wfd_on_sta_assoc_disassoc: Entered\n");

	/* get connected peers */
	memset(info, 0, sizeof(info));
	status = BCMP2PGetPeerInfo(p2papp_dev_hdl, &info[0], sizeof(info), &num_peers);
	if (status != BCMP2P_SUCCESS)
		return;

	/* clear the way to rebuild the peer list */
	WFADispGroupOwnerUnregisterAllPeers(&wfadispdev);

	/* rebuild the peer list */
	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_wfd_on_sta_assoc_disassoc: 1\n");
	for (i = 0; i < num_peers; i++) {
		BCMP2P_PEER_INFO *peer = &info[i];

		/* register peer */
		WFADispGroupOwnerRegisterPeer(&wfadispdev, peer->mac_address,
									  peer->ie_data, peer->ie_data_len);
	}

	p2papi_log(BCMP2P_LOG_MED, TRUE, "p2papp_wfd_on_sta_assoc_disassoc: num_peers %d\n", num_peers);

	/* Update beacon and probrsp WFD IE for the session information.
	 * Do not update "sess avl" bit for the GO in this event because the dis-associated 
	 * STA was not necessarily doing rtsp session before dis-association
	 */
	upd_ies(BCMP2P_TRUE);

}

/* Applicable to Auto-GO only */
void
p2papp_wfd_on_sta_assoc_disassoc(BCMP2P_BOOL sta_assoc)
{
	p2papp_wfd_reset_all_go_ies();

	/* Save peer info to a file after the peer is associated */
	if (sta_assoc)
		p2papp_wfd_save_dev_info();
}

void
p2papp_wfd_on_create_link_complete()
{
	/* save device info */
	p2papp_wfd_save_dev_info();
}

BCMP2P_STATUS
p2papp_wfd_set_rtsp_sess_avl(BCMP2P_BOOL sess_avl)
{
	printf("p2papp_wfd_set_rtsp_sess_avl: sess_avl %d\n", sess_avl);
	
	p2papi_log(BCMP2P_LOG_MED, TRUE, 
		"p2papp_wfd_set_rtsp_sess_avl: sess_avl %d\n", sess_avl);

	/* set session as availability bit */
	if (WFDCAPD_SUCCESS == WFADispSessionAvailability(&wfadispdev, sess_avl))
		upd_ies(BCMP2P_TRUE);

	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papp_wfd_get_disc_dev_list(BCMP2P_DISCOVER_ENTRY **peer_list, uint32 *peer_count)
{	
	printf("xxxxxxxxxxxxp2papp_wfd_get_disc_dev_list: p2papp_peer_count %d\n", p2papp_peer_count);

	*peer_list = p2papp_peers_list;
	*peer_count = p2papp_peer_count;

	return BCMP2P_SUCCESS;
}


BCMP2P_STATUS
p2papp_wfd_set_rtsp_port(int port)
{
	/* set rtsp port number */
	if (WFDCAPD_SUCCESS == WFADispSetRtspPort(&wfadispdev, port))
		upd_ies(BCMP2P_FALSE);

	return BCMP2P_SUCCESS;
}

/* Set the preferred connection type */
BCMP2P_STATUS
p2papp_wfd_set_connection_type(int connection_type)
{
	/* set rtsp port number */
	if (WFDCAPD_SUCCESS == WFADispSetPrefConnType(
		&wfadispdev, 
		connection_type? WFDCAPD_CONNECTION_TDLS : WFDCAPD_CONNECTION_P2P))
		upd_ies(BCMP2P_FALSE);

	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papp_wfd_set_alt_mac(const char *alt_mac)
{
	WFDCAPD_ETHER_ADDR alt_mac_addr;

	if (alt_mac == NULL)
		return BCMP2P_INVALID_PARAMS;

	if (p2papp_macaddr_aton(alt_mac, alt_mac_addr.octet) != BCMP2P_SUCCESS) {
		printf("p2papp_wfd_set_alt_mac: Wrong mac format %s\n", alt_mac);
		return BCMP2P_INVALID_PARAMS;
	}

	/* Set alternative mac address */
	if (WFDCAPD_SUCCESS == WFADispSetAltMac(&wfadispdev, &alt_mac_addr))
		upd_ies(BCMP2P_FALSE);
	else
		return BCMP2P_ERROR;

	return BCMP2P_SUCCESS;
}

BCMP2P_BOOL
p2papp_wfd_get_alt_mac(const char *name, BCMP2P_ETHER_ADDR *alt_mac_addr)
{
	BCMP2P_BOOL ret = BCMP2P_FALSE;  // Session available by default
	BCMP2P_DISCOVER_ENTRY *peer;
	unsigned int	peer_idx;
	WFDCAPD_CAP_CONFIG dev_info;

	if (name == NULL)
	  return ret;

	if (alt_mac_addr == NULL)
	  return ret;

	printf("p2papp_wfd_get_alt_mac: name %s\n", name);
	memset(alt_mac_addr, 0, sizeof(BCMP2P_ETHER_ADDR));
	if (p2papp_get_peer_idx_from_name(name, &peer_idx) == BCMP2P_SUCCESS) {
	        printf("p2papp_wfd_get_alt_mac: name %s, peer_idx %d\n", name, peer_idx);
		peer = &p2papp_peers_list[peer_idx];
		if (wfd_capdie_get_dev_cfg(peer->ie_data, peer->ie_data_len, &dev_info) == WFDCAPD_SUCCESS) {
		  memcpy(alt_mac_addr->octet, dev_info.alt_mac.octet, 6);
		  ret = BCMP2P_TRUE;
		}
	}
	else
	  printf("p2papp_wfd_get_alt_mac: Not found\n");

	return ret;
}

int
p2papp_wfd_get_host_p2p_role()
{
  return BCMP2PIsGroupOwner(p2papp_dev_hdl)? 1 : 0;
}

BCMP2P_STATUS
p2papp_wfd_set_dev_type(int dev_type)
{
	if (WFDCAPD_SUCCESS == WFADispSetDevType(&wfadispdev, dev_type))
		upd_ies(BCMP2P_FALSE);

	return BCMP2P_SUCCESS;
}
