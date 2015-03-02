#include <stdlib.h>
#include <string.h>
#include <BcmP2PAPI.h>
#include <tutrace.h>
#include "wfd_capdie.h"
#include "wfd_capdie_lib.h"

#ifdef __cplusplus
extern "C" void
p2papi_log(BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp,
	const char *fmt, ...);
#endif

static void
wfd_capd_output_p2p_log(bool is_err, char *traceMsg)
{
	p2papi_log(is_err? BCMP2P_LOG_ERR : BCMP2P_LOG_MED, TRUE, traceMsg);
}

WFDCAPD_STATUS
wfd_capdie_open()
{
	wfd_capd_redirect_log(wfd_capd_output_p2p_log);
	return WFDCAPD_SUCCESS;
}

WFDCAPD_STATUS
wfd_capdie_close()
{
	return WFDCAPD_SUCCESS;
}

/* Given device configuration and group IE information, create WFD IE data */
WFDCAPD_STATUS
wfd_capdie_create_custom_ie(const WFDCAPD_CAP_CONFIG *dev_cap_cfg,
							const wfd_capdie_dev_ie_t *group_dev_ie_list,
							WFDCAPD_UINT8 group_dev_total,
							WFD_CAPD_IE_FLAG ie_flag,
							WFDCAPD_UINT8 *wfd_ie_buf,
							WFDCAPD_UINT16 *wfd_ie_buf_len)
{
	WFDCAPD_STATUS status;
	uint8 *ie_buf = NULL;
	uint16 ie_buf_len = 0;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	if (wfd_ie_buf_len == NULL) {
		status = WFDCAPD_INVALID_PARAMS;
		goto exit;
	}

	ie_buf = (uint8 *)malloc(WFD_CAPDIE_MAX_WFD_IE_LEN);
	memset(ie_buf, 0, WFD_CAPDIE_MAX_WFD_IE_LEN);
	ie_buf_len = WFD_CAPDIE_MAX_WFD_IE_LEN;

	switch (ie_flag) {
		case WFD_CAPD_IE_FLAG_BEACON:
			capdie_encode_beacon_wfd_ie(dev_cap_cfg, ie_buf, &ie_buf_len);
			break;
		case WFD_CAPD_IE_FLAG_PRBREQ:
			capdie_encode_prbreq_wfd_ie(dev_cap_cfg, ie_buf, &ie_buf_len);
			break;
		case WFD_CAPD_IE_FLAG_PRBRSP:
			capdie_encode_prbresp_wfd_ie(dev_cap_cfg, group_dev_ie_list,
				group_dev_total, ie_buf, &ie_buf_len);
			break;
		case WFD_CAPD_IE_FLAG_ASSOCREQ:
			capdie_encode_assocreq_wfd_ie(dev_cap_cfg, ie_buf, &ie_buf_len);
			break;
		case WFD_CAPD_IE_FLAG_ASSOCRSP:
			capdie_encode_assocresp_wfd_ie(dev_cap_cfg, group_dev_ie_list,
				group_dev_total, ie_buf, &ie_buf_len);
			break;
		case WFD_CAPD_IE_FLAG_GONREQ:
		case WFD_CAPD_IE_FLAG_GONRSP:
		case WFD_CAPD_IE_FLAG_GONCONF:
			capdie_encode_gon_wfd_ie(dev_cap_cfg, ie_buf, &ie_buf_len);
			break;
		case WFD_CAPD_IE_FLAG_INVREQ:
		case WFD_CAPD_IE_FLAG_INVRSP:
			capdie_encode_inv_wfd_ie(dev_cap_cfg, group_dev_ie_list,
				group_dev_total, ie_buf, &ie_buf_len);
			break;
		case WFD_CAPD_IE_FLAG_PDREQ:
		case WFD_CAPD_IE_FLAG_PDRSP:
			capdie_encode_provdis_wfd_ie(dev_cap_cfg, group_dev_ie_list,
				group_dev_total, ie_buf, &ie_buf_len);
			break;
		case WFD_CAPD_IE_FLAG_TDLS_SETUPREQ:
		case WFD_CAPD_IE_FLAG_TDLS_SETUPRSP:
			capdie_encode_tdls_setup_wfd_ie(dev_cap_cfg, ie_buf, &ie_buf_len);
			break;
		default:
			status = WFDCAPD_INVALID_PARAMS;
			goto exit;
	};

	/* Caller is requesting buffer size */
	if (NULL == wfd_ie_buf) {
		*wfd_ie_buf_len = ie_buf_len;
		status = WFDCAPD_SUCCESS;
		goto exit;
	}

	/* Verify input buffer size */
	if (*wfd_ie_buf_len < ie_buf_len) {
		status = WFDCAPD_INVALID_PARAMS;
		goto exit;
	}

	/* Copy over IE data */
	memcpy(wfd_ie_buf, ie_buf, ie_buf_len);
	*wfd_ie_buf_len = ie_buf_len;
	status = WFDCAPD_SUCCESS;

exit:
	if (ie_buf)
		free(ie_buf);

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. status %d\n", status));
	return status;
}

/* Given the device's IE data, get the device's WFD configuraiton information */
WFDCAPD_STATUS
wfd_capdie_get_dev_cfg(const WFDCAPD_UINT8 *ie_buf, 
					   WFDCAPD_UINT16 ie_buf_len,
					   WFDCAPD_CAP_CONFIG *wfd_cfg)
{
	WFDCAPD_STATUS status;
	wfd_capdie_ie_t wfd_ies;

	WFDCAPDLOG((TUTRACE_INFO, "Entered. buf_len %d\n", ie_buf_len));

	if (ie_buf == NULL || wfd_cfg == NULL) {
		WFDCAPDLOG((TUTRACE_ERR, "ie_buf %d, wfd_cfg %d\n", ie_buf));
		status = WFDCAPD_INVALID_PARAMS;
		goto exit;
	}

	memset(&wfd_ies, 0, sizeof(wfd_ies));
	if (!capdie_search_wfd_ies(ie_buf, ie_buf_len, &wfd_ies)) {
		status = WFDCAPD_WFD_IE_NOT_FOUND;
		goto exit;
	}

	WFDCAPDLOG((TUTRACE_INFO, "capdie_search_wfd_ies completed. wfd_ies.devinfo_subelt.len %d\n", wfd_ies.devinfo_subelt.len));

	memset(wfd_cfg, 0, sizeof(WFDCAPD_CAP_CONFIG));
	if (wfd_ies.devinfo_subelt.len > 0) {
		wfd_capdie_dev_info_t dev_info;

		/* Device information */
		capdie_decode_dev_cap_bitmap(wfd_ies.devinfo_subelt.info_bmp, &dev_info);

		wfd_cfg->dev_type = dev_info.dev_type;
		wfd_cfg->sess_avl = dev_info.sess_avl;
		wfd_cfg->preferred_connection = dev_info.preferred_connection;
		wfd_cfg->support_cpl_sink = dev_info.support_cpl_sink;
		wfd_cfg->support_time_sync = dev_info.support_time_sync;
		wfd_cfg->support_wsd = dev_info.support_wsd;
		wfd_cfg->content_protected = dev_info.content_protected;

		/* rtsp port number */
		wfd_cfg->rtsp_tcp_port = wfd_ies.devinfo_subelt.port;

		/* max throughput */
		wfd_cfg->max_tput = wfd_ies.devinfo_subelt.max_tput;

		WFDCAPDLOG((TUTRACE_INFO, 
			"wfd_cfg->rtsp_tcp_port %d, wfd_cfg->sess_avl %d\n", 
			wfd_cfg->rtsp_tcp_port, 
			wfd_cfg->sess_avl));	

	}

	/* Associated bssid */
	if (wfd_ies.assocbssid_subelt.len > 0) {
		memcpy(wfd_cfg->tdls_cfg.assoc_bssid.octet, wfd_ies.assocbssid_subelt.bssid, 6);
	}

	/* Alternative mac */
	if (wfd_ies.altmac_subelt.len > 0) {
		memcpy(wfd_cfg->alt_mac.octet, wfd_ies.altmac_subelt.alt_mac, 6);
	}

	/* Local IP address */
	if (wfd_ies.localip_subelt.len > 0) {
		wfd_cfg->tdls_cfg.local_ip = wfd_ies.localip_subelt.ip4_addr;
	}

	status = WFDCAPD_SUCCESS;

exit:
	WFDCAPDLOG((TUTRACE_INFO, "Exiting. status %d\n", status));
	return status;
}

/* Given the device's IE data, get the device's group session information which contains
 * a list of device info descriptors
 */
WFDCAPD_STATUS
wfd_capdie_get_group_sess_info(const WFDCAPD_UINT8 *ie_buf, 
						   WFDCAPD_UINT16 ie_buf_len,
						   wfd_capdie_dev_cfg_info_t *sess_cfg_list,
						   WFDCAPD_UINT32 sess_buf_len,
						   WFDCAPD_UINT8 *entry_num)
{
	WFDCAPD_STATUS status;
	wfd_capdie_ie_t wfd_ies;
	uint8 i;
	wfd_capdie_dev_cfg_info_t *dev_cfg;
	wifi_wfd_devinfo_desc_t *devinfo_desc;

	WFDCAPDLOG((TUTRACE_INFO, "Entered. ie_buf_len %d\n", ie_buf_len));
	
	if (ie_buf == NULL || ie_buf_len == 0) {
		status = WFDCAPD_INVALID_PARAMS;
		goto exit;
	}

	memset(&wfd_ies, 0, sizeof(wfd_ies));

	/* Decode IE buffer */
	if (!capdie_search_wfd_ies(ie_buf, ie_buf_len, &wfd_ies)) {
		status = WFDCAPD_WFD_IE_NOT_FOUND;
		goto exit;
	}

	if (wfd_ies.sess_dev_total == 0) {
		status = WFDCAPD_WFD_NO_SESS_INFO;
		goto exit;
	}

	/* 
	 * Session information is available 
	 */
	/* Verify the input buffer size */
	*entry_num = wfd_ies.sess_dev_total;
	if (sess_cfg_list == NULL || 
		sess_buf_len < (*entry_num) * sizeof(wfd_capdie_dev_cfg_info_t)) {
		status = WFDCAPD_NOT_ENOUGH_SPACE;
		goto exit;
	}

	/* Covert and copy over information of each device in the session */
	devinfo_desc = (wifi_wfd_devinfo_desc_t *)wfd_ies.sessinfo_subelt.data;
	for (i = 0; i < wfd_ies.sess_dev_total; i++) {
		dev_cfg = &sess_cfg_list[i];
		wfd_capdie_dev_info_t dev_info;

		/* Device information */
		capdie_decode_dev_cap_bitmap(devinfo_desc->info_bmp, &dev_info);

		dev_cfg->wfd_cfg.dev_type = dev_info.dev_type;
		dev_cfg->wfd_cfg.sess_avl = dev_info.sess_avl;

		dev_cfg->wfd_cfg.preferred_connection = dev_info.preferred_connection;
		dev_cfg->wfd_cfg.support_cpl_sink = dev_info.support_cpl_sink;
		dev_cfg->wfd_cfg.support_time_sync = dev_info.support_time_sync;
		dev_cfg->wfd_cfg.support_wsd = dev_info.support_wsd;
		dev_cfg->wfd_cfg.content_protected = dev_info.content_protected;

	
		/* Device addr */
		memcpy(dev_cfg->peer_addr, devinfo_desc->peer_mac, 6);

		/* Associated bssid */
		memcpy(&dev_cfg->wfd_cfg.tdls_cfg.assoc_bssid, devinfo_desc->assoc_bssid, 6);

		/* Max throughput */
		dev_cfg->wfd_cfg.max_tput = devinfo_desc->max_tput;

		/* Coupled sink information */
		memcpy(dev_cfg->wfd_cfg.cpl_sink_addr, devinfo_desc->cpl_sink_addr, 6);
		dev_cfg->wfd_cfg.cpl_status =
			(WFDCAPD_COUPLE_STATUS)devinfo_desc->cpl_sink_status;

		/* Point to next device info descriptor */
		devinfo_desc = (wifi_wfd_devinfo_desc_t *)((uint8 *)devinfo_desc +
				sizeof(wifi_wfd_devinfo_desc_t));
	}

	status = WFDCAPD_SUCCESS;

exit:
	WFDCAPDLOG((TUTRACE_INFO, "Exiting. status %d, *entry_num %d\n", status, *entry_num));
	return status;
}
