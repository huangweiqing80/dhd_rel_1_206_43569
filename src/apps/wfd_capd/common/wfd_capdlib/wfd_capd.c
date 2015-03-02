#include <typedefs.h>
#include "wfd_capd.h"
#include "wfd_capdlib.h"

/** Initialize the library */
WFDCAPD_API WFDCAPD_STATUS
wfd_capd_init()
{
	return WFDCAPD_SUCCESS;
}

/** Uninitialize the library */
WFDCAPD_API WFDCAPD_STATUS
wfd_capd_uninit()
{
	return WFDCAPD_SUCCESS;
}


/** Open a wireless adapter for WFD */
WFDCAPD_API wfdcapd_handle
wfd_capd_open(char *adapter, char *prime_adapter, wfdcapd_callback_ctx cb_ctx, wfd_capd_status_cb status_cb)
{
	return NULL;
}


/** Open the wireless adapter used by WFD session */
WFDCAPD_API WFDCAPD_STATUS wfd_capd_close(wfdcapd_handle wfd_handle)
{
	return WFDCAPD_SUCCESS;
}


/** Set WFD configuration. Config data will not take effect until the next discovery
 *  or connection happens
 */
WFDCAPD_API WFDCAPD_STATUS
wfd_capd_set_config_data(wfdcapd_handle wfd_handle, WFDCAPD_CONFIG *wfd_cfg)
{
	return WFDCAPD_SUCCESS;
}


/** Start WFD device discovery */
WFDCAPD_API WFDCAPD_STATUS
wfd_capd_discover(wfdcapd_handle wfd_handle, WFDCAPD_DISCOVER_PARAM *disc_param)
{
	return WFDCAPD_SUCCESS;
}


/** Cancel current device discovery process */
WFDCAPD_API WFDCAPD_STATUS wfd_capd_cancel_discover(wfdcapd_handle wfd_handle)
{
	return WFDCAPD_SUCCESS;
}


/** Get the result of discovery issued by wfd_capd_discover */
WFDCAPD_API WFDCAPD_STATUS  wfd_capd_get_discover_result(wfdcapd_handle wfd_handle,
														 WFDCAPD_BOOL b_final,
														 PWFDCAPD_DISCOVER_ENTRY *data_buf,
														 WFDCAPD_UINT32 data_buf_len,
														 WFDCAPD_UINT32 *entry_total)
{
	return WFDCAPD_SUCCESS;
}


/** Set WPS PIN code required for WFD connection */
WFDCAPD_API WFDCAPD_STATUS wfd_capd_set_wps_pin(WFDCAPD_WPS_PIN *pin);

/** Establish WFD link connection via P2P or TDLS. Check if tdls should be determined internally */
WFDCAPD_API WFDCAPD_STATUS wfd_capd_establish_link(wfdcapd_handle wfd_handle, 
												   WFDCAPD_ETHER_ADDR *peer_mac,
												   WFDCAPD_CONNECTION_TYPE conn_type)
{
	return WFDCAPD_SUCCESS;
}


/** Tear down or cancel a connection */
WFDCAPD_API WFDCAPD_STATUS wfd_capd_teardown_link(wfdcapd_handle wfd_handle)
{
	return WFDCAPD_SUCCESS;
}


/** Start a WFD group as autonomous group owner */
WFDCAPD_API WFDCAPD_STATUS wfd_capd_start_group(wfdcapd_handle wfd_handle, char *nw_name)
{
	return WFDCAPD_SUCCESS;
}


/** Stop the created group */
WFDCAPD_API WFDCAPD_STATUS wfd_capd_stop_group(wfdcapd_handle wfd_handle)
{
	return WFDCAPD_SUCCESS;
}


/** Accept an incoming connection request by starting WPS or reject by doing nothing
 *  Call wfd_capd_set_wps_pin when PIN is required
 */
WFDCAPD_API WFDCAPD_STATUS wfd_capd_accept_link_request(wfdcapd_handle wfd_handle, 
														WFDCAPD_BOOL b_accept)
{
	return WFDCAPD_SUCCESS;
}


/** Check if local device supports TDLS */
WFDCAPD_API WFDCAPD_STATUS wfd_capd_check_tdls(wfdcapd_handle wfd_handle)
{
	return WFDCAPD_SUCCESS;
}

/** Set device availability for WFD session */
WFDCAPD_API WFDCAPD_STATUS wfd_capd_set_session_available(wfdcapd_handle wfd_handle,
														  WFDCAPD_BOOL b_available)
{
	capdlib_instance_t *hdl = (capdlib_instance_t *)wfd_handle;

	return WFDCAPD_SUCCESS;
}
