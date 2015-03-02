#include "wfd_capdlib.h"

WFDCAPD_STATUS
capdlib_set_session_available(capdlib_instance_t *hdl, WFDCAPD_BOOL b_available)
{
	hdl->avl_for_sess = b_available;

	return WFDCAPD_SUCCESS;
}
