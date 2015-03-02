/*****************************************************************************
 * Per-port
 *
 *****************************************************************************
*/

#if !defined(__PP_DAT_H__)
#define __PP_DAT_H__


struct pp_dat {
	bool is_vif ;	/* is ifname a virtual interface? */
	char ifname[MAX_IF_NAME_SIZE+1];
	int bsscfg_index;
	void *disp_handle; /* ETHER_TYPE_BRCM dispatcher handle */
	int (*wlss_rx)(void *, void *, int);
	void *wlss_rx_arg;
	uint8 bitvec[WL_EVENTING_MASK_LEN];
};


#endif /* !defined(__PP_DAT_H__) */
