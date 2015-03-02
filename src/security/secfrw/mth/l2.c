/*****************************************************************************
 *
 *****************************************************************************
*/

#include <typedefs.h>
#include <proto/ethernet.h>
#include <l2p.h>

/* for 802.3 ethernet packets*/
#define ETH_P_802_2	0x04

static const struct l2 _l2_type[] = {
	{
		"eapol",
		ETHER_TYPE_802_1X
	},
	{
		"btsig",
		ETH_P_802_2
	},
};
extern const struct l2 *
common_eapol_type(int index)
{
	return &_l2_type[index];
}

extern const struct l2 *
eapol_type(void)
{
	/* the regular eapol type */
	return &_l2_type[0];
}
