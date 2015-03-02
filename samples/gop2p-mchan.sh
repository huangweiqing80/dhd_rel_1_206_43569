#! /bin/sh 

export LD_LIBRARY_PATH=.
#./wpa_supplicant -Dnl80211 -c  p2p.conf -i p2p0 -t

#./wpa_supplicant -i eth2 -Dnl80211  -c wpa_supplicant.conf -puse_multi_chan_concurrent=1 -N -ip2p0 -Dnl80211 -cp2p.conf -puse_p2p_group_interface=1use_multi_chan_concurrent=1 -dd -B
./wpa_supplicant -ieth2 -Dnl80211  -csimple.conf -puse_multi_chan_concurrent=1 -N -ip2p0 -Dnl80211 -cp2p.conf -puse_p2p_group_interface=1use_multi_chan_concurrent=1  -t




