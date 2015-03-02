#
# Helper script for testing a concurrent legacy connection.
#
# This script sets up a concurrent connection on eth1.
# After running this script, run the HSL test app to set up a P2P connection
# using the same channel.  eg. if the legacy AP is on channel 6, run this in
# one window:
#     ./test_concurrent.sh
# When pinging starts, run this in another window:
#     ./bcmp2papp -n deviceA -d -c 6 -o 6 -l log.txt
# And on the peer device, run:
#     ./bcmp2papp -n DeviceB -d -c 6 -o 6 -l log.txt
#

# === Associate on the primary wireless interface to a legacy AP
./wl disassoc
sleep 1
./wl up
./wl status
./wl wsec 4
./wl auth 0
./wl wpa_auth 0x80
./wl sup_wpa 1
./wl set_pmk .........4
./wl join wirelesslab  imode bss  amode wpa2psk
sleep 6
echo wl sup_auth_status, sup_auth_status_ext
./wl sup_auth_status
./wl sup_auth_status_ext
./wl status
ifconfig eth1

# === Kill any existing dhcpd or dhclient
dheth1_pid=`ps aux | grep dhcpd | awk '{ print $2 }'`
echo kill -9 $dheth1_pid
kill -9 $dheth1_pid
dheth1_pid=`ps aux | grep dhclient | awk '{ print $2 }'`
echo kill -9 $dheth1_pid
kill -9 $dheth1_pid
ps -e | grep dh

# Run dhclient to get an IP address
/sbin/dhclient eth1
/sbin/ifconfig eth1

# Run a continuous ping test
ping broadcom.com
