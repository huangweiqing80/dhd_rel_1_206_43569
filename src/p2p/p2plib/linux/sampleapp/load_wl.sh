#
# Load dhd.ko and prepare it to run P2P by entering APSTA mode before the
# first "wl up".
#
sync
date

ifconfig eth1 down

# This delay is needed to prevent an occasional crash in Linux's
# netdevice_remove during the rmmod.
sleep 1

# Install the wl.ko driver.
rmmod dhd
rmmod wl
#modprobe -r wl
echo insmod wl.ko
insmod wl.ko
sleep 2
lsmod | grep wl

sleep 1

# Check that the driver is running
echo ./wl isup
./wl isup

# Enable APSTA mode.  This must be done now, in case other apps on the device
# establish a concurrent connection on BSS 0 before running the HSL.
# When the HSL starts up, it will check if apsta is 1.  If not, the HSL
# will do a "wl down", "wl apsta 1", "wl up" which will drop any existing
# concurrent connection on BSS 0.
echo ./wl apsta 1
./wl apsta 1
./wl apsta

# Disable spectrum management while wl is down.
# This is required if using a 5 GHz operating channel.
# However, it has a side effect of disabling infra STA 11h.
echo ./wl spect 0
./wl spect 0
./wl spect

# Bring up the Linux wireless interface
#echo ifconfig eth1 up
#ifconfig eth1 up
#sleep 1
#ifconfig eth1

echo ./wl isup
./wl isup

echo ./wl msglevel +error
./wl msglevel +error
echo ./wl msglevel -assoc
./wl msglevel -assoc
echo ./wl msglevel -wsec
./wl msglevel -wsec
