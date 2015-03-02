#
# Load dhd.ko, download the firmware and NVRAM.
# Prepare to run P2P by entering APSTA mode before bringing up the driver.
#
# (Enter APSTA mode before "wl up" is necessary because "wl down" is not
# supported in -reclaim- dongle builds.)
#
sync
date

ifconfig eth1 down

# This delay is needed to prevent an occasional crash in Linux's
# netdevice_remove during the rmmod.
sleep 1

# Install the dhd.ko driver.
rmmod wl
rmmod dhd
modprobe -r dhd
echo insmod dhd.ko
insmod dhd.ko
sleep 2
lsmod | grep dhd

# Download the dongle code.
echo ls -l rtecdc.bin
ls -l rtecdc.bin
#./dhd download rtecdc.bin src/shared/nvram/bcm94329sdagb.txt
echo ./dhd download rtecdc.bin bcm94329sdagb.txt
./dhd download rtecdc.bin bcm94329sdagb.txt
sleep 3

# Check that the dhd driver can now talk to the dongle 
echo ./dhd cpu
./dhd cpu

# Bring up the Linux wireless interface
echo ifconfig eth1 up
ifconfig eth1 up
sleep 1
ifconfig eth1

# Enable APSTA while wl is down.
echo ./wl apsta 1
./wl apsta 1
./wl apsta

# Disable spectrum management while wl is down.
# This is required if using a 5 GHz operating channel.
# However, it has a side effect of disabling infra STA 11h.
echo ./wl spect 0
./wl spect 0
./wl spect
