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

# Install the dhd.ko driver.
rmmod sdhci
rmmod sdhci_pci
rmmod wl
rmmod dhd
echo insmod dhd.ko
insmod dhd.ko
sleep 2
lsmod | grep dhd

# Download the dongle code.
echo ls -l rtecdc.bin
ls -l rtecdc.bin
echo ./dhd -i eth1 download rtecdc.bin bcm94329sdagb.txt
./dhd -i eth1 download rtecdc.bin bcm94330fcbga_McLaren.txt
sleep 3

# Check that the dhd driver can now talk to the dongle 
echo ./dhd -i eth1 cpu
./dhd -i eth1 cpu

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
