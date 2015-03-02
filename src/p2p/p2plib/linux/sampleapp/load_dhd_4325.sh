#
# Load dhd.ko and prepare it to run P2P by entering APSTA mode before the
# first "wl up".
#
# Copyright (C) 2014, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: load_dhd_4325.sh,v 1.1 2010-02-26 03:17:10 $
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
echo ./dhd download rtecdc.bin
./dhd download rtecdc.bin
sleep 3

# Check that the dhd driver can now talk to the dongle 
echo ./dhd cpu
./dhd cpu

# Enable APSTA mode.  This must be done now, in case other apps on the device
# establish a concurrent connection on BSS 0 before running the HSL.
# When the HSL starts up, it will check if apsta is 1.  If not, the HSL
# will do a "wl down", "wl apsta 1", "wl up" which will drop any existing
# concurrent connection on BSS 0.
./wl apsta 1

# Bring up the Linux wireless interface
echo ifconfig eth1 up
ifconfig eth1 up
sleep 1
ifconfig eth1
