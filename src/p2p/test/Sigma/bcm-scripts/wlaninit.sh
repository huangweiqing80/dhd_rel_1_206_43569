#!/bin/bash

kill $(ps -e | grep dhcpd | awk '{ print $1 }')
kill $(ps -e | grep dhclient | awk '{ print $1 }')
kill $(ps -e | grep wfa_ca | awk '{ print $1 }')

rmmod wl
insmod wl.ko

./wl apsta 1
./wl up
