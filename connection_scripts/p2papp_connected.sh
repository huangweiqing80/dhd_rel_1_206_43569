#
# This script is called by p2papp after a connection is established between
# the two peers.  This script:
# - sets up the network interface for the connection
# - verifies the connection by doing a ping and a file transfer.
# When this script exits, p2papp will tear down the connection.
#
# Copyright (C) 2010, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: p2papp_connected.sh,v 1.9 2009/06/18 18:18:49 dlo Exp $
#


#
# Actions for the AP side of the connection
#
if [ $1 == ap ]; then

# On the AP peer, our IP address is statically assigned by the P2P Library
# to the IP address required by the DHCP server.
echo ifconfig wl0.1
ifconfig wl0.1

echo
echo === Check that we can ping the peer:
echo
echo ping -c 6 192.168.16.202
ping -c 6 192.168.16.202

#echo
#echo === Testing a file transfer to the peer...
#echo
#echo scp testfile root@192.168.16.202:/tmp
#scp testfile root@192.168.16.202:/tmp
#echo

echo
echo === Press ENTER twice to start the iperf server.
echo === Do this FIRST, before starting the iperf client on the peer.
read abc
#echo ./iperf -u -s -P 1 -i 1
echo ./iperf -s -P 1 -i 1
echo
echo ===
echo === NOTE: When the iperf client is finished the test, 
echo ===       press ctrl-C here to exit the iperf server.
echo ===
echo
#./iperf -u -s -P 1 -i 1
./iperf -s -P 1 -i 1

fi



#
# Actions for the STA side of the connection
#
if [ $1 == sta ]; then

if [ -e /tmp/testfile ]; then
rm -v /tmp/testfile
fi

# For now, statically assign ourself an IP address.
# In the future we should invoke a DHCP client to get an IP address from
# the DHCP server running on the AP peer.
echo
echo === Configuring the IP address:
echo
echo ifconfig $2 192.168.16.202 up
ifconfig $2 192.168.16.202 up
ifconfig $2

echo
echo === Check that we can ping the peer:
echo
echo ping -c 6 192.168.16.1
ping -c 6 192.168.16.1

#echo === TEMP: test STA powersave
#echo ./wl PM 1
#./wl PM 1
#echo ping -c 3 192.168.16.202

#echo === Waiting up to 100 seconds for peer to initiate a file transfer...
#if [ -e /tmp/testfile ]; then
#  echo rm -v /tmp/testfile
#  rm -v /tmp/testfile
#fi
#for (( i = 0 ; i <= 100 ; i++ ))
#do
#  sleep 1
#  if [ -e /tmp/testfile ]; then
#    echo
#    echo === Received file:
#    ls -l /tmp/testfile
#    echo
#    exit 0
#  fi
#done

echo
echo === Press ENTER twice to start the iperf client.
echo === Do this SECOND, after starting the iperf server on the peer.
read abc
#echo ./iperf -u -c 192.168.16.1 -t 10 -i 1
#./iperf -u -c 192.168.16.1 -t 10 -i 1
echo ./iperf -c 192.168.16.1 -t 10 -i 1
./iperf -c 192.168.16.1 -t 10 -i 1


fi


#sleep 2
