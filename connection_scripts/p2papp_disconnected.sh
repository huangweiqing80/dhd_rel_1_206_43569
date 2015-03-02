#
# This script is called by p2papp after tearing down a connection between
# the two peers.  This script de-initializes the network interface for the
# connection.
#
# Copyright (C) 2010, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: p2papp_disconnected.sh,v 1.10 2010/02/24 23:47:36 dlo Exp $
#


echo === Kill existing dhcpd:
dheth1_pid=`ps aux | grep dhcpd | awk '{ print $2 }'`
echo kill -9 $dheth1_pid
kill -9 $dheth1_pid

echo === Kill existing dhclient:
dheth1_pid=`ps aux | grep dhclient | awk '{ print $2 }'`
echo kill -9 $dheth1_pid
kill -9 $dheth1_pid


#
# Actions for the AP peer in a P2P connection
#
if [ $1 == ap ]; then

#echo
#echo === Check that we can no longer ping the peer:
#echo
#echo ping -c 1 -W 3 192.168.16.202
#ping -c 1 -W 3 192.168.16.202

echo ifconfig $2 0.0.0.0
/sbin/ifconfig $2 0.0.0.0

kill $(ps -e | grep dhcpd | awk '{ print $1 }')

fi



#
# Actions for the STA peer in a P2P connection
#
if [ $1 == sta ]; then

#echo
#echo === Check that we can no longer ping the peer:
#echo
#echo ping -c 1 -W 3 192.168.16.1
#ping -c 1 -W 3 192.168.16.1

echo ifconfig $2 0.0.0.0
/sbin/ifconfig $2 0.0.0.0

kill $(ps -e | grep dhclient | awk '{ print $1 }')

fi

