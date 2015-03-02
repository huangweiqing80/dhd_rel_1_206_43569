#
# Copyright (C) 2014, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: readme.txt,v 1.7 2010-02-11 21:26:58 $
#

========================================================================
                Broadcom P2P Library and Sample App
                    Version 1.10 Release Notes
                                                             2009-Aug-06
========================================================================

Known Issues
-----------------------------------------------------
- On a 4329, the sample app only supports the Create Soft AP menu option 
  for now.  Other menu options may not function correctly.  On a 4325 all
  menu options do work.
- Occasionally one the action frames sent in the Group Owner Negotiation
  may fail to be received at the other peer.  The workaround is to press
  ctrl-C and run bcmp2papp again.

How to Build 
-----------------------------------------------------
This assumes the release package has been extracted into the directory
~/work.

   * Build rtecdc.bin with the necessary options:
     * cd ~/work/src/include; make
     * cd ~/work/src/dongle/rte/wl
     * To build a 4325 image:
        * make builds/4325b0/sdio-g-cdc-reclaim--apsta-af-idsup-idauth-p2p
        * cp builds/4325*/sdio*/rtecdc.bin ~/work
     * To build a 4329 image:
        * make builds/4329b1/sdio-g-cdc-full11n-reclaim-apsta-af-idsup-idauth-p2p
        * cp builds/43259/sdio*/rtecdc.bin ~/work

   * Build dhd.ko with the necessary options:
     * cd ~/work/src/dhd/linux
     * make dhd-cdc-sdstd-apsta
     * cp dhd.ko ~/work

   * Build the dhd utility:
     * cd ~/work/src/dhd/exe
     * make
     * cp dhd ~/work

   * Build the wl utility:
     * cd ~/work/src/wl/exe
     * make
     * cp wl ~/work

   * Build bcmp2papp:
     * cd ~/work/src/p2p/p2plib/linux/sampleapp
     * make
     * cp obj/debug/x86/bcmp2papp ~/work
     * cp dhdmin.sh bcmp2papp*.sh ~/work

How to run the P2P sample app
-----------------------------------------------------
To start the P2P sample app on a Dell D430 Fedora Core 4 Linux laptops:

   * Go to the work directory and su as root:
      * cd ~/work; su
   * Insert Apollo1/4325 board into the SD card slot.
   * Load the DHD driver and download the 43xx firmware.  This step does not
     have to be done again for subsequent runs of bcmp2papp.
      * ./dhdmin.sh   # for the 4325
      * ./dhd4329.sh  # For the 4329
   * Run the P2P sample app.
      * ./bcmp2papp -n friendlyname  # Use a different name on each PC
   * The app's menu should now be displaed.

To create a Soft AP:
   * Press 's' in the menu.
   * Any non-P2P STA should now be able to connect to the soft AP.
   * The soft AP's security setting is specified on the command line when
     starting bcmp2papp. eg.
      * bcmp2papp -n myap --sec open
      * bcmp2papp -n myap --sec wpa2
      * bcmp2papp -n myap --sec wpa
      * bcmp2papp -n myap --sec wep
   * The WPA, WPA2, WEP passphrases/key is hardcoded in bcmp2papp.
     They can be found in p2p_app.c line 146 in the static initializations of
     p2papp_wpa2_link_config, p2papp_wpa_link_config, and
     p2papp_wep_link_config.

To establish a P2P connection between 2 P2P peers:

   * Press 'e' <enter> on each PC to enable !P2P discovery.
   * After a few seconds each peer will display the other peer in
     the "Discovered !P2P peers:" list.
   * Press '1' on one of the PCs to select the other peer to connect to.
   * The other peer should show a connection accept y/n prompt.
     Press 'y' to accept the connection.
   * Wait for the WPS handshake and the secure connection to be established.
     When done, both peers will ping each other.
   * Both peers will prompt to press a key to start an iperf data transfer
     test.  Press Enter twice on each peer to start the test.
     After the test, both peers will show their main menus.
   * Press 'x' on each peer to disconnect.

To create a P2P Group Owner:
   * Press 'g' in the menu.
   * Another P2P peer can now discover and connect to the P2P group using the
     procedure above for connecting to a P2P peer.
     The only difference is the P2P group will not start an iperf server 
     so the P2P client's iperf test will fail.

To discover and connect to a P2P Group Owner:
   * Press 'e' <enter> to enable !P2P discovery.
   * After a few seconds the P2P group will be displayed in the
     "Discovered !P2P peers:" list.
   * Press '1' to select the P2P group to connect to.
   * The P2P group peer should show a connection accept y/n prompt.
     Press 'y' to accept the connection.
   * Wait for the WPS handshake and the secure connection to be established.
     When done, the client peer will ping the group.
   * The client peer will then prompt to press a key to start an iperf data
     transfer test.  This 
   * Press 'x' on the client peer to disconnect.
