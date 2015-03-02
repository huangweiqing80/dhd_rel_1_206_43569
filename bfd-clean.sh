#!/bin/bash


echo ""
echo "------------------------------------------"
echo "cleaning bcmdl"
echo "------------------------------------------"
make -C src/usbdev/usbdl clean

echo ""
echo "------------------------------------------"
echo "cleaning wl exe"
echo "------------------------------------------"
make -C src/wl/exe clean

echo ""
echo "------------------------------------------"
echo "cleaning wl sys"
echo "------------------------------------------"
rm -vrf ./src/dhd/linux/dhd-cdc-*

echo ""
echo "------------------------------------------"
echo "cleaning usb shim"
echo "------------------------------------------"
rm -vrf ./src/linuxdev/obj-*



