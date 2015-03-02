#!/bin/sh

./wl down
./wl up
./wl auth 0
./wl infra 1
./wl wsec 4
./wl sup_wpa 1
./wl wpa_auth 4
./wl set_pmk 1234567890
./wl ssid <AP NAME>
sleep 3
./wl status

ifconfig eth1 192.168.1.200
sleep 1
ping 192.168.1.1 -c 4

