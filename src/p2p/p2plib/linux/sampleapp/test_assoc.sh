# SoftAP tests:
# ./zctest 0a6 - WPA2-PSK AES
# ./zctest 0e6 - WPA-PSK TKIP
# ./zctest 0f6 - WPA-PSK AES
# ./zctest 0co6 - open
# ./zctest 0do6 - open WEP
# ./zctest 0d6  - open WEP, 4 128-bit keys, key index 3, ssid "lhs_wep2"
# ./zctest 0d6.10 - WEP/Open, ssid=lhs_wep.10, 1 128-bit key, index 0
# ./zctest 0d6.11 - WEP/Open, ssid=lhs_wep.10, 1 128-bit key, index 3
# ./zctest 0d6.20 - WEP/Open, ssid=lhs_wep.20, 2 128-bit keys, index 0
# ./zctest 0d6.21 - WEP/Open, ssid=lhs_wep.21, 2 128-bit keys, index 1
# ./zctest 0d6.22 - WEP/Open, ssid=lhs_wep.22, 2 128-bit keys, index 2
# ./zctest 0d6.40 - WEP/Open, ssid=lhs_wep.40, 4 128-bit keys, index 0
# ./zctest 0d6.41 - WEP/Open, ssid=lhs_wep.40, 4 128-bit keys, index 1
# ./zctest 0d6.42 - WEP/Open, ssid=lhs_wep.40, 4 128-bit keys, index 2
# ./zctest 0d6.43 - WEP/Open, ssid=lhs_wep.40, 4 128-bit keys, index 3

#
# Copyright (C) 2014, Broadcom Corporation. All Rights Reserved.
# 
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# $Id: test_assoc.sh,v 1.1 2010-02-26 03:17:10 $
#

if [ $# == 0 ]; then
	echo You must specify a test case name parameter, eg. '"zctest 7a"'
	exit
fi


dmesg -c > /dev/null

#./wl down
./wl disassoc
sleep 1
./wl up
./wl status

# Set the following bits of the event_msgs bitvector to enable the sending of
# the following events from the dongle side of the driver to the host side:
#     WLC_E_SET_SSID (bit 0)
#     WLC_E_AUTH (bit 3)
#     WLC_E_DEAUTH_IND (bit 6)
#     WLC_E_ASSOC (bit 7)
#     WLC_E_REASSOC (bit 9)
#     WLC_E_DISASSOC (bit 11)
#     WLC_E_DISASSOC_IND (bit 12)
#     WLC_E_PRUNE (bit 23)
#     WLC_E_PSK_SUP (bit 48)
./wl event_msgs 0x00000000000000000001000000801AC9
# However, for the Raptor branch, WLC_E_PSK_SUP is bit 46 instead of 48:
#./wl event_msgs 0x00000000000000000000400000801AC9


#@@@TEMP!!!!!!!!!
#./wl event_msgs 0x0000000000000000000FFFFFFFFFFFFF



# Toggle SE Linux from enforcing to permissive.  
# This prevents dhclient read errors.
/usr/sbin/setenforce 1


# wl auth: (802.11 authentication type)
# 0 = OpenSystem
# 1 = SharedKey
#./wl auth 0

# wsec bits:
# 1 - WEP enabled
# 2 - TKIP enabled
# 4 - AES enabled
# 8 - WSEC in software
# 128 - FIPS enabled
#./wl wsec 4

# wl wpa_auth: (Link layer WPA authorization mode) ("security type")
# 0x0000 - disabled
# 0x0001 - WPA-NONE
# 0x0002 - WPA-802.1x
# 0x0004 - WPA-PSK
# 0x0008 - CCKM(WPA)
# 0x0010 - CCKM(WPA2)
# 0x0040 - WPA2-802.1x
# 0x0080 - WPA2-PSK
# 0x00df = everything
#./wl wpa_auth 0x80

# Undocumented IOVar setting needed to turn on the in-driver WPA supplicant 
#./wl sup_wpa 1

# Change '-' to '+' to turn on debug logs, if they are compiled in
./wl msglevel +error
#./wl msglevel +info
#./wl msglevel +assoc
#./wl msglevel +rtdc
#./wl msglevel +wsec
#./wl msglevel +scan
#./wl msglevel +mbss
#./wl msglevel +trace

# Uncomment this to turn on DHD trace logs to see received WLC events
#./dhd msglevel +trace
# For the Raptor branch, use this line instead:
#./dhd msglevel +event
./dhd msglevel +error

echo ========= Attempting wl join at `date`


#
# Test case series 0aX: WPA2-PSK AES, successful join to various APs
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524 5=Broadcom
#

if [ $1 == 0a0 ]; then
echo Test 0a0: Successfully join the "wlandl_wrt54g" WPA2-PSK AES network
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_PSK_SUP status=6(WLC_SUP_KEYED) reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
fi

if [ $1 == 0a1 ]; then
echo Test 0a: Successfully join the "wirelesslab" WPA2-PSK AES network
# - STA: 80211auth=Open LinkLayer_wpa_auth=wpa2psk wsec=AES pmk=
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=AES pmk=
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#     WLC_E_PSK_SUP status=6(WLC_SUP_KEYED) reason=0
./wl wsec 4
./wl auth 0
./wl wpa_auth 0x80
./wl sup_wpa 1
./wl set_pmk 5.........
./wl join wirelesslab  imode bss  amode wpa2psk
fi

if [ $1 == 0a2 ]; then
echo Test 0a2: Successfully join the "wlan_DI624" WPA2-PSK AES network
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - AP : 80211auth=N/A  wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#     WLC_E_PSK_SUP status=6(WLC_SUP_KEYED) reason=0
#
# NOTE: if the join fails with WLC_E_ASSOC reason=43, try do a "wl disassoc"
#       and then repeat the join.  This sometimes works.  Possibly the 43
#       means the AP thinks a previous association with the STA is still
#       active.
#
# NOTE: this test fails for a DLink DI624 before upgrading the firmware:
# - failure logs:
#     wl0: JOIN: authentication success
#     wl0: JOIN: sending ASSOC REQ ...
#     0001.921.499 @@@wlc_bss_mac_event: 7 WLC_E_ASSOC status=1 reason=43
#     wl0: JOIN: association failure 43  (what is 43???)
#     wl0: JOIN: no more join targets available
# - failure events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=1 reason=43
#     WLC_E_SET_SSID status=1 reason=0
#
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlan_DI624  imode bss  amode wpa2psk
fi

if [ $1 == 0a5 ]; then
echo Test 0a5: Successfully join the "BAP1169251" WPA2-PSK AES network
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_PSK_SUP status=6(WLC_SUP_KEYED) reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join BAP1169251  imode bss  amode wpa2psk
fi

if [ $1 == 0a6 ]; then
echo Test 0a6: WPA2-PSK/AES, successful join [lhs_wpa2]
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk 22ndStStation
./wl join lhs_wpa2  imode bss  amode wpa2psk
fi

if [ $1 == 0a65 ]; then
echo Test 0a6:5 WPA2-PSK/AES, successful join [7405]
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk 22ndStStation
./wl join 7405  imode bss  amode wpa2psk
fi

if [ $1 == 0a651 ]; then
echo Test 0a651 WPA2-PSK/AES, successful join [01]
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk 22ndStStation
./wl join 01  imode bss  amode wpa2psk
fi

if [ $1 == 0a656 ]; then
echo Test 0a6:5 WPA2-PSK/AES, successful join [7405]
./wl channel 6
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk 22ndStStation
./wl join 7405  imode bss  amode wpa2psk
fi

if [ $1 == 0a6m ]; then
echo Test 0a6: WPA2-PSK/AES, successful join [lhs_wpa2]
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk Metrotown
./wl join lhs_wpa2  imode bss  amode wpa2psk
fi

if [ $1 == 0a6d ]; then
echo Test 0a6d: WPA2-PSK/AES, successful join [DIRECT-Ni-lhs_ra2_ch1]
./wl channel 1
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk 22ndStStation
./wl join DIRECT-Ni-lhs_ra2_ch1  imode bss  amode wpa2psk
fi

if [ $1 == 0a7 ]; then
echo Test 0a0: Successfully join the "123" WPA2-PSK AES network
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_PSK_SUP status=6(WLC_SUP_KEYED) reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk 12345678
./wl join 123  imode bss  amode wpa2psk
fi


#
# Test case series 0bX: WPA2-PSK TKIP+AES, successful join
# x: none=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 0b0 ]; then
echo Test 0b0: Successfully join the "wlandl_wrt54g" WPA2-PSK TKIP+AES network
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#     WLC_E_PSK_SUP status=6(WLC_SUP_KEYED) reason=0
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 6
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
fi



#
# Test case series 0coX: Open network 80211auth=Open, successful join
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 0co0 ]; then
echo Test case 0co0: Open network 80211auth=Open, successful join [Linksys]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl set_pmk N0C0ffee
./wl join dlbcm  imode bss  amode open
fi

if [ $1 == 0co2 ]; then
echo Test case 0co2: Open network 80211auth=Open, successful join [DI624]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join wlan_DI624  imode bss  amode open
fi

if [ $1 == 0co3 ]; then
echo Test case 0co3: Open network 80211auth=Open, successful join [DI624]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join bbelief  imode bss  amode open
fi

if [ $1 == 0co5 ]; then
echo Test case 0co5: Open network 80211auth=Open, successful join [BCM95354]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join dlbcm  imode bss  amode open
fi

if [ $1 == 0co6 ]; then
echo Test case 0co6: Open, 80211auth=Open, successful join [lhs_open]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join lhs_open  imode bss  amode open
fi

if [ $1 == 0co61 ]; then
echo Test case 0co61: Open, 80211auth=Open, successful join [01]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join 01  imode bss  amode open
fi

if [ $1 == 0co6c ]; then
echo Test case 0co6c: Open, 80211auth=Open, successful join [linksys-cindy]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join linksys-cindy  imode bss  amode open
fi

if [ $1 == 0co6m ]; then
echo Test case 0co6: Open, 80211auth=Open, successful join [lhs_open]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join MyDevice  imode bss  amode open
fi

if [ $1 == 0co6b ]; then
echo Test case 0co6a: Open, 80211auth=Open, successful join [sjlP2P14]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join sjlP2P14  imode bss  amode open
fi



#
# Test case series 0csX: Open network 80211auth=Shared, successful join
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 0cs0 ]; then
echo Test 0cs0: Open/SharedKey, successful join [WRT54G]
# - STA: 80211auth=SharedKey wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
./wl auth 1
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl addwep 0 ED91FE1952
./wl addwep 1 F848FE9790
./wl addwep 2 8B557B6AA5
./wl addwep 3 4B06C3F2A6
./wl primary_key 0
./wl join wlandl_wrt54g  imode bss  amode shared
fi

if [ $1 == 0cs2 ]; then
echo Test 0cs2: Open/SharedKey, successful join [DI624]
# - STA: 80211auth=SharedKey wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=none
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
./wl auth 1
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
#./wl set_pmk N0C0ffee
./wl join wlan_DI624  imode bss  amode open
fi


#
# Test case series 0dX: WEP auth=Shared, successful join
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 0d0 ]; then
echo Test 0d0: WEP/SharedKey, successful join [WRT54G]
# - STA: 80211auth=SharedKey wpa_auth=none wsec=WEP wpa_supplicant=off
# - Linksys WRT54G AP setup: 
#     Wireless/Basic Wireless Settings tab:
#         Wireless Network Mode: Mixed
#         Wireless Network Name (SSID): wlandl_wrt54g
#         Wireless Channel: 6 - 2.37GHz
#         Wireless SSID Broadcaset: Enable
#     Wireless/Wireless Security tab:
#         Security Mode: WEP
#         Default Transmit Key: 1
#         WEP Encryption: 64 bits 10 hex digits
#         Passphrase: RICECOOKIE
#           KEY1: ED91FE1952
#           KEY2: F848FE9790
#           KEY3: 8B557B6AA5
#           KEY4: 4B06C3F2A6
#     Wireless/Wireless MAC Filter tab:
#         Wireless MAC Filter: Disable
#     Wireless/Advanced Wireless Settings tab: (all default settings)
#         Authentication Type: Shared
#         Basic Rate: Default
#         Transmission Rate: Auto
#         CTS Protection Mode: Disable
#         Frame Burst: Disable
#         Beacon Interval: 100
#         DTIM Interval: 1
#         Fragmentation Threshold: 2347
#         AP Isolation: Off
#         Secure Easy Setup: Enable
#     Status tab:
#       MAC=00:14:BF:A7:B8:0B
#
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#
# Note: the "wl wsec 1" line must come after the "wl auth 1" line.  
# If the order is reversed then the join will fail with the log
# "encryption mandatory in BSS, but encryption off for us".
#
# Need to test if this Linux command can be used instead:
#     iwconfig eth1 essid "wlandl_wrt54g" key 3 4B06C3F2A6 key 2 8B557B6AA5 key 1 \
#     F848FE9790 key 0 ED91FE1952
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl addwep 0 ED91FE1952
./wl addwep 1 F848FE9790
./wl addwep 2 8B557B6AA5
./wl addwep 3 4B06C3F2A6
./wl primary_key 0
./wl auth 1
./wl wsec 1
./wl join wlandl_wrt54g  imode bss  amode shared
fi

if [ $1 == 0d2 ]; then
echo Test 0d2: WEP/SharedKey, successful join [DI624]
# - STA: 80211auth=SharedKey wpa_auth=none wsec=WEP wpa_supplicant=off
# - DLink DI624 AP setup: 
#     192.168.0.1, login: admin, password: blank
#     Home tab/Wireless bar settings:
#         SSID: wlan_DI624
#         Channel: Auto Select
#         Super G Mode: Disabled
#         Extended Range Mode: Disabled
#         802.11g Only Mode: Enabled
#         SSID Broadcast: Enabled
#         Security: WEP
#         Authentication: Shared Key
#         WEP Encryption: 64Bit
#         Key Type: HEX
#           KEY1: ED91FE1952
#           KEY2: F848FE9790
#           KEY3: 8B557B6AA5
#           KEY4: 4B06C3F2A6
#     Status tab:
#       MAC=00:1b:11:60:e1:b7
#       IP address: 192.168.0.1
#       Subnet mask: 255.255.255.0
#
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#
# Note: the "wl wsec 1" line must come after the "wl auth 1" line.  
# If the order is reversed then the join will fail with the log
# "encryption mandatory in BSS, but encryption off for us".
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl addwep 0 ed91fe1952
./wl addwep 1 f848fe9790
./wl addwep 2 8b557b6aa5
./wl addwep 3 4b06c3f2a6
./wl primary_key 0
./wl auth 1
./wl wsec 1
./wl join wlan_DI624  imode bss  amode shared
fi



if [ $1 == 0d6 ]; then
echo Test 0d6: WEP/Open, 4 128-bit keys, index 3, successful join [lhs_wep2]
# - STA: 80211auth=Open wpa_auth=none wsec=WEP wpa_supplicant=off
#
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl addwep 0 123456789ABCDEF0123456789A
./wl addwep 1 FEDCBA9876AAAAAAAAABBBBBBB
./wl addwep 2 30405060708090A0B0C0D0E0F0
./wl addwep 3 012233445566778899AABBCCDE
./wl primary_key 3
./wl auth 0
./wl wsec 1
#./wl wsec 0
./wl join lhs_wep2  imode bss  amode open
fi


if [ $1 == 0d6.10 ]; then
echo Test 0d6.10: WEP/Open, ssid=lhs_wep.10, 1 128-bit key, index 0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl rmwep 0
./wl rmwep 1
./wl rmwep 2
./wl rmwep 3
./wl addwep 0 012233445566778899AABBCCDE
./wl primary_key 0
./wl auth 0
./wl wsec 1
./wl join lhs_wep.10  imode bss  amode open
fi

if [ $1 == 0d6.11 ]; then
echo Test 0d6.11: WEP/Open, ssid=lhs_wep.10, 1 128-bit key, index 1
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl rmwep 0
./wl rmwep 1
./wl rmwep 2
./wl rmwep 3
./wl addwep 1 FEDCBA9876AAAAAAAAABBBBBBB
./wl primary_key 1
./wl auth 0
./wl wsec 1
./wl join lhs_wep.11  imode bss  amode open
fi

if [ $1 == 0d6.20 ]; then
echo Test 0d6.20: WEP/Open, ssid=lhs_wep.20, 2 128-bit keys, index 0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl rmwep 0
./wl rmwep 1
./wl rmwep 2
./wl rmwep 3
./wl addwep 0 012233445566778899AABBCCDE
./wl addwep 1 FEDCBA9876AAAAAAAAABBBBBBB
./wl primary_key 0
./wl auth 0
./wl wsec 1
./wl join lhs_wep.20  imode bss  amode open
fi

if [ $1 == 0d6.21 ]; then
echo Test 0d6.21: WEP/Open, ssid=lhs_wep.21, 2 128-bit keys, index 1
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl rmwep 0
./wl rmwep 1
./wl rmwep 2
./wl rmwep 3
./wl addwep 0 012233445566778899AABBCCDE
./wl addwep 1 FEDCBA9876AAAAAAAAABBBBBBB
./wl primary_key 1
./wl auth 0
./wl wsec 1
./wl join lhs_wep.21  imode bss  amode open
fi

if [ $1 == 0d6.22 ]; then
echo Test 0d6.22: WEP/Open, ssid=lhs_wep.22, 2 128-bit keys, index 2
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl rmwep 0
./wl rmwep 1
./wl rmwep 2
./wl rmwep 3
./wl addwep 1 FEDCBA9876AAAAAAAAABBBBBBB
./wl addwep 2 30405060708090A0B0C0D0E0F0
./wl primary_key 2
./wl auth 0
./wl wsec 1
./wl join lhs_wep.22  imode bss  amode open
fi

if [ $1 == 0d6.40 ]; then
echo Test 0d6.40: WEP/Open, ssid=lhs_wep.40, 4 128-bit keys, index 0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl rmwep 0
./wl rmwep 1
./wl rmwep 2
./wl rmwep 3
./wl addwep 0 012233445566778899AABBCCDE
./wl addwep 1 FEDCBA9876AAAAAAAAABBBBBBB
./wl addwep 2 30405060708090A0B0C0D0E0F0
./wl addwep 3 123456789ABCDEF0123456789A
./wl primary_key 0
./wl auth 0
./wl wsec 1
./wl join lhs_wep.40  imode bss  amode open
fi

if [ $1 == 0d6.41 ]; then
echo Test 0d6.41: WEP/Open, ssid=lhs_wep.41, 4 128-bit keys, index 1
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl addwep 0 012233445566778899AABBCCDE
./wl addwep 1 FEDCBA9876AAAAAAAAABBBBBBB
./wl addwep 2 30405060708090A0B0C0D0E0F0
./wl addwep 3 123456789ABCDEF0123456789A
./wl primary_key 1
./wl auth 0
./wl wsec 1
./wl join lhs_wep.41  imode bss  amode open
fi

if [ $1 == 0d6.42 ]; then
echo Test 0d6.42: WEP/Open, ssid=lhs_wep.42, 4 128-bit keys, index 2
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl addwep 0 012233445566778899AABBCCDE
./wl addwep 1 FEDCBA9876AAAAAAAAABBBBBBB
./wl addwep 2 30405060708090A0B0C0D0E0F0
./wl addwep 3 123456789ABCDEF0123456789A
./wl primary_key 2
./wl auth 0
./wl wsec 1
./wl join lhs_wep.42  imode bss  amode open
fi

if [ $1 == 0d6.43 ]; then
echo Test 0d6.43: WEP/Open, ssid=lhs_wep.43, 4 128-bit keys, index 3
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl addwep 0 012233445566778899AABBCCDE
./wl addwep 1 FEDCBA9876AAAAAAAAABBBBBBB
./wl addwep 2 30405060708090A0B0C0D0E0F0
./wl addwep 3 123456789ABCDEF0123456789A
./wl primary_key 3
./wl auth 0
./wl wsec 1
./wl join lhs_wep.43  imode bss  amode open
fi


if [ $1 == 0do2 ]; then
echo Test 0do2: WEP/Open, successful join [DI624]
# - STA: 80211auth=Open wpa_auth=none wsec=WEP wpa_supplicant=off
# - DLink DI624 AP setup: 
#     192.168.0.1, login: admin, password: blank
#     Home tab/Wireless bar settings:
#         SSID: wlan_DI624
#         Channel: Auto Select
#         Super G Mode: Disabled
#         Extended Range Mode: Disabled
#         802.11g Only Mode: Enabled
#         SSID Broadcast: Enabled
#         Security: WEP
#         Authentication: Open
#         WEP Encryption: 64Bit
#         Key Type: HEX
#           KEY1: ED91FE1952
#           KEY2: F848FE9790
#           KEY3: 8B557B6AA5
#           KEY4: 4B06C3F2A6
#     Status tab:
#       MAC=00:1b:11:60:e1:b7
#       IP address: 192.168.0.1
#       Subnet mask: 255.255.255.0
#
# - Resulting events: 
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl addwep 0 ed91fe1952
./wl addwep 1 f848fe9790
./wl addwep 2 8b557b6aa5
./wl addwep 3 4b06c3f2a6
./wl primary_key 0
./wl auth 0
./wl wsec 1
./wl join wlan_DI624  imode bss  amode open
fi

if [ $1 == 0do6 ]; then
echo Test 0do6: WEP/Open, successful join [lhs_wep]
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl addwep 0 ED91FE1952
./wl primary_key 0
./wl auth 0
./wl wsec 1
./wl join lhs_wep  imode bss  amode open
fi


#
# Test case series 0eX: WPA-PSK TKIP, successful join
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000 4=DI524
#

if [ $1 == 0e0 ]; then
echo Test 0e0: WPA-PSK TKIP, successful join [WRT54G]
# - STA: 80211auth=Open wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: 00:14:bf:a7:b8:0c authorized
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#     WLC_E_PSK_SUP status=6(WLC_SUP_KEYED) reason=0
./wl wpa_auth 0x04
./wl sup_wpa 1
./wl auth 0
./wl wsec 2
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpapsk
fi

if [ $1 == 0e2 ]; then
echo Test 0e2: WPA-PSK TKIP, successful join [DI624]
# - STA: 80211auth=Open wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - AP:  80211auth=N/A wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: authentication success
#     wl0: JOIN: association success ...
#     wl0: JOIN: join BSS "wlan_DI624" on channel 6
#     wl0: ROAM: roam_reason cleared to 0x0
#     wl0: link up
#     wl0: adopting aligned TBTT
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#     WLC_E_PSK_SUP status=6(WLC_SUP_KEYED) reason=0
./wl wpa_auth 0x04
./wl sup_wpa 1
./wl auth 0
./wl wsec 2
./wl set_pmk N0C0ffee
./wl join wlan_DI624  imode bss  amode wpapsk
fi

if [ $1 == 0e3 ]; then
echo Test 0e3: WPA-PSK TKIP, successful join [SMT-R2000]
# - STA: 80211auth=Open wpa_auth=wpapsk wsec=TKIP pmk=TESTING123
# - AP:  80211auth=Auto wpa_auth=wpapsk wsec=TKIP pmk=TESTING123
./wl wpa_auth 0x04
./wl sup_wpa 1
./wl auth 0
./wl wsec 2
./wl set_pmk TESTING123
./wl join SMT-R2000-WLAN1  imode bss  amode wpapsk
sleep 5
./wl PM 1
fi

if [ $1 == 0e4 ]; then
echo Test 0e4: WPA-PSK TKIP, successful join [DI524]
# - STA: 80211auth=Open wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: 00:14:bf:a7:b8:0c authorized
./wl wpa_auth 0x04
./wl sup_wpa 1
./wl auth 0
./wl wsec 2
./wl set_pmk swisswaterprocess
./wl join decaf  imode bss  amode wpapsk
fi

if [ $1 == 0e5 ]; then
echo Test 0e5: WPA-PSK TKIP, successful join [BCM95354]
# - STA: 80211auth=Open wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: 00:14:bf:a7:b8:0c authorized
./wl wpa_auth 0x04
./wl sup_wpa 1
./wl auth 0
./wl wsec 2
./wl set_pmk dlbcmdlbcm
./wl join dlbcm  imode bss  amode wpapsk
fi

if [ $1 == 0e6 ]; then
echo Test 0e6: WPA-PSK TKIP, successful join [lhs_wpa]
# - STA: 80211auth=Open wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: 00:14:bf:a7:b8:0c authorized
./wl wpa_auth 0x04
./wl sup_wpa 1
./wl auth 0
./wl wsec 2
./wl set_pmk Metrotown
./wl join lhs_wpa  imode bss  amode wpapsk
fi


if [ $1 == 0f6 ]; then
echo Test 0f6: WPA-PSK AES, successful join [lhs_wpaaes]
./wl wpa_auth 0x04
./wl sup_wpa 1
./wl auth 0
./wl wsec 4
./wl set_pmk Metropolis
./wl join lhs_wpaaes  imode bss  amode wpapsk
fi




if [ $1 == 1 ]; then
echo Test 1: network with given SSID not found
# - Resulting Linux NIC driver logs in /var/log/messages:
#      MACEVENT: SET_SSID, no networks found
# - Resulting events in wl_event(): 
#      WLC_E_SET_SSID status=3 (WLC_E_STATUS_NO_NETWORKS)
# - Expected IWEVCUSTOM event data:
#       "Conn NoNetworks"
./wl auth 0
./wl wpa_auth 0x80
./wl sup_wpa 1
./wl wsec 4
./wl set_pmk UnusedPassphrase
./wl join nosuchap  imode bss  amode wpa2psk
fi



#
# Test case series 2aX: security profile mismatch: WPA2-PSK/None
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2a0 ]; then
echo Test 2a0: security profile mismatch: WPA2-PSK/None [Linksys]
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES 
# - AP:  80211auth=N/A  Security=Disabled
# - Resulting Linux NIC driver logs in /var/log/messages:
# - Resulting events in wl_event(): 
#       WLC_E_PRUNE status=0 reason=8 (WLC_E_RSN_MISMATCH)
#       WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
# - Expected IWEVCUSTOM event data:
#       "Conn ConfigMismatch"
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
fi

if [ $1 == 2a2 ]; then
echo Test 2a2: security profile mismatch: WPA2-PSK/None [DI624]
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES 
# - AP:  80211auth=Auto Security=none
# - Resulting Linux NIC driver logs in /var/log/messages:
# - Resulting events in wl_event(): 
#       WLC_E_PRUNE status=0 reason=8 (WLC_E_RSN_MISMATCH)
#       WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlan_DI624  imode bss  amode wpa2psk
fi


#
# Test case series 2aaX: security profile mismatch: Open/WPA2-PSK
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2aa0 ]; then
echo Test 2aa0: security profile mismatch: None/WPA2-PSK [Linksys]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
# - Resulting events in wl_event(): 
#       WLC_E_PRUNE status=0 reason=1 (WLC_E_PRUNE_ENCR_MISMATCH)
#       WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
# - Expected IWEVCUSTOM event data:
#       "Conn ConfigMismatch"
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode open
fi

if [ $1 == 2aa2 ]; then
echo Test 2aa2: security profile mismatch: None/WPA2-PSK [DI624]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
# - Resulting events in wl_event(): 
#       WLC_E_PRUNE status=0 reason=1 (WLC_E_PRUNE_ENCR_MISMATCH)
#       WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
# - Expected IWEVCUSTOM event data:
#       "Conn ConfigMismatch"
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl set_pmk N0C0ffee
./wl join wlan_DI624  imode bss  amode open
fi


#
# Test case series 2bX: security profile mismatch: WPA2-PSK/WPA-PSK
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2b0 ]; then
echo Test 2b0: security profile mismatch: WPA2-PSK/WPA-PSK
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES 
# - AP:  80211auth=Auto Security=wpa-psk AES
# - Resulting Linux NIC driver logs in /var/log/messages:
# - Resulting events in wl_event(): 
#       WLC_E_PRUNE status=0 reason=8 (WLC_E_RSN_MISMATCH)
#       WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
# - Expected IWEVCUSTOM event data:
#       "Conn ConfigMismatch"
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
fi


#
# Test case series 2cX: security profile mismatch: WPA-PSK/WPA2-PSK
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2c0 ]; then
echo Test 2c0: security profile mismatch: WPA-PSK/WPA2-PSK
# - STA: 80211auth=Open wpa_auth=wpapsk wsec=TKIP+AES
# - AP:  80211auth=Auto Security=WPA2-PSK TKIP+AES
# - Resulting events in wl_event(): 
#       WLC_E_PRUNE status=0 reason=8 (WLC_E_RSN_MISMATCH)
#       WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
# - Expected IWEVCUSTOM event data:
#       "Conn ConfigMismatch"
./wl auth 0
./wl wpa_auth 0x04
./wl wsec 6
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpapsk
fi


#
# Test case series 2dX: WPA/PSK security profile RSN mismatch: AES/TKIP
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2d0 ]; then
echo Test 2d0: WPA-PSK security profile RSN mismatch: AES/TKIP
# - STA: 80211auth=Open wpa_auth=wpa-psk wsec=AES 
# - AP:  80211auth=Auto Security=wpa-psk TKIP
# - Resulting log: 
# - Resulting events in wl_event(): 
#       WLC_E_PRUNE status=0 reason=1 (WLC_E_PRUNE_ENCR_MISMATCH)
#       WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
./wl auth 0
./wl wpa_auth 0x04
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpapsk
fi


#
# Test case series 2eX: WPA2-PSK security profile RSN mismatch: AES/TKIP+AES
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2e0 ]; then
echo Test 2e0: WPA2-PSK security profile RSN mismatch: AES/TKIP+AES [Linksys]
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES 
# - AP:  80211auth=Auto Security=wpa2psk TKIP+AES
# - Result: 
#       successful join 
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_REASSOC status=0 reason=0
#     WLC_E_PSK_SUP status=8 reason=4
#     WLC_E_DEAUTH_IND reason=15
#     ... sequence repeats
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
fi


#
# Test case series 2eX: WPA2 security RSN mismatch: TKIP+AES/AES 
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2e2 ]; then
echo Test 2e2: security profile mismatch: WPA2-PSK, TKIP+AES/AES [DLinkDI624]
# - STA: 80211auth=SharedKey wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
# - AP : 80211auth=N/A wpa_auth=wpa2-psk AES pmk=N0C0ffee
# - Result: 
#       successful join 
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#     WLC_E_PSK_SUP status=6(WLC_SUP_KEYED) reason=0
# NOTE: this test fails for a DLink DI624 before upgrading the firmware:
# - failure events:
#     t=00s WLC_E_AUTH status=0 reason=0
#     t=00s WLC_E_ASSOC status=0 reason=0
#     t=00s WLC_E_JOIN status=0 reason=0
#     t=00s WLC_E_SET_SSID status=0 reason=0
#     t=09s WLC_E_DEAUTH_IND status=0 reason=1
#     t=11s WLC_E_AUTH status=0 reason=0
#     t=11s WLC_E_REASSOC status=1 reason=43
#     t=14s WLC_E_AUTH status=0 reason=0
#     t=14s WLC_E_REASSOC status=1 reason=43
#     ... repeats
./wl auth 1
./wl wpa_auth 0x80
./wl wsec 6
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlan_DI624  imode bss  amode wpa2psk
fi


#
# Test case series 2etX: WPA-PSK AES, TKIP+AES/AES mismatch
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000
#

if [ $1 == 2et2 ]; then
echo Test 2et2: security profile mismatch: WPA-PSK, TKIP+AES/AES [DLinkDI624]
# - STA: 80211auth=SharedKey wpa_auth=wpapsk wsec=TKIP+AES pmk=N0C0ffee
# - AP : 80211auth=N/A Security=wpapsk wsec=TKIP password=N0C0ffee
# - Resulting log: 
#     wl0: JOIN: BSSID 00:11:95:79:cb:ac pruned for security reasons
#     wl0: JOIN: no more join targets available
# - Resulting events:
#       WLC_E_PRUNE status=0 reason=8 (WLC_E_RSN_MSMATCH)
#       WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
./wl auth 1
./wl wpa_auth 0x80
./wl wsec 6
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlan_DI624  imode bss  amode wpa2psk
fi


#
# Test case series 2fX: WPA2 STA/WEP AP security mismatch
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2f0 ]; then
echo Test 2f0: security profile mismatch: WPA2-PSK/WEP
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES 
# - AP:  80211auth=Auto Security=WEP 
# - Resulting log: 
#       nothing unique, just variations of "E_SET_SSID failed"
# - Resulting events in wl_event(): 
#       WLC_E_PRUNE status=0 reason=8 (WLC_E_RSN_MISMATCH)
#       WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
# - Expected IWEVCUSTOM event data:
#       "Conn ConfigMismatch"
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
/wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
fi

if [ $1 == 2f2 ]; then
echo Test 2f2: WPA2/WEP security mismatch [DLinkDI624]
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES supplicant=ON pmk=N0C0ffee
# - AP : 80211auth=Open security=WEP key1=ed91fe1952
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: BSSID 00:14:bf:a7:b8:0c pruned for security reasons
#     wl0: JOIN: no more join targets available
#     wl0: MACEVENT: JOIN ends, E_SET_SSID failed, assoc_state==AS_IDLE
# - Resulting events in wl_event(): 
#     WLC_E_PRUNE status=0 reason=8 (WLC_E_RSN_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
#     NOTE: this is followed by a spurious WLC_E_PSK_SUP status=6 reason=0
#     if previously the STA was successfully connected to the AP using WPA!
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlan_DI624  imode bss  amode wpa2psk
fi


#
# Test case series 2gX: WEP STA/WPA2 AP security profile mismatch
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2g0 ]; then
echo Test 2g0: security profile mismatch: WEP/WPA2-PSK [Linksys]
# - STA: 80211auth=Open wpa_auth=disabled wsec=WEP key=D1CEC0031E 
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: authentication success
#     wl0: JOIN: association failure 12
#     wl0: JOIN: no more join targets available
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC_FAIL status=1 reason=12 (DOT11_SC_ASSOC_FAIL)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl wsec 1
./wl auth 0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl join wlandl_wrt54g  key D1CEC0031E  imode bss  amode open
fi

if [ $1 == 2g4 ]; then
echo Test 2g4: security profile mismatch: WEP/WPA-PSK [DI524]
# - STA: 80211auth=Open wpa_auth=disabled wsec=WEP key=D1CEC0031E 
# - AP:  80211auth=Auto wpa_auth=wpapsk wsec=TKIP+AES pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: authentication success
#     wl0: JOIN: association failure 12
#     wl0: JOIN: no more join targets available
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=1 reason=12 (DOT11_SC_ASSOC_FAIL)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl wsec 1
./wl auth 0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl join decaf  key D1CEC0031E  imode bss  amode open
fi


#
# Test case series 2hX: WEP STA/WPA AP security profile mismatch
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2h0 ]; then
echo Test 2h0: security profile mismatch: WEP/WPA-PSK [Linksys]
# - STA: 80211auth=Open wpa_auth=disabled wsec=WEP key=D1CEC0031E 
# - AP:  80211auth=Auto wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC_FAIL status=1 reason=12 (DOT11_SC_ASSOC_FAIL)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl wsec 1
./wl auth 0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl join wlandl_wrt54g  key D1CEC0031E  imode bss  amode open
fi


#
# Test case series 2iX: WPA-NONE/WPA2-PSK mismatch
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 2i0 ]; then
echo Test 2i0: WPA-NONE/WPA2-PSK security profile mismatch [Linksys]
# - STA: 80211auth=Open wpa_auth=wpa-none wsec=TKIP+AES pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpa2psk  wsec=TKIP+AES pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: authentication success
#     wl0: JOIN: association failure 12
#     wl0: JOIN: no more join targets available
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC_FAIL status=1 reason=12 (DOT11_SC_ASSOC_FAIL)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
# The same results occur with the STA's wpa_auth set to any other value that
# is not WPA2-PSK.
./wl auth 0
./wl wpa_auth 0x00
./wl wsec 6
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode open
fi



#
# Test case series 3aX: Open AP, auth=shared/open mismatch
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 3a0 ]; then
echo Test 3a0: Open AP, 80211auth=Shared/Open mismatch [Linksys]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=none 
# - AP:  80211auth=Auto   Security=disabled wsec=none
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: out-of-sequence authentication response from 00:14:bf:a7:b8:0c
#     wl0: JOIN: timeout waiting for authentication response, assoc_state 8
#     wl0: JOIN: no more join targets available
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=2(WLC_E_STATUS_TIMEOUT) reason=0
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl auth 1
./wl wsec 0
./wl join wlandl_wrt54g  imode bss  amode shared
fi

if [ $1 == 3a2 ]; then
echo Test 3a2: Open AP, 80211auth=SharedKey/Open mismatch [DLinkDI624]
# - STA: 80211auth=SharedKey wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Open Security=Disable
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: BSS case, sending AUTH REQ alg=1 ...
#     wl0: JOIN: authentication failure status 13 from 00:1b:11:60:e1:b7
#     wl0: JOIN: no more join targets available
# - Resulting events for DI624:
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
# - Resulting events for DIR625:
#     WLC_E_AUTH status=2 (WLC_E_STATUS_TIMEOUT) reason=0
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl auth 1
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join wlan_DI624  imode bss  amode shared
fi

if [ $1 == 3a3 ]; then
echo Test 3a3: 80211auth Shared/Open mismatch on open network [SMT-R2000-WLAN1]
# - STA: 80211auth=SharedKey wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=Open Security=Disable
# - Resulting Linux NIC driver logs in /var/log/messages:
# - Resulting events:
#     (no WLC_E_AUTH!)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl auth 1
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join SMT-R2000-WLAN1  imode bss  amode shared
fi


if [ $1 == 3bo0 ]; then
echo Test 3bo0: STA is WEP/Open, AP is Open/Auto [Linksys]
# - STA: 80211auth=Open wpa_auth=disabled wsec=WEP key=01234567FF
# - AP:  80211auth=Auto   Security=disabled
# - Resulting Linux NIC driver logs in /var/log/messages:
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=6 (WLC_E_STATUS_UNSOLICITED) reason=0
#       or WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) reason=0
#       or WLC_E_AUTH status=2 (WLC_E_STATUS_TIMEOUT) reason=0
#   and then
#     WLC_E_AUTH status=2 (WLC_E_STATUS_TIMEOUT) reason=0
#     WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl auth 0
./wl wsec 1
./wl join wlandl_wrt54g  key 01234567FF  imode bss  amode shared
fi

if [ $1 == 3bs0 ]; then
echo Test 3bs0: STA is WEP/SharedKey & AP is Open/SharedKey [Linksys]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key=01234567FF
# - AP:  80211auth=Auto   Security=disabled
# - Resulting Linux NIC driver logs in /var/log/messages:
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=WLC_E_STATUS_TIMEOUT reason=0
#     WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
#   or
#     WLC_E_AUTH status=5(WLC_E_STATUS_NO_ACK) reason=0
#     WLC_E_SET_SSID status=WLC_E_STATUS_FAIL reason=0
# - Expected IWEVCUSTOM event data:
#       "Conn AuthTimeout"
#       "Conn ConfigMismatch"
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl auth 1
./wl wsec 1
./wl join wlandl_wrt54g  key 01234567FF  imode bss  amode shared
fi



#
# Test case series 3cX: Open AP, auth=open/sharedKey mismatch
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 3c0 ]; then
echo Test 3c0: Open-Open/Open-SharedKey mismatches [Linksys]
# - STA: 80211auth=Open wsec=none 
# - AP:  80211auth=Auto(Linksys has no Open) Security=none 
# - Resulting log: 
#     Successful connection
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl auth 0
./wl wsec 0
./wl join wlandl_wrt54g  imode bss  amode open
fi

if [ $1 == 3c2 ]; then
echo Test 3c2: Open + 80211auth=Open/SharedKey mismatches [DLinkDI624]
# - STA: 80211auth=Open wsec=none 
# - AP:  Security=disable (There is no way to set Open/SharedKey!)
# - Resulting Linux NIC driver logs in /var/log/messages:
#     Successful connection
# - Resulting events:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
./wl sup_wpa 0
./wl wpa_auth 0
./wl auth 0
./wl wsec 0
./wl join wlan_DI624  imode bss  amode open
fi



#
# Test case series 4aX: WEP bad password, 80211auth=SharedKey
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 4a0 ]; then
echo Test 4a0: WEP bad password 80211auth=SharedKey [Linksys]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key=123456789A
# - AP:  80211auth=SharedKey wsec=WEP PassPhrase=RICECOOKIE defTxKey=1
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=15 (DOT11_SC_AUTH_CHALLENGE_FAIL)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
# - Expected IWEVCUSTOM event data:
#       "Conn AuthFail 15"
#       "Conn ConfigMismatch"
#
./wl auth 1
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl wsec 1
./wl join wlandl_wrt54g  key 123456789A  imode bss  amode shared
fi

if [ $1 == 4a2 ]; then
echo Test 4a2: WEP bad password 80211auth=SharedKey [DLinkDI624]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key1=123456789A
# - AP:  80211auth=SharedKey wpa_auth=disabled wsec=WEP key1=ED91FE1952
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: Skipping BSSID 00:1b:11:60:e1:b7, encryption not mandatory
#      in BSS, but encryption on and aExcludeUnencrypted set for us.
#     wl0: JOIN: no more join targets available
# - Resulting events for DI624:
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=15 (DOT11_SC_AUTH_CHALLENGE_FAIL)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
# - Resulting events for DIR625:
#     WLC_E_AUTH status=2 (WLC_E_STATUS_TIMEOUT) reason=0
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
#
./wl auth 1
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl wsec 1
./wl join wlan_DI624  key 123456789A  imode bss  amode shared
fi

if [ $1 == 4a3 ]; then
echo Test 4a3: WEP bad password 80211auth=SharedKey [SMT-R2000-WLAN1]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key1=123456789A
# - AP:  80211auth=SharedKey wpa_auth=disabled wsec=WEP key1=ED91FE1952
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
#
./wl auth 1
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl wsec 1
./wl join SMT-R2000-WLAN1  key 123456789A  imode bss  amode shared
fi

if [ $1 == 4a4 ]; then
echo Test 4a4: WEP bad password 80211auth=SharedKey [DI524]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key1=123456789A
# - AP:  80211auth=SharedKey wpa_auth=disabled wsec=WEP key1=ED91FE1952
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
#
./wl auth 1
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl wsec 1
./wl join decaf  key 123456789A  imode bss  amode shared
fi


#
# Test case series 4aX: WEP bad password, 80211auth=Open
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 4ao0 ]; then
echo Test 4ao0: WEP bad password 80211auth=Open [Linksys]
# - STA: 80211auth=Open wpa_auth=disabled wsec=WEP key1=123456789A
# - AP:  80211auth=Auto Security=WEP key1=ED91FE1952
# - Resulting log: 
# - Resulting events for DI624:
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
# - Resulting events for DIR625:
#     WLC_E_AUTH status=2 (WLC_E_STATUS_TIMEOUT) reason=0
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
#
./wl auth 0
./wl wpa_auth 0
./wl sup_wpa 0
./wl wsec 1
./wl join wlandl_wrt54g  key 23456789A1  imode bss  amode open
fi

if [ $1 == 4ao2 ]; then
echo Test 4ao2: WEP bad password 80211auth=Open [DLinkDI624]
# - STA: 80211auth=Open wpa_auth=disabled wsec=WEP key1=123456789A
# - AP:  80211auth=Open wpa_auth=disabled wsec=WEP key1=ED91FE1952
# - Resulting log: 
# - Resulting events for DI624:
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
#
./wl auth 0
./wl wpa_auth 0
./wl sup_wpa 0
./wl wsec 1
./wl primary_key 2
./wl join wlan_DI624  key 123456789A  imode bss  amode shared
fi

if [ $1 == 4ao3 ]; then
echo Test 4ao3: WEP bad password 80211auth=Open [SMT-R2000-WLAN1]
# - STA: 80211auth=Open wpa_auth=disabled wsec=WEP key1=123456789A
# - AP:  80211auth=Open wpa_auth=disabled wsec=WEP key1=ED91FE1952
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
#
./wl auth 0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl wsec 1
./wl join SMT-R2000-WLAN1  key 123456789A  imode bss  amode shared
fi

if [ $1 == 4ao4 ]; then
echo Test 4ao4: WEP bad password 80211auth=Open [DLinkDI524]
# - STA: 80211auth=Open wpa_auth=disabled wsec=WEP key1=123456789A
# - AP:  80211auth=Open wpa_auth=disabled wsec=WEP key1=ED91FE1952
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
#
./wl auth 0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl wsec 1
./wl join decaf  key 123456789A  imode bss  amode shared
fi

if [ $1 == 4an0 ]; then
echo Test 4an0: STA is WEP+SharedKey+NoKey, AP is WEP [Linksys]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key=01234567FF
# - AP:  80211auth=SharedKey Security=WEP key=RICECOOKIE defTxKey=1
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=5(WLC_E_STATUS_NO_ACK) reason=0
#     WLC_E_SET_SSID status=1(WLC_E_STATUS_FAIL) reason=0
#   or
#     WLC_E_SET_SSID status=1(WLC_E_STATUS_FAIL) reason=0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl rmwep 0
./wl rmwep 1
./wl rmwep 2
./wl rmwep 3
./wl primary_key 0
./wl auth 1
./wl wsec 1
./wl join wlandl_wrt54g  imode bss  amode shared
fi

if [ $1 == 4an2 ]; then
echo Test 4an2: STA is WEP/SharedKey/NoKey, AP is WEP/SharedKey [DLinkDI624]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key=01234567FF
# - AP:  80211auth=SharedKey Security=WEP key=RICECOOKIE defTxKey=1
#        key1=ed91fe1952 key==f848fe9790 key3=8b557b6aa5 key4=4b06c3f2a6
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=5(WLC_E_STATUS_NO_ACK) reason=0
#     WLC_E_SET_SSID status=1(WLC_E_STATUS_FAIL) reason=0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl rmwep 0
./wl rmwep 1
./wl rmwep 2
./wl rmwep 3
./wl primary_key 0
./wl auth 1
./wl wsec 1
./wl join wlandl_wrt54g  imode bss  amode shared
fi


if [ $1 == 4b0 ]; then
echo Test 4b0: STA is WEP+SharedKey, AP is Open [Linksys]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key=01234567FF
# - AP:  80211auth=Auto or SharedKey, Security=Disabled
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=1 (WLC_E_STATUS_FAIL) reason=12 (DOT11_SC_ASSOC_FAIL)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl addwep 0 ED91FE1952
./wl addwep 1 F848FE9790
./wl addwep 2 8B557B6AA5
./wl addwep 3 4B06C3F2A6
./wl primary_key 0
./wl auth 1
./wl wsec 1
./wl join wlandl_wrt54g  imode bss  amode shared
fi

if [ $1 == 4b2 ]; then
echo Test 4b2: STA is WEP+SharedKey, AP is Open [DLinkDI624]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key=01234567FF
# - AP:  80211auth=Auto   wpa_auth=disabled wsec=none
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl addwep 0 ED91FE1952
./wl addwep 1 F848FE9790
./wl addwep 2 8B557B6AA5
./wl addwep 3 4B06C3F2A6
./wl primary_key 0
./wl auth 1
./wl wsec 1
./wl join wlan_DI624  imode bss  amode shared
fi


if [ $1 == 4bn0 ]; then
echo Test 4bn0: STA is WEP+SharedKey+NoKey, AP is Open/Auto [Linksys]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key=01234567FF
# - AP:  80211auth=Auto   wpa_auth=disabled wsec=none
# - Resulting log: 
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=5(WLC_E_STATUS_NO_ACK) reason=0
#     WLC_E_SET_SSID status=1(WLC_E_STATUS_FAIL) reason=0
#   or
#     WLC_E_SET_SSID status=1(WLC_E_STATUS_FAIL) reason=0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl rmwep 0
./wl rmwep 1
./wl rmwep 2
./wl rmwep 3
./wl primary_key 0
./wl auth 1
./wl wsec 1
./wl join wlandl_wrt54g  imode bss  amode shared
fi

if [ $1 == 4bn2 ]; then
echo Test 4bn2: STA is WEP+SharedKey+NoKey, AP is Open [DLinkDI624]
# - STA: 80211auth=SharedKey wpa_auth=disabled wsec=WEP key=01234567FF
# - AP:  80211auth=N/A Security=disabled
# - Resulting log: 
# - Resulting events:
#     WLC_E_AUTH status=5(WLC_E_STATUS_NO_ACK) reason=0
#     WLC_E_SET_SSID status=1(WLC_E_STATUS_FAIL) reason=0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl rmwep 0
./wl rmwep 1
./wl rmwep 2
./wl rmwep 3
./wl primary_key 0
./wl auth 1
./wl wsec 1
./wl join wlandl_wrt54g  imode bss  amode shared
fi


if [ $1 == 4c0 ]; then
echo Test 4c0: STA is Open, AP is WEP/SharedKey [Linksys]
# - STA: 80211auth=Open      wpa_auth=disabled wsec=none
# - AP:  80211auth=SharedKey wsec=WEP PassPhrase=RICECOOKIE defTxKey=1
# - Resulting log: 
#     wl0: JOIN: Skipping BSSID 00:1b:11:60:e1:b7, encryption mandatory in
#     BSS, but encryption off for us.
# - Resulting events in wl_event(): 
#     WLC_E_PRUNE status=0 reason=1 (WLC_E_PRUNE_ENCR_MISMATCH)
#     WLC_E_SET_SSID status=1 reason=0
# - Expected IWEVCUSTOM event data:
#       "Conn ConfigMismatch"
./wl auth 0
./wl wpa_auth 0x00
./wl sup_wpa 0
./wl wsec 0
./wl join wlandl_wrt54g amode open
fi

if [ $1 == 4c2 ]; then
echo Test 4c2: STA is Open, AP is WEP/SharedKey [DLinkDI624]
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=SharedKey Security=WEP
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: Skipping BSSID 00:1b:11:60:e1:b7, encryption mandatory in
#      BSS, but encryption off for us.
# - Resulting events:
#     WLC_E_PRUNE status=0 reason=1 (WLC_E_PRUNE_ENCR_MISMATCH)
#     WLC_E_SET_SSID status=1 reason=0
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join wlan_DI624  imode bss  amode shared
fi

if [ $1 == 4c3 ]; then
echo Test 4c3: wsec Open/WEP mismatch [SMT-R2000-WLAN1]
# - STA: 80211auth=SharedKey wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=SharedKey Security=WEP
# This results in the following Linux NIC driver log:
#     wl0: JOIN: Skipping BSSID 00:1b:11:60:e1:b7, encryption mandatory in
#     BSS, but encryption off for us.
# - Resulting events:
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl auth 1
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
#./wl set_pmk N0C0ffee
./wl join SMT-R2000-WLAN1  imode bss  amode shared
fi


if [ $1 == 4cs2 ]; then
echo Test 4cs2: STA is Open/SharedKey, AP is WEP/SharedKey [DLinkDI624]
# - STA: 80211auth=SharedKey wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=SharedKey Security=WEP
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: Skipping BSSID 00:1b:11:60:e1:b7, encryption mandatory in
#      BSS, but encryption off for us.
# - Resulting events:
#     WLC_E_PRUNE status=0 reason=1 (WLC_E_PRUNE_ENCR_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl auth 1
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join wlan_DI624  imode bss  amode shared
fi


#
# Test case series 4dX: Open AP, MAC address banned by AP
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 4d0 ]; then
echo Test 4d0: Join the "wlandl_wrt54g" open network but our MAC addr is banned 
# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP setup:
#     Wireless/Advanced Wireless Settings tab: (all default settings)
#         Authentication Type: Auto
#     Wireless/Wireless Security tab:
#         Security Mode:           Disabled
#     Wireless/Wireless MAC Filter tab: 
#         Wireless MAC Filter:     Enable
#         Prevent/Permit:          Prevent, 
#         MAC address filter list:
#             MAC 01:              00:0F:66:6E:B6:FE
# - Resulting log: 
#       MACEVENT: AUTH, MAC 00:14:bf:a7:b8:0c, Open System, FAILURE, status 1
#       MACEVENT: JOIN ends, E_SET_SSID failed, assoc_state=AS_IDLE, set
#       radio_mpc_disable
# - Resulting events in wl_event(): 
#       WLC_E_AUTH status=WLC_E_STATUS_FAIL
#       WLC_E_SET_SSID status=WLC_E_STATUS_FAIL
# - Expected IWEVCUSTOM event data:
#       Conn AuthFail 01
#       Conn ConfigMismatch
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode open
fi

if [ $1 == 4d2 ]; then
echo Test 4d2: Join the "wlan_DI624" open network but our MAC address is banned 

# - STA: 80211auth=Open wpa_auth=none wsec=none wpa_supplicant=off
# - AP : 80211auth=Open wpa_auth=none wsec=none, MAC address filter on for
#        STA's MAC of 00:1C:26:AC:E9:6B
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: authentication success
#     wl0: disassociation from 00:1b:11:60:e1:b7 (reason 1)
#     wl0: JOIN: timeout waiting for association response
#     wl0: JOIN: no more join targets available
# - Resulting events for DI624:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=2 (WLC_E_STATUS_TIMEOUT) reason=0
#     WLC_E_SET_SSID status=1 reason=0
# - Resulting events for DIR625:
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) reason=1
#     WLC_E_SET_SSID status=1 reason=0
./wl auth 0
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl set_pmk N0C0ffee
./wl join wlan_DI624  imode bss  amode open
fi


#
# Test case series 4eX: WPA2-PSK AES 80211auth Open/SharedKey mismatch 
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
# Note: Cannot test on Linksys WRT54G and DLink DI624 because they do not
#       allow setting 80211auth for WPA2-PSK.
#

if [ $1 == 4e1 ]; then
echo Test 4e1: WPA2-PSK AES 80211auth Open/SharedKey mismatch 
# - STA: 80211auth=SharedKey  wpa_auth=wpa2psk wsec=AES 
# - AP:  80211auth=Open       wpa_auth=wpa2psk wsec=AES
# - Resulting log: 
#     wl0: JOIN: BSS case, sending AUTH REQ alg=1 ...
#     wl0: JOIN: authentication failure status 13 from 00:15:2b:92:c3:60
#     wl0: JOIN: BSS case, sending AUTH REQ alg=1 ...
#     wl0: JOIN: authentication failure status 13 from 00:15:2b:92:c3:60
#     wl0: JOIN: BSS case, sending AUTH REQ alg=1 ...
#     wl0: JOIN: authentication failure status 13 from 00:15:2b:92:c3:60
#     wl0: JOIN: BSS case, sending AUTH REQ alg=1 ...
#     wl0: unsolicited authentication response from 00:16:c8:66:a0:90
#     wl0: JOIN: authentication failure status 13 from 00:0f:24:83:dd:d0
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
#     WLC_E_AUTH status=6 (WLC_E_STATUS_UNSOLICITED) 
#                reason=0
#     WLC_E_AUTH status=1 (WLC_E_STATUS_FAIL) 
#                reason=13 (DOT11_SC_AUTH_MISMATCH)
./wl auth 1
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk 5......... 
./wl join wirelesslab  imode bss  amode shared
fi


if [ $1 == 4f2 ]; then
echo Test 4f2: security mismatch Open/WPA [DLinkDI624]
# - STA: 80211auth=SharedKey wpa_auth=none wsec=none wpa_supplicant=off
# - AP:  80211auth=N/A Security=wpapsk cipher=TKIP
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: Skipping BSSID 00:1b:11:60:e1:b7, encryption mandatory
#      in BSS, but encryption off for us.
#     wl0: JOIN: no more join targets available
# - Resulting events:
#     WLC_E_PRUNE status=0 reason=1 (WLC_E_PRUNE_ENCR_MISMATCH)
#     WLC_E_SET_SSID status=1 (WLC_E_STATUS_FAIL) reason=0
./wl auth 1
./wl wpa_auth 0
./wl wsec 0
./wl sup_wpa 0
./wl join wlan_DI624  imode bss  amode shared
fi



if [ $1 == 5 ]; then
echo Test 5: association failure -- not implemented yet
# I have not found any way to test these connection failures.
# TODO: add test cases here for:
#     WLC_E_ASSOC status=WLC_E_STATUS_FAIL reason=DOT11_SC_REASSOC_FAIL
#     WLC_E_REASSOC status=WLC_E_STATUS_FAIL reason=DOT11_SC_REASSOC_FAIL
#     WLC_E_STATUS_ABORT (due to soft reset, setting IOVAR IOV_ASSOC_RECREATE,
fi



if [ $1 == 6 ]; then
echo Test 6: WPA handshake failure
echo     WLC_E_PSK_SUP status=[wpa state] reason=1..13
# I was unable to create any system test cases to cause these failures.
# So I unit tested these failures by modifying the code:
# - Set up the AP:
#   - STA: 80211auth=Open wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
#   - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
# - For each WLC_E_PSK_SUP reason code: 
#   - In wlc_wpa_sup_eapol(), find the wlc_wpa_send_sup_fail() call with that 
#     reason code.
#   - Temporarily modify the if-statements above that call to force it to 
#     execute the wlc_wpa_send_sup_fail() call.
#   - Run the test case below to make the STA attempt to connect to the AP.
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 6
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
fi



#
# Test case series 7aX: WPA2-PSK AES bad password
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 7a0 ]; then
echo Test 7a0: WPA2-PSK AES bad password [Linksys]
# - STA: 80211auth=Open  wpa_auth=wpa2psk wsec=AES pmk=TestOfBadKey
# - AP:  80211auth=Open  wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_REASSOC status=0 reason=0
#     WLC_E_PSK_SUP status=8 (WLC_SUP_KEYXCHANGE_WAIT_M3) 
#                   reason=14 (WLC_E_SUP_DEAUTH)
#     WLC_E_DEAUTH_IND status=0 reason=15 (DOT11_SC_AUTH_CHALLENGE_FAIL)
#     ...sequence repeats
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk TestOfBadKey
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
echo wl sup_auth_status_ext
./wl sup_auth_status_ext
fi

if [ $1 == 7a1 ]; then
echo Test 7a1: WPA2-PSK AES bad password [wirelesslab]
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=AES pmk=TestOfBadKey
# - AP:  80211auth=Open wpa_auth=wpa2psk wsec=AES pmk=**********
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: authentication success
#     wl0: JOIN: association success ...
#     wl0: link up
#     wl0: deauthentication from 00:0f:24:80:96:60 (reason 0)
#     wl0: wlc_roam_scan: ROAM: roam_reason 0x2 fast_roam 0x0
#     wl0: SCAN: wlc_assoc_scan_start for (ROAM) starting an SSID scan for
#     wirelesslab
#     ...sequence repeats
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#     WLC_E_PSK_SUP status=8 (WLC_SUP_KEYXCHANGE_WAIT_M3) 
#                   reason=14 (WLC_E_SUP_DEAUTH)
#     WLC_E_DEAUTH_IND status=0 reason=0
#     ...sequence repeats
# - Expected IWEVCUSTOM event data:
#       "Conn Deauth"
#       ... repeated many times
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk TestOfBadKey
./wl join wirelesslab  imode bss  amode wpa2psk
fi

if [ $1 == 7a2 ]; then
echo Test 7a2: WPA2-PSK AES bad password [DI624]
# - STA: 80211auth=Open  wpa_auth=wpa2psk wsec=AES pmk=TestOfBadKey
# - AP:  80211auth=Open  wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: authentication success
#     wl0: JOIN: reassociation failure 43
#     ...sequence repeats
# - Resulting events for DI624:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=1 reason=43
#     WLC_E_SET_SSID status=1 reason=0
#     WLC_E_PSK_SUP status=8 reason=0
# - Resulting events for DIR625:
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#     WLC_E_PSK_SUP status=8 reason=14
#     WLC_E_DEAUTH_IND status=0 reason=0
#     ...sequence repeats
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk TestOfBadKey
./wl join wlan_DI624  imode bss  amode wpa2psk
echo wl sup_auth_status_ext
./wl sup_auth_status_ext
fi


#
# Test case series 7aaX: WPA-PSK TKIP bad password
# X: 0=Linksys, 1=Cisco, 2=DI624, 3=SMT-R2000, 4=DI524
#

if [ $1 == 7aa0 ]; then
echo Test 7aa0: WPA-PSK TKIP, bad password [Linksys]
# - STA: 80211auth=Open  wpa_auth=wpapsk wsec=TKIP pmk=TestOfBadKey
# - AP:  80211auth=Open  wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - Resulting log: 
#       wl0: MACEVENT: DEAUTH_IND, MAC 00:14:bf:a7:b8:0c, reason 15
# - Resulting events in wl_event(): 
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_ASSOC status=0 reason=0
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#     WLC_E_PSK_SUP status=8 (WLC_SUP_KEYXCHANGE_WAIT_M3) 
#                   reason=14 (WLC_E_SUP_DEAUTH)
#     WLC_E_DEAUTH_IND status=0 reason=15 (DOT11_SC_AUTH_CHALLENGE_FAIL)
# - Expected IWEVCUSTOM event data:
#       "Conn Deauth 15"
./wl auth 0
./wl wpa_auth 0x04
./wl wsec 2
./wl sup_wpa 1
./wl set_pmk TestOfBadKey
./wl join wlandl_wrt54g  imode bss  amode wpapsk
fi

if [ $1 == 7aa2 ]; then
echo Test 7aa2: WPA-PSK TKIP, bad password [DI624]
# - STA: 80211auth=Open wpa_auth=wpapsk wsec=TKIP pmk=N0C0ffee
# - AP:  80211auth=N/A wpa_auth=wpapsk wsec=TKIP pmk=abadpassword
# - Resulting Linux NIC driver logs in /var/log/messages:
# - Resulting events:
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_SET_SSID status=0 reason=0
#     WLC_E_DEAUTH_IND status=0 reason=1
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_REASSOC status=0 reason=0
#     wl0: link up
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_ROAM(deauth) status=0 reason=0
#
#     WLC_E_PSK_SUP status=8 (WLC_SUP_KEYXCHANGE_WAIT_M3) 
#                   reason=14 (WLC_E_SUP_DEAUTH)
#     WLC_E_DEAUTH_IND status=0 reason=1
#     WLC_E_AUTH status=0 reason=0
#     WLC_E_REASSOC status=0 reason=0
#     wl0: link up
#     WLC_E_JOIN status=0 reason=0
#     WLC_E_ROAM(deauth) status=0 reason=0
#     ...
#     The WLC_E_PSK_SUP...WLC_E_ROAM event block repeats every 10 seconds
./wl wpa_auth 0x04
./wl sup_wpa 1
./wl auth 0
./wl wsec 2
./wl set_pmk abadpassword
./wl join wlan_DI624  imode bss  amode wpapsk
fi

if [ $1 == 7aa4 ]; then
echo Test 7aa4: WPA-PSK TKIP bad password [DI524]
# - STA: 80211auth=Open wpa_auth=wpapsk wsec=TKIP pmk=abadpassword
# - AP:  80211auth=Auto wpa_auth=wpapsk wsec=TKIP pmk=someotherpassword
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: 00:14:bf:a7:b8:0c authorized
./wl wpa_auth 0x04
./wl sup_wpa 1
./wl auth 0
./wl wsec 2
./wl set_pmk abadpassword
./wl join decaf  imode bss  amode wpapsk
fi



if [ $1 == 7b1 ]; then
echo Test 7b1: De-auth fail due to WPA2 auth open/SharedKey mismatch 
# - STA: 80211auth=SharedKey  wpa_auth=wpa2psk wsec=AES 
# - AP:  80211auth=Open       wpa_auth=wpa2psk wsec=AES
# - Resulting log: 
#     Successful join
# - Resulting events in wl_event(): 
./wl wpa_auth 0x80
./wl auth 1
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk 5......... 
./wl join wirelesslab  imode bss  amode wpa2psk
fi


if [ $1 == 7c0 ]; then
echo Test 7c0: STA disassoc after successful join [Linksys]
# - STA: 80211auth=Open  wpa_auth=wpapsk wsec=AES  pmk=N0C0ffee
# - AP:  80211auth=Auto  wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - Resulting log: 
#       wl0: MACEVENT: LINK UP
#       wl0: 00:14:bf:a7:b8:0c authorized
#       wl0: JOIN: sending DISASSOC to 00:14:bf:a7:b8:0c
# - Resulting events in wl_event(): 
#       WLC_E_LINK
#       WLC_E_DISASSOC status=WLC_E_STATUS_FAIL status=0 reason=8
# - Expected IWEVCUSTOM event data:
#       "Conn Disassoc 08"
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
sleep 6
./wl down
fi

if [ $1 == 7c2 ]; then
echo Test 7c2: STA disassoc after successful join [DI624]
# - STA: 80211auth=Open  wpa_auth=wpapsk wsec=AES  pmk=N0C0ffee
# - AP:  80211auth=Auto  wpa_auth=wpa2psk wsec=AES pmk=N0C0ffee
# - Resulting Linux NIC driver logs in /var/log/messages:
#     wl0: JOIN: association success ...
#     wl0: link up
#     wl0: JOIN: sending DISASSOC to 00:1b:11:60:e1:b7
# - Resulting events in wl_event(): 
#     wl0: link down
#     *** No WLC_E_DISASSOC is seen!
# ***TODO: investigate this
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlan_DI624  imode bss  amode wpa2psk
sleep 6
echo ./wl disassoc
./wl disassoc
fi


if [ $1 == 7d ]; then
echo Test 7d: Successfully join the "wlandl_wrt54g" WPA2-PSK TKIP+AES network
echo          and then turn on the MAC address filter on the AP to kick off
echo          the STA.
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
#
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 6
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
#
# After this we should be successfully connected, as shown by this log:
#       wl0: 00:14:bf:a7:b8:0c authorized
# Go to the router's Wireless/Wireless MAC Filter tab and enable the filter.
# On this PC, enter "ping 192.168.1.1".
# - Resulting log: 
#       wl0: MACEVENT: DEAUTH_IND, MAC 00:14:bf:a7:b8:0c, reason 7
# - Resulting events in wl_event(): 
#       WLC_E_DEAUTH_IND reason=7
# - Expected IWEVCUSTOM event data:
#       Conn Deauth 07
fi



if [ $1 == 8 ]; then
echo Test 8: STA can see AP beacons, but AP cannot see packets sent by STA
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
#
# NOTE!! Before running this test, you must temporarily modify 
#        wlc_wpa_sup_sendeapol() to discard the packet being sent.
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 6
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
fi



if [ $1 == 9 ]; then
echo Test 9: Multiple APs with the same settings.
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
# - AP : 80211auth=Auto wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
#
# NOTE!! Before running this test, you must set up 2 or more APs with the same
#        settings at different distances from the STA.
# - Should see multiple connect fails + 1 success?
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 6
./wl sup_wpa 1
./wl set_pmk N0C0ffee
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
fi


if [ $1 == 10 ]; then
echo Test 10: Check that the auth state and WPA state IOVARs do not contain 
echo          leftover values from the previous join attempt.
#
echo === Part 1: Successfully join the "wlandl_wrt54g" WPA2-PSK network
# - STA: 80211auth=Open wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
# - AP:  80211auth=Auto wpa_auth=wpa2psk wsec=TKIP+AES pmk=N0C0ffee
#
# NOTE!! This test will not pass due to the fix for PR55757.
#
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 6
./wl sup_wpa 1
./wl set_pmk N0C0ffee
sleep 1
./wl join wlandl_wrt54g  imode bss  amode wpa2psk
sleep 2
echo wl status, wl_sup_auth_status_ext: should be 6
./wl sup_auth_status_ext
#
sleep 10
./wl sup_auth_status_ext
./wl down
sleep 1
./wl up
sleep 1
#
echo === Part 2: join, SSID not found
# - Expected IWEVCUSTOM event data:
#       "Conn NoNetworks"
./wl auth 0
./wl wpa_auth 0x80
./wl wsec 4
./wl set_pmk UnusedPassphrase
./wl join nosuchap  imode bss  amode wpa2psk
sleep 2
echo wl_sup_auth_status_ext: should be 0
./wl sup_auth_status_ext
fi


if [ $1 == 11 ]; then
echo Test 11: Disable sending IWEVCUSTOM events via the event_msgs bitvector
# - STA tries to join the AP named "nosuchap"
# - Resulting log:
#      MACEVENT: SET_SSID, no networks found
# - Resulting events in wl_event(): 
#      WLC_E_SET_SSID status=3 (WLC_E_STATUS_NO_NETWORKS)
# - Expected IWEVCUSTOM event data:
#       none (not "Conn NoNetworks")
# NOTE:
#   This test fails with a Linux NIC driver build (still see "Conn NoNetworks")
#   Need to try this with a dongle/dhd build.
#
./wl event_msgs 0x00000000000000000000000000000000
./wl auth 0
./wl wpa_auth 0x80
./wl sup_wpa 1
./wl wsec 4
./wl set_pmk UnusedPassphrase
./wl join nosuchap  imode bss  amode wpa2psk
fi




# Show the connection status 
sleep 4
echo wl sup_auth_status, sup_auth_status_ext
./wl sup_auth_status
./wl sup_auth_status_ext
sleep 2
echo wl sup_auth_status, sup_auth_status_ext
./wl sup_auth_status
./wl sup_auth_status_ext
#sleep 2
#echo wl sup_auth_status, sup_auth_status_ext
#./wl sup_auth_status
#./wl sup_auth_status_ext
#sleep 2
#echo wl sup_auth_status, sup_auth_status_ext
#./wl sup_auth_status
#./wl sup_auth_status_ext
#sleep 2
#echo wl sup_auth_status, sup_auth_status_ext
#./wl sup_auth_status
#./wl sup_auth_status_ext
#sleep 2
#echo wl sup_auth_status, sup_auth_status_ext
#./wl sup_auth_status
#./wl sup_auth_status_ext

echo wl status 
./wl status
date



### @@@ TEMPORARY debug WL commands
#./wl bcn_li_bcn 0
#./wl bcn_li_dtim 3
#./wl msglevel +rtdc
#./wl pm2_sleep_ret 50
#./wl pm2_tx_no_exit_ps 1
#./wl pm2_rcv_dur 50
#./wl PM 2

# Flush cached disk writes to disk in case we crash in the next test
sync

#ifconfig eth1 192.168.16.21
ifconfig eth1
#ping -c 3 192.168.16.1
