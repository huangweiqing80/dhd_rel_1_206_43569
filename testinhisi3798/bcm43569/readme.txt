1.用串口终端登录板子HI3798MDM01A或者通过adb shell, 需要将bcm43569目录推到目标板目录/data
adb push ./bcm43569 /data/bcm43569
2.移除ath6kl_usb，cfg80211_ath6k
$rmmod ath6kl_usb
$rmmod cfg80211_ath6k
3.插入模块cfg80211
$insmod /system/lib/modules/cfg80211.ko
4.下载wifi模块固件与加载驱动
$./insmod43569.sh
or $./insmod43569ap.sh  (Driver for AP)
5.测试STA
$./testwifista.sh （需要修改配置文件wpa_supplicant.conf，加入相应的热点AP）
5.测试AP或者STA
$./testwifista.sh （缺省是SSID:itontest, 无加密。可通过修改hostapd.conf，完成其它配置的测试）