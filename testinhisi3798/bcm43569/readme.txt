1.�ô����ն˵�¼����HI3798MDM01A����ͨ��adb shell, ��Ҫ��bcm43569Ŀ¼�Ƶ�Ŀ���Ŀ¼/data
adb push ./bcm43569 /data/bcm43569
2.�Ƴ�ath6kl_usb��cfg80211_ath6k
$rmmod ath6kl_usb
$rmmod cfg80211_ath6k
3.����ģ��cfg80211
$insmod /system/lib/modules/cfg80211.ko
4.����wifiģ��̼����������
$./insmod43569.sh
or $./insmod43569ap.sh  (Driver for AP)
5.����STA
$./testwifista.sh ����Ҫ�޸������ļ�wpa_supplicant.conf��������Ӧ���ȵ�AP��
5.����AP����STA
$./testwifista.sh ��ȱʡ��SSID:itontest, �޼��ܡ���ͨ���޸�hostapd.conf������������õĲ��ԣ�