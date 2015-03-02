Brcm wpa supplicant release notes:

1: If the driver is built under kernel version 3.4, please enable flag WL_SUPPORT_BACKPORTED_KPATCHES.
2: Make sure that Kernel has following configurations enabled:
CONFIG_WIRELESS_EXT=y
CONFIG_CFG80211=y
CONFIG_NL80211_TESTMODE=y
CONFIG_CFG80211_DEVELOPER_WARNINGS=y
CONFIG_CFG80211_REG_DEBUG=y
CONFIG_CFG80211_DEFAULT_PS=y
CONFIG_CFG80211_DEBUGFS=y
CONFIG_CFG80211_INTERNAL_REGDB=y
CONFIG_CFG80211_WEXT=y
CONFIG_LIB80211=y
CONFIG_LIB80211_DEBUG=y
CONFIG_CFG80211_ALLOW_RECONNECT=y

3: Install OpenSSL and libnl open source and build them.
Currently we are using following version:
OpenSSL: 1.0.1g
libnl: 3.2.14
4: Build wpa supplicant.
Specify the path of libnl header and openssl in Makefile. See reference patch: wpa.patch.
5: Load binaries:
Copy wpa_supplican and wpa_cli from /wpa_supplicant to working directory.
Copy libnl* from libnl-3.2.14/lib/.libs/ to working directory.


Sample build steps ( for Android linux 3.3.6 on STB)
1.	source setenv-android.sh (Set Cross Compiler Environment)

2.	cd OPENSSL/openssl-1.0.1g
./Configure linux-mips
make CC=mipsel-linux-gcc

3.	cd libnl-3.2.14
./configure --host=mipsel-linux
make CC=mipsel-linux-gcc clean
make CC=mipsel-linux-gcc

4.	cd libbcmdhd
make CC=mipsel-linux-gcc clean
make CC=mipsel-linux-gcc

5.	cd wpa_supplicant
make CC=mipsel-linux-gcc clean
make CC=mipsel-linux-gcc



