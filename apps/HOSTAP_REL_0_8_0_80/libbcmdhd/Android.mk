#
# Copyright (C) 2008 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

ifeq ($(WPA_SUPPLICANT_VERSION),VER_0_8_X)

ifneq ($(BOARD_WPA_SUPPLICANT_DRIVER),)
  CONFIG_DRIVER_$(BOARD_WPA_SUPPLICANT_DRIVER) := y
endif

WPA_SUPPL_DIR = $(LOCAL_PATH)/..
WPA_SRC_FILE :=

include $(WPA_SUPPL_DIR)/wpa_supplicant/android.config

WPA_SUPPL_DIR_INCLUDE = $(WPA_SUPPL_DIR)/src \
	$(WPA_SUPPL_DIR)/src/common \
	$(WPA_SUPPL_DIR)/src/drivers \
	$(WPA_SUPPL_DIR)/src/l2_packet \
	$(WPA_SUPPL_DIR)/src/utils \
	$(WPA_SUPPL_DIR)/src/wps \
	$(WPA_SUPPL_DIR)/wpa_supplicant
ifdef CONFIG_DRIVER_NL80211
WPA_SUPPL_DIR_INCLUDE += bionic/libc/include
WPA_SUPPL_DIR_INCLUDE += bionic/libc/kernel/common
WPA_SUPPL_DIR_INCLUDE += external/libnl_2/include
WPA_SUPPL_DIR_INCLUDE += external/libnl_2/include/linux
WPA_SUPPL_DIR_INCLUDE += external/libnl-headers
WPA_SRC_FILE += driver_cmd_nl80211.c
endif

ifdef CONFIG_WAPI
WPA_SUPPL_DIR_INCLUDE += $(WPA_SUPPL_DIR)/src/wapi
endif

ifdef CONFIG_DRIVER_WEXT
WPA_SRC_FILE += driver_cmd_wext.c
endif

# To force sizeof(enum) = 4
L_CFLAGS += -mabi=aapcs-linux

# To make P2P working in existing Android framework (below KLP)
# with kernels below linux-3.8
ifdef CONFIG_P2P_HACK_PRE38
L_CFLAGS += -DCONFIG_P2P_HACK_PRE38
endif

# To make P2P working in existing Android framework (below KLP)
# with kernels linux-3.8 and above
ifdef CONFIG_P2P_HACK_POST38
ifdef CONFIG_P2P_HACK_PRE38
$(error "CONFIG_P2P_HACK_PRE38 and CONFIG_P2P_HACK_POST38 are mutually exclusive")
endif
L_CFLAGS += -DCONFIG_P2P_HACK_POST38
endif

# To Support SD offload
ifdef CONFIG_BRCM_SDO
SUPP_CFLAGS += -DBCM_SDO -DANDROID_P2P -DBCM_GENL
# Enable BCM_MAP_SDCMDS_2_SDOCMDS to map old wpa_cli commands to SD offloaded Commands
#SUPP_CFLAGS += -DBCM_MAP_SDCMDS_2_SDOCMDS
endif
HOSTAPD_CFLAGS += -DHOSTAPD

ifdef CONFIG_ANDROID_LOG
L_CFLAGS += -DCONFIG_ANDROID_LOG
endif

#Enable and configure firmware for driver based roaming
ifdef CONFIG_BRCM_DRV_ROAM
L_CFLAGS += -DBRCM_DRV_ROAM
endif

ifdef CONFIG_IEEE80211R
L_CFLAGS += -DCONFIG_IEEE80211R
endif

ifdef CONFIG_BRCM_VE
L_CFLAGS += -DBRCM_VE
endif

ifdef CONFIG_WAPI
L_CFLAGS += -DWAPI
endif

ifdef CONFIG_CTRL_IFACE_DBUS
L_CFLAGS += -DCONFIG_CTRL_IFACE_DBUS
endif

ifdef CONFIG_AP
L_CFLAGS += -DCONFIG_AP
endif

########################
include $(CLEAR_VARS)
LOCAL_MODULE := lib_driver_cmd_bcmdhd_supplicant
LOCAL_SHARED_LIBRARIES := libc libcutils
LOCAL_CFLAGS := $(L_CFLAGS) $(SUPP_CFLAGS)
LOCAL_SRC_FILES := $(WPA_SRC_FILE)
LOCAL_C_INCLUDES := $(WPA_SUPPL_DIR_INCLUDE)
include $(BUILD_STATIC_LIBRARY)
########################
include $(CLEAR_VARS)
LOCAL_MODULE := lib_driver_cmd_bcmdhd_hostapd
LOCAL_SHARED_LIBRARIES := libc libcutils
LOCAL_CFLAGS := $(L_CFLAGS) $(HOSTAPD_CFLAGS)
LOCAL_SRC_FILES := $(WPA_SRC_FILE)
LOCAL_C_INCLUDES := $(WPA_SUPPL_DIR_INCLUDE)
include $(BUILD_STATIC_LIBRARY)
########################
endif
