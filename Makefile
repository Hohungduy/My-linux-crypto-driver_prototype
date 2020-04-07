#
# Copyright (c) 2020 Duyho
# This is free software, lisenced under the GNU General Public Lisence v2.
#
#  $Id$

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mycrypto
PKG_VERSION:=1.10
PKG_RELEASE:=1
 
PKG_SOURCE_URL:=https://github.com/Hohungduy/My-linux-crypto-driver_prototype.git 
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_PROTO:=git
PKG_MIRROR_HASH:=skip
PKG_HASH:=22f8640fa5afdb9ef3353f9179a497fccde4502c6cfb2a4c035872a94917d6d7
PKG_HASH:=skip
PKG_SOURCE_VERSION=$(PKG_VERSION)
PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=COPYING

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
MODULE_FILES=$(PKG_BUILD_DIR)/*.$(LINUX_KMOD_SUFFIX)
MODULE_HEADER:=$(PKG_NAME).h

include $(INCLUDE_DIR)/package.mk

define KernelPackage/mycrypto
	SUBMENU:=Cryptographic API modules
	DEFAULT:=y if ALL
	TITLE:=Driver for cryptographic acceleration
	URL:=http://google.vn
	VERSION:=$(LINUX_VERSION)+$(PKG_VERSION)-$(BOARD)-$(PKG_RELEASE)
	DEPENDS:=+kmod-crypto-authenc +kmod-crypto-hash +kmod-crypto-md5 +kmod-crypto-hmac +kmod-crypto-sha256 +kmod-crypto-sha512
	FILES:=$(MODULE_FILES)
	AUTOLOAD:=$(call AutoLoad,50,mycrypto)
	$(call AddDepends/crypto)
endef

define KernelPackage/my_cryptodriver/description
	This is prototype for hardware accelerator engine driver for FPGA cards (PCIe)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

EXTRA_KCONFIG:= \
	CONFIG_MYCRYPTO=m

EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG)))) \

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	TARGET="$(HAL_TARGET)" \
	TOOLPREFIX="$(KERNEL_CROSS)" \
	TOOLPATH="$(KERNEL_CROSS)" \
	KERNELPATH="$(LINUX_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(EXTRA_KCONFIG)

define Build/Configure
endef

# define Build/Compile
# 	  $(MAKE) -C $(PKG_BUILD_DIR) \
# 		$(KERNEL_MAKE_FLAGS) \
# 		KERNEL_DIR="$(LINUX_DIR)" all
# endef

# define Build/Compile
#     $(MAKE) -C "$(LINUX_DIR)" \
#         $(MAKE_OPTS) \
#         modules
# endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
	$(MAKE_OPTS) \
	modules
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include/crypto
	$(CP) $(PKG_BUILD_DIR)/mycrypto.h $(STAGING_DIR)/usr/include/crypto/
endef

$(eval $(call KernelPackage,mycrypto))


