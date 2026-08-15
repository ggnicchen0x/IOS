TARGET := iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = FreeFireMAX

ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FFMAXLicense

FFMAXLicense_FILES = Tweak.x
FFMAXLicense_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
FFMAXLicense_FRAMEWORKS = Foundation UIKit Security
FFMAXLicense_PRIVATE_FRAMEWORKS =
FFMAXLicense_LDFLAGS = -lz

include $(THEOS_MAKE_PATH)/tweak.mk
