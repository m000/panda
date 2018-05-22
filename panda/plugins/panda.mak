# Note: We will be run from target directory. (build/target)

include ../config-host.mak
include config-devices.mak
include config-target.mak
include $(SRC_PATH)/rules.mak

ifdef EXTRA_PLUGINS_PATH
$(call set-vpath, $(SRC_PATH):$(EXTRA_PLUGINS_PATH):$(BUILD_DIR))
else
$(call set-vpath, $(SRC_PATH):$(BUILD_DIR))
endif

PLUGIN_SRC_DIR=$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)
PLUGIN_OBJ_DIR=panda/plugins/$(PLUGIN_NAME)
PLUGIN_TARGET_DIR=panda/plugins

TARGET_PATH=$(SRC_PATH)/target/$(TARGET_BASE_ARCH)
TARGET_BUILD=../target/$(TARGET_BASE_ARCH)

# Macro expanding to the name of the compiled unit.
# E.g. this will be when compiling /path/to/taint2.cpp, this expands to taint2.
# We need to make sure that this is not force-expanded (:=) prematurely.
PLUGIN_CC_UNIT=$(basename $(notdir $<))

# Define PLUGIN_MAIN if compiled unit matches plugin name.
# PLUGIN_MAIN is used by the PPP *_ext.h files (generated by apigen.py),
# to make sure that api call function pointers are defined only once,
# in the main compilation unit of th plugin.
# We append PLUGIN_MAIN to CFLAGS because some plugins prematurely expand
# QEMU_CFLAGS/QEMU_CXXFLAGS in order to filter-out some flags.
CFLAGS+=$(if $(subst $(PLUGIN_CC_UNIT),,$(PLUGIN_NAME)),,-DPLUGIN_MAIN)

# Extra flags
QEMU_CFLAGS+=-DPLUGIN_NAME=\"$(PLUGIN_NAME)\" -DNEED_CPU_H -fPIC
QEMU_CXXFLAGS+=-DPLUGIN_NAME=\"$(PLUGIN_NAME)\" -DNEED_CPU_H -fPIC -fpermissive -std=c++11

# GLib flags
QEMU_CFLAGS+=$(GLIB_CFLAGS)
QEMU_CXXFLAGS+=$(GLIB_CFLAGS) -Wno-pointer-arith

# Include flags
QEMU_INCLUDES+=-I$(PLUGIN_SRC_DIR) -I$(PLUGIN_SRC_ROOT) -I$(SRC_PATH)/panda/plugins
QEMU_INCLUDES+=-I$(PLUGIN_TARGET_DIR) -I.. -I$(TARGET_PATH) -I$(TARGET_BUILD)

# Add plugin dir to runtime library path
LDFLAGS_SHARED+=-Wl,-rpath=$(abspath $(PLUGIN_TARGET_DIR))

# These should get generated automatically and include dependency information.
-include $(wildcard $(PLUGIN_OBJ_DIR)/*.d)

# You can override this recipe by using the full name of the plugin in a
# plugin Makefile. (e.g. $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)$(DSOSUF)).
$(PLUGIN_TARGET_DIR)/panda_%$(DSOSUF):
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) $(LDFLAGS) $(LDFLAGS_SHARED) -o $@ $^ $(LIBS),"PLUGIN  $(TARGET_DIR)$@")

# Rule for creating support .so files.
$(PLUGIN_TARGET_DIR)/dso_$(PLUGIN_NAME)_%$(DSOSUF): $(PLUGIN_SRC_DIR)/%.c
	$(call quiet-command,$(CC) $(LDFLAGS) $(LDFLAGS_SHARED) -o $@ $^,"DSO     $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)$(DSOSUF)
