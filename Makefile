# sparsebundlefs-lib
#
# Mount macOS sparsebundles (encrypted or plain) as a single virtual disk
# image via FUSE. Supports both legacy 3DES-CBC wrapped keyblobs and modern
# (Big Sur+) AES-192-CBC wrapped keyblobs.

# ------------------------------------------------------------ Configuration

# Use libfuse3 by default. Override on the command line: `make FUSE_PC=fuse`
FUSE_PC ?= fuse3

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wno-deprecated-declarations
LDFLAGS ?=

# Auto-pull include paths and linker flags
PKG_CFLAGS := $(shell pkg-config --cflags $(FUSE_PC) libcrypto)
PKG_LIBS   := $(shell pkg-config --libs   $(FUSE_PC) libcrypto)

DEFINES := -D_FILE_OFFSET_BITS=64 -DSPARSEBUNDLEFS_USE_EMBEDDED_CRYPTO

INCLUDES := \
    -Isrc/sparsebundlefs \
    -Isrc/crypto \
    -Isrc/crypto/aes-rijndael \
    -Isrc/crypto/hmac-sha1/hmac \
    -Isrc/crypto/hmac-sha1/sha

# ------------------------------------------------------------ Sources

LIB_SRCS := \
    src/sparsebundlefs/sparsebundlefs.c \
    src/crypto/Des.c \
    src/crypto/TripleDes.c \
    src/crypto/PBKDF2_HMAC_SHA1.c \
    src/crypto/aes-rijndael/aescrypt.c \
    src/crypto/aes-rijndael/aeskey.c \
    src/crypto/aes-rijndael/aes_modes.c \
    src/crypto/aes-rijndael/aestab.c \
    src/crypto/aes-rijndael/aesxts.c \
    src/crypto/hmac-sha1/hmac/hmac_sha1.c \
    src/crypto/hmac-sha1/sha/sha1.c

FUSE_SRC := src/fuse/sparsebundlefs-fuse.c

BUILD_DIR := build
TARGET    := $(BUILD_DIR)/sparsebundlefs

# ------------------------------------------------------------ Targets

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(FUSE_SRC) $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) $(PKG_CFLAGS) \
	    $(FUSE_SRC) $(LIB_SRCS) \
	    -o $@ $(LDFLAGS) $(PKG_LIBS) -lpthread

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

PREFIX ?= /usr/local
install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/sparsebundlefs

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/sparsebundlefs
