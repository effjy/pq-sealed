# Makefile for PQ-Sealed — incremental post-quantum encrypted backups (GTK3).
#
# Requires: gtk+-3.0, libsodium (secretstream / Argon2 / RNG), libargon2
# (Argon2id KDF), OpenSSL >= 3.0 (X448 + SHA-256/AES-GCM for key armor), and
# liboqs (ML-DSA snapshot signing). All are located via pkg-config. liboqs is
# rarely packaged; build it with ./setup-liboqs.sh, then if it lives in a
# custom prefix point pkg-config at it:
#
#   make PKG_CONFIG_PATH=$HOME/.local/lib/pkgconfig
#
# Targets:
#   make                build the ./pq-sealed binary
#   sudo make install   install globally (binary, icon, menu entry)
#   sudo make uninstall remove all installed files
#   make clean

VERSION := 1.0.1
BIN     := pq-sealed

PREFIX   ?= /usr/local
BINDIR   := $(PREFIX)/bin
DATADIR  := $(PREFIX)/share
APPDIR   := $(DATADIR)/applications
ICONBASE := $(DATADIR)/icons/hicolor
ICONDIR  := $(ICONBASE)/scalable/apps

# Raster icon sizes installed alongside the scalable SVG so the icon shows
# reliably in the applications menu and the window/taskbar.
ICON_SIZES := 16 24 32 48 64 128 256

export PKG_CONFIG_PATH
PKG_CONFIG ?= pkg-config
DEPS        = gtk+-3.0 libsodium libargon2 openssl liboqs
PKG_CFLAGS  = $(shell $(PKG_CONFIG) --cflags $(DEPS))
PKG_LIBS    = $(shell $(PKG_CONFIG) --libs $(DEPS))

CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wshadow -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong
# Kyber-1024 = NIST level 5 (KYBER_K=4); kyber/ holds the CRYSTALS reference.
CFLAGS  += -DKYBER_K=4 -Iinclude -Isrc/kyber $(PKG_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)
LDLIBS  += $(PKG_LIBS)

# Kyber-1024 reference sources (SHAKE/fips202 only). randombytes is resolved
# from libsodium, so kyber/randombytes.c is intentionally omitted.
KYBER_SRC = src/kyber/kem.c src/kyber/indcpa.c src/kyber/poly.c \
            src/kyber/polyvec.c src/kyber/ntt.c src/kyber/reduce.c \
            src/kyber/cbd.c src/kyber/fips202.c src/kyber/verify.c \
            src/kyber/symmetric-shake.c

SRC = src/main.c src/repo.c src/repocrypto.c src/hybrid_kem.c \
      src/util.c src/keyfile.c src/sigfile.c $(KYBER_SRC)
OBJ = $(SRC:.c=.o)

HDRS = include/sealed.h include/pqsign.h include/keyfile_internal.h \
       src/hybrid_kem.h

.PHONY: all clean install uninstall

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS) $(LDLIBS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -d $(DESTDIR)$(ICONDIR)
	install -m 0644 data/pq-sealed.svg $(DESTDIR)$(ICONDIR)/pq-sealed.svg
	for s in $(ICON_SIZES); do \
	    install -d $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps; \
	    install -m 0644 data/pq-sealed-$${s}.png \
	        $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps/pq-sealed.png; \
	done
	install -d $(DESTDIR)$(APPDIR)
	install -m 0644 data/pq-sealed.desktop $(DESTDIR)$(APPDIR)/pq-sealed.desktop
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	@echo "PQ-Sealed $(VERSION) installed to $(BINDIR)/$(BIN)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(ICONDIR)/pq-sealed.svg
	for s in $(ICON_SIZES); do \
	    rm -f $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps/pq-sealed.png; \
	done
	rm -f $(DESTDIR)$(APPDIR)/pq-sealed.desktop
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	@echo "PQ-Sealed uninstalled"

clean:
	rm -f $(OBJ) $(BIN)
