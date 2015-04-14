RAGEL = ragel
RAGEL_FLAGS = -F0 -C

COMPILE.rl = $(RAGEL) $(RAGEL_FLAGS)
COMPILE.c = $(CC) $(CFLAGS) $(EXTRA_FLAGS) -c

%.c: %.rl
	$(COMPILE.rl) $(OUTPUT_OPTION) $<

VERSION=v13
GIT_DESC=$(shell test -d .git && git describe 2>/dev/null)

ifneq "$(GIT_DESC)" ""
VERSION=$(GIT_DESC)
endif

base_CFLAGS = -std=c11 -g \
	-Wall -Wextra -pedantic \
	-Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes \
	-D_GNU_SOURCE \
	-DENVOY_VERSION=\"$(VERSION)\"

libsystemd_CFLAGS = $(shell pkg-config --cflags libsystemd-daemon)
libsystemd_LDLIBS = $(shell pkg-config --libs libsystemd-daemon)

dbus_CFLAGS = $(shell pkg-config --cflags dbus-1)
dbus_LDLIBS = $(shell pkg-config --libs dbus-1)

CFLAGS := \
	$(base_CFLAGS) \
	$(libsystemd_CFLAGS) \
	$(dbus_CFLAGS) \
	$(CFLAGS)

LDLIBS := \
	$(libsystemd_LDLIBS) \
	$(dbus_LDLIBS) \
	$(LDLIBS)

LIBDIR := $(shell pkg-config --variable=libdir libsystemd)

VPATH = src

all: envoyd envoy envoy-exec pam_envoy.so

gpg-protocol.o: gpg-protocol.c
gpg-protocol.o: EXTRA_FLAGS := -fPIC -Isrc

pam_envoy.o: EXTRA_FLAGS := -fPIC
agents.o: EXTRA_FLAGS := -fPIC
socket.o: EXTRA_FLAGS := -fPIC
util.o: EXTRA_FLAGS := -fPIC

envoyd: envoyd.o dbus.o gpg-protocol.o agents.o socket.o util.o
envoy: envoy.o gpg-protocol.o agents.o socket.o util.o
envoy-exec: envoy-exec.o gpg-protocol.o agents.o socket.o util.o
pam_envoy.so: pam_envoy.o gpg-protocol.o agents.o socket.o util.o
	$(LINK.o) -shared $^ $(LOADLIBES) $(LDLIBS) -o $@

install: envoyd envoy pam_envoy.so
	install -Dm755 envoyd $(DESTDIR)/usr/bin/envoyd
	install -Dm755 envoy $(DESTDIR)/usr/bin/envoy
	install -Dm755 envoy-exec $(DESTDIR)/usr/bin/envoy-exec
	install -Dm755 pam_envoy.so $(DESTDIR)/$(LIBDIR)/security/pam_envoy.so
	install -Dm644 man/envoyd.1 $(DESTDIR)/usr/share/man/man1/envoyd.1
	install -Dm644 man/envoy.1 $(DESTDIR)/usr/share/man/man1/envoy.1
	install -Dm644 man/envoy-exec.1 $(DESTDIR)/usr/share/man/man1/envoy-exec.1
	install -Dm644 units/envoy@.service $(DESTDIR)/usr/lib/systemd/system/envoy@.service
	install -Dm644 units/envoy@.socket $(DESTDIR)/usr/lib/systemd/system/envoy@.socket
	install -Dm644 units/envoy@.service $(DESTDIR)/usr/lib/systemd/user/envoy@.service
	install -Dm644 units/envoy@.socket $(DESTDIR)/usr/lib/systemd/user/envoy@.socket
	install -Dm644 zsh-completion $(DESTDIR)/usr/share/zsh/site-functions/_envoy

clean:
	$(RM) envoyd envoy envoy-exec pam_envoy.so *.o gpg-protocol.c

.PHONY: all clean install
