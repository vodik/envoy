RAGEL = ragel
RAGEL_FLAGS := -F0

COMPILE.rl = $(RAGEL) $(RAGEL_FLAGS)
COMPILE.c = $(CC) $(CFLAGS) $(EXTRA_FLAGS) -c

%.c: %.rl
	$(COMPILE.rl) -C $(OUTPUT_OPTION) $<

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

VPATH = src
LIBDIR := $(shell pkg-config --variable=libdir libsystemd)
ENVOYLIBS = gpg-protocol.o agents.o socket.o util.o

all: envoyd envoy envoy-exec pam_envoy.so

gpg-protocol.o: $(VPATH)/gpg-protocol.c
$(ENVOYLIBS) pam_envoy.o: EXTRA_FLAGS := -fPIC

envoyd: envoyd.o dbus.o $(ENVOYLIBS)
envoy: envoy.o $(ENVOYLIBS)
envoy-exec: envoy-exec.o $(ENVOYLIBS)
pam_envoy.so: pam_envoy.o $(ENVOYLIBS)
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
	$(RM) envoyd envoy envoy-exec pam_envoy.so *.o src/gpg-protocol.c

.PHONY: all clean install
