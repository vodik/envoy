VERSION = $(shell git describe --tags)

CFLAGS := -std=c99 \
	-Wall -Wextra -pedantic \
	-DENVOY_VERSION=\"${VERSION}\" \
	${CFLAGS}

LDLIBS = -lsystemd-daemon

all: envoyd envoy
envoyd: envoyd.o
envoy: envoy.o

install: envoyd envoy
	install -Dm755 envoyd ${DESTDIR}/usr/bin/envoyd
	install -Dm755 envoy ${DESTDIR}/usr/bin/envoy
	install -Dm644 envoy@.service ${DESTDIR}/usr/lib/systemd/system/envoy@.service
	install -Dm644 envoy@.socket ${DESTDIR}/usr/lib/systemd/system/envoy@.socket

clean:
	${RM} envoyd envoy *.o

.PHONY: clean install uninstall
