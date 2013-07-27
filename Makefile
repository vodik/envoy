VERSION = $(shell git describe --tags)

CFLAGS := -std=c99 \
	-Wall -Wextra -pedantic \
	-D_GNU_SOURCE \
	-DENVOY_VERSION=\"${VERSION}\" \
	${CFLAGS}

LDLIBS = -lsystemd-daemon

all: envoyd envoy envoy-exec pam_envoy.so

lib/envoy.o: lib/envoy.c
pam_envoy.o: pam_envoy.c
envoyd: envoyd.o lib/envoy.o clique/cgroups.o
envoy: envoy.o lib/envoy.o lib/gpg-protocol.o
envoy-exec: envoy-exec.o lib/envoy.o lib/gpg-protocol.o

lib/gpg-protocol.c: lib/gpg-protocol.rl
	ragel -C $< -o $@

lib/gpg-protocol.o: lib/gpg-protocol.c
	${CC} ${CFLAGS} -fPIC -o $@ -c $<

lib/envoy.o pam_envoy.o:
	${CC} ${CFLAGS} -fPIC -o $@ -c $<

pam_envoy.so: pam_envoy.o lib/envoy.o lib/gpg-protocol.o
	${CC} ${LDFLAGS} -shared -DPIC -o $@ $?

install: envoyd envoy pam_envoy.so
	install -Dm755 envoyd ${DESTDIR}/usr/bin/envoyd
	install -Dm755 envoy ${DESTDIR}/usr/bin/envoy
	install -Dm755 envoy-exec ${DESTDIR}/usr/bin/envoy-exec
	install -Dm755 pam_envoy.so ${DESTDIR}/usr/lib/security/pam_envoy.so
	install -Dm644 man/envoyd.1 ${DESTDIR}/usr/share/man/man1/envoyd.1
	install -Dm644 man/envoy.1 ${DESTDIR}/usr/share/man/man1/envoy.1
	install -Dm644 man/envoy-exec.1 ${DESTDIR}/usr/share/man/man1/envoy-exec.1
	install -Dm644 systemd/envoy.service ${DESTDIR}/usr/lib/systemd/system/envoy.service
	install -Dm644 systemd/envoy.socket ${DESTDIR}/usr/lib/systemd/system/envoy.socket

clean:
	${RM} envoyd envoy pam_envoy.so *.o

.PHONY: all clean install uninstall
