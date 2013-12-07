VERSION=v6
GIT_DESC=$(shell test -d .git && git describe 2>/dev/null)

ifneq "$(GIT_DESC)" ""
VERSION=$(GIT_DESC)
endif

CFLAGS := -std=c11 \
	-Wall -Wextra -pedantic \
	-Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes \
	-D_GNU_SOURCE \
	-DENVOY_VERSION=\"${VERSION}\" \
	-I/usr/include/dbus-1.0 -I/usr/lib/dbus-1.0/include \
	${CFLAGS}

LDLIBS = -lsystemd-daemon -ldbus-1

all: envoyd envoy envoy-exec pam_envoy.so

envoyd: envoyd.o agents.o socket.o util.o \
	clique/systemd-scope.o clique/systemd-unit.o \
	clique/dbus/dbus-shim.o clique/dbus/dbus-util.o
envoy: envoy.o agents.o socket.o gpg-protocol.o util.o
envoy-exec: envoy-exec.o agents.o socket.o gpg-protocol.o util.o

gpg-protocol.c: gpg-protocol.rl
	ragel -F0 -C $< -o $@

gpg-protocol.o: gpg-protocol.c
	${CC} ${CFLAGS} -fPIC -o $@ -c $<

agents.o: agents.c
	${CC} ${CFLAGS} -fPIC -o $@ -c $<
socket.o: socket.c
	${CC} ${CFLAGS} -fPIC -o $@ -c $<
pam_envoy.o: pam_envoy.c
	${CC} ${CFLAGS} -fPIC -o $@ -c $<

pam_envoy.so: pam_envoy.o agents.o socket.o gpg-protocol.o
	${CC} ${LDFLAGS} -shared -DPIC -o $@ $?

install: envoyd envoy pam_envoy.so
	install -Dm755 envoyd ${DESTDIR}/usr/bin/envoyd
	install -Dm755 envoy ${DESTDIR}/usr/bin/envoy
	install -Dm755 envoy-exec ${DESTDIR}/usr/bin/envoy-exec
	install -Dm755 pam_envoy.so ${DESTDIR}/usr/lib/security/pam_envoy.so
	install -Dm644 man/envoyd.1 ${DESTDIR}/usr/share/man/man1/envoyd.1
	install -Dm644 man/envoy.1 ${DESTDIR}/usr/share/man/man1/envoy.1
	install -Dm644 man/envoy-exec.1 ${DESTDIR}/usr/share/man/man1/envoy-exec.1
	install -Dm644 units/envoy@.service ${DESTDIR}/usr/lib/systemd/system/envoy@.service
	install -Dm644 units/envoy@.socket ${DESTDIR}/usr/lib/systemd/system/envoy@.socket
	install -Dm644 zsh-completion ${DESTDIR}/usr/share/zsh/site-functions/_envoy

clean:
	${RM} envoyd envoy envoy-exec pam_envoy.so *.o

.PHONY: all clean install uninstall
