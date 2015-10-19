%global commit      1497c9bef81f8b0cafdac518225252380061c2e6
%global shortcommit %(c=%{commit}; echo ${c:0:7})

%global repo        https://github.com/vodik/envoy/archive/%{commit}

Name:		envoy
Version:	0.GIT.%{shortcommit}
Release:	1%{?dist}
Summary:	A ssh/gpg-agent wrapper using cgroups and systemd.socket

License:	GPL
URL:		https://github.com/vodik/envoy
Source0:        %{repo}/envoy-%{version}.tar.gz

BuildRequires:	dbus-devel
BuildRequires:	make
BuildRequires:	pam-devel
BuildRequires:	ragel
BuildRequires:	systemd
BuildRequires:	systemd-devel

Requires:	dbus
Requires:	dbus-libs
Requires:	pam
Requires:	systemd-libs
Requires:	pkgconfig

%description
Envoy helps you to manage ssh keys in similar fashion to keychain, but done in C, takes advantage of cgroups and systemd.

%prep
%setup -q -n envoy-%{commit}


%build
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install


%files
%{_bindir}/envoyd
%{_bindir}/envoy
%{_bindir}/envoy-exec
%{_libdir}/security/pam_envoy.so
%{_unitdir}/envoy@.service
%{_unitdir}/envoy@.socket
%{_unitdir}/../user/envoy@.service
%{_unitdir}/../user/envoy@.socket
%{_datadir}/zsh/site-functions/_envoy
%doc
%{_mandir}/man1/envoyd.1.gz
%{_mandir}/man1/envoy.1.gz
%{_mandir}/man1/envoy-exec.1.gz



%changelog
* Mon Oct 19 2015 Santiago Saavedra
- Initial specfile
