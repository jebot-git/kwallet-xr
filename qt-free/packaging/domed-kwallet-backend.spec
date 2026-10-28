# SPDX-License-Identifier: LGPL-2.0-or-later
# Package a previously staged, verified Release build with /usr prefix.
%global debug_package %{nil}
%global __os_install_post %{nil}
Name: domed-kwallet-backend
Version: 6.30.0
Release: 2.dome
Summary: Qt-free KWallet and Secret Service backend with DomeD FLTK prompts
License: LGPL-2.0-or-later AND LGPL-2.0-only AND BSD-3-Clause AND CC0-1.0
URL: https://github.com/jebot-git/kwallet-xr
Source0: native-payload.tar.gz
Requires: domed-session-services >= 0.1.0
# Preserve the installed Fedora KF6 client library's conditional runtime provider.
# This is a D-Bus service replacement; no Qt C++ ABI is provided by the daemon.
Provides: kf6-kwallet = 6.30.0-1.fc44
Provides: kf6-kwallet%{?_isa} = 6.30.0-1.fc44
Obsoletes: kf6-kwallet <= 6.30.0-1.fc44

%description
Native KWallet-compatible D-Bus, Secret Service and Secret portal provider.
Existing encrypted KWallet files and the PAM hash-pipe handoff are preserved.
Credential dialogs use DomeD's installed native FLTK Pinentry. The backend
has no Qt or KDE library dependency. Qt applications retain their separate
client libraries. Package installation does not stop or restart any session
or wallet service, and does not access users' wallet contents.

%prep
%setup -q -c

%build
# The payload is built and verified as the regular user before packaging.

%install
mkdir -p %{buildroot}
cp -a usr %{buildroot}/

%files
%defattr(-,root,root,-)
/usr/bin/ksecretd
/usr/bin/kwalletd6
/usr/libexec/domed/dome-walletd
/usr/lib/systemd/user/dome-wallet.service
/usr/share/dbus-1/services/*.service
/usr/share/xdg-desktop-portal/portals/kwallet.portal
%doc /usr/share/doc/kwallet-dome
%license /usr/share/licenses/kwallet-dome

%changelog
* Wed Oct 28 2026 de-xr maintainers <noreply@example.invalid> - 6.30.0-2.dome
- Replace Qt backend with native KWallet/Secret Service provider and FLTK prompts
- Retain existing daemon launch paths and encrypted wallet format
