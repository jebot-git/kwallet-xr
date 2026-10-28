# Dome Wallet native backend

This fork's default build supplies `dome-walletd`, a Qt-free KWallet/Secret
Service backend for DomeD. It uses GLib/GIO for D-Bus, the existing KDE
Blowfish/CBC/SHA implementation and libgcrypt for compatible wallet storage,
GPGME for OpenPGP wallets, and DomeD's fixed native FLTK Pinentry executable for
credential/confirmation dialogs. No Qt or KDE library is discovered or linked
by the native build. `DOME_QT_FREE=OFF` explicitly selects the earlier Qt-based
implementation, including the retained FLTK prompt adapter.

## Compatibility target

The backend keeps `org.kde.KWallet` at `/modules/kwalletd6`, including overloaded
methods, asynchronous open, folder/password/map/binary operations, lifecycle
methods and the `org.kde.kwalletcompat` password-change endpoint. It also hosts
Secret Service collections/items/prompts/sessions and the existing `kwallet`
Secret portal. Plain sessions and `dh-ietf1024-sha256-aes128-cbc-pkcs7` sessions
are supported; transport keys/handles/prompts are bound to the calling bus
connection. Portal application secrets are delivered over the supplied Unix FD,
and only the actual desktop portal bus owner may request them.

Existing `.kwl`, `.salt` and `_attributes.json` storage is retained. Passwords
remain encrypted at rest; there is no automatic export/migration to a new store.
The native codec implements the required big-endian Qt data-stream format,
UTF-16 strings and byte arrays without linking Qt. Existing password, map and
binary entries remain readable. The legacy cipher/hash readers and modern
PBKDF2-SHA512/CBC writer retain upstream algorithms; legacy hash-based wallets
are saved with that hash until an explicit password change. OpenPGP file
read/write uses GPGME and the existing key identity inside the encrypted file.
New wallets created through the current native UI use password encryption;
OpenPGP creation is available through the core API but the old graphical key
selection wizard has not been ported to the native daemon.

This preserves the **D-Bus API**, not the Qt C++ client ABI: existing Qt apps can
keep using their installed KF6Wallet client library in their own process. The
native default does not rebuild that library. The old external-Secret-Service
migration/bridge modes are not implemented by this self-contained provider;
use the explicit legacy build for those modes. Existing saved application
allow-lists are not automatically imported: the native backend asks for approval
when another bus caller first accesses an already unlocked wallet. This is a
stricter authorization policy rather than an implicit grant to every client.

## Build and stage

Build dependencies: CMake 3.25+, C++20, pkg-config, GLib/GIO development files,
libgcrypt, GPGME and nlohmann-json. The root fork currently requires CMake 3.29+;
`cmake -S qt-free` also works independently with 3.25+. The FLTK helper is an
existing DomeD session component, not a Qt dependency of this backend.

```sh
cmake -S . -B build/native-release -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_TESTING=OFF
cmake --build build/native-release --parallel
DESTDIR="$PWD/build/stage" cmake --install build/native-release
python3 qt-free/tests/dependencies.py build/native-release/qt-free/dome-walletd
```

`DOME_NATIVE_PINENTRY` is an absolute, fixed build-time path, defaulting to
`/usr/local/libexec/domed/pinentry-fltk`. Secrets pass through private child
pipes, never command arguments, environment variables, plaintext temporary
files or public password-delivery methods. The helper path has no runtime
environment override. Cancellation/helper failure never becomes an empty
password success. Prompt size/deadline limits, private atomic wallet writes,
input bounds, ownership/symlink checks, process core-dump suppression and wiping
allocators protect the native path.

The stage includes activation files for the existing bus names, compatibility
executables and a user service. Installing activation files does not replace a
currently running provider. The daemon refuses to take over a name already
owned by another wallet/Secret Service provider. Run it as the desktop user,
never as root. A `--storage-dir` override permits isolated test stores; the
normal location is `$XDG_DATA_HOME/kwalletd` (the usual XDG fallback applies).

The existing PAM protocol `--pam-login HASH_FD ENV_FD` is supported. The hash
travels through its inherited pipe and the environment handoff verifies its
Unix peer UID. A PAM-unlocked wallet still requires approval for a new caller.
A distributor's PAM module may have a compiled-in daemon path: deploying the
new activation files alone does not change it. The matching PAM launch path
must be configured when replacing an installed package. No host PAM setup or
live wallet provider has been changed during this implementation.

An existing user-owned 0755 wallet directory is tightened to 0700 before data
is loaded; directories writable by other users and symlinks are rejected.

DomeD's startup selector prefers this executable when installed. Set
`DOME_WALLET_BACKEND=native` to require it with no Qt fallback; `auto` retains the
previous KWallet service only when the native backend is absent. An already
owned Secret Service is preserved in either case.

## Verification

Tests use an isolated HOME, session bus, storage and GnuPG home. Raw/generated
wallets and keys stay in ignored build directories or temporary directories.

```sh
uv venv build/test-venv
uv pip install --python build/test-venv/bin/python -r qt-free/tests/requirements.txt
cmake -S . -B build/native-tests -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DDOME_TEST_PYTHON="$PWD/build/test-venv/bin/python" -DDOME_NATIVE_GUI_TESTS=ON
cmake --build build/native-tests --parallel
ctest --test-dir build/native-tests --output-on-failure
```

Four test groups cover the file core, actual transitive dependency graph,
private-bus API/protocol behavior and real FLTK prompts on a private Xvfb.
The API test includes wrong/cancelled passwords, password change, maps/binary
entries, spoofed callers/handles, independent DH/HKDF/AES verification,
collection/item lifecycle, prompt dismissal while a credential helper is active,
locked-error behavior, invalid signatures, portal
FD/caller checks, restart persistence and the PAM pre-hashed handoff.

`tests/qt-oracle.cpp` is a **test-only** comparator against the pre-existing
Qt/KDE backend; it is deliberately not built or linked by the native target.
Local bidirectional tests passed for modern encrypted wallets with Unicode,
password/map/binary entries and for OpenPGP wallets. They do not assert complete
compatibility with every historical wallet revision, GPG agent/card setup or
application policy. Live installation remains a separate deployment step.

The upstream source and license notices are retained. The native
serialization derives from `src/runtime/kwalletbackend` with the original
cipher implementations reused, not a new encryption format.

## Fedora/Nobara replacement package

The packaging helper accepts an already staged Release build with `/usr` prefix:

```sh
cmake -S . -B build/native-package -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBEXECDIR=libexec -DBUILD_TESTING=OFF
cmake --build build/native-package --parallel
DESTDIR="$PWD/build/package-stage" cmake --install build/native-package
python3 qt-free/packaging/build-rpm.py build/package-stage build/rpm
```

The `domed-kwallet-backend` RPM upgrades the earlier FLTK prompt adapter package.
It preserves `/usr/bin/ksecretd` and `/usr/bin/kwalletd6` as wrappers, so PAM's
compiled-in path and existing DomeD launchers select the native daemon without
editing authentication policy or rebuilding the compositor. It retains the
Fedora 6.30.0 runtime-provider capability needed by existing client libraries;
those libraries are independent of this daemon. The old Qt `kwallet-query`
executable and private Qt backend library are no longer part of the native
package. Keep the previous RPM for rollback. No wallet files are packaged.

The package has no stop/restart scriptlets. After installation, reload user
systemd's unit definitions without restarting providers. Existing processes
continue until a normal logout/login; that next session starts the native
backend. Do not run the old and new backends against the same wallet store.

See [VALIDATION.md](VALIDATION.md) for the tested compatibility scope and limits.
