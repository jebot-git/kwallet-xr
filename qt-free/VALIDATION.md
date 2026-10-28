# Native backend validation — 2026-10-28

Validated on Nobara/Fedora 44, x86-64. All wallets, passwords, keys, buses and
displays used by tests are disposable; live user wallets were not opened.

- Optimized Release configuration succeeds before any ECM/Qt/KDE discovery.
- Four CTest groups pass: encrypted file core, transitive dependency check,
  private-bus service integration, and actual FLTK credential windows on Xvfb.
- KWallet introspection method names/input/output signatures match the original
  public XML, including overloads. Password/map/binary/Unicode operations,
  caller-bound handles and cancellation are exercised.
- Original-format Secret Service metadata is exercised for attributes, MIME,
  timestamps and schema. Updating a password through Secret Service keeps its
  KWallet password entry type. Plain/encrypted sessions, independently computed
  DH/HKDF/AES transport, locking, prompt dismissal, portal Unix FD delivery and
  sender restrictions pass.
- PAM's existing inherited hash-pipe/environment-socket protocol unlocks a
  disposable wallet. Core tests also create a password-readable new wallet from
  a PAM-prepared salt/hash and retain a pre-existing salt during normal creation.
- Existing safe user-owned 0755 storage directories become 0700. Restart
  persistence and private 0600 wallet files are checked.
- A separately compiled original Qt/KDE storage backend creates a modern wallet
  containing password/map/binary/Unicode entries. Native reads and updates it;
  the original backend reads the result. OpenPGP wallets also pass native →
  original Qt → native → original Qt using a disposable GnuPG key/home.
  `tests/original-backend.py` repeats these checks with the independently built
  `tests/qt-oracle.cpp` comparator and native interop/GPG test executables.
- The staged native binary's full `ldd` graph contains no Qt or KF libraries.
  Native RPM auto-requires contain no Qt/KF dependencies. An offline RPM upgrade
  dependency test passes against the installed system.
- DomeD's standalone backend-selector tests pass (six cases). A full compositor
  rebuild is not part of this backend validation; the replacement RPM retains
  the existing daemon paths, including the path compiled into PAM.

Address/undefined sanitizer execution was unavailable: the host compiler's
linker references missing libasan/libubsan runtime files. This is not counted
as a passing check. Historical wallet revisions, all client-policy nuances,
GPG smartcards and external Secret Service migration are not fully certified.
See README.md for the explicit compatibility limits and Qt client ABI boundary.

Installation is a package upgrade with a rollback RPM. It does not restart the
running wallet providers, compositor or display manager. The new backend starts
at the next normal session login. Existing Qt applications retain their own
client libraries; backend Qt removal does not remove their dependencies.
