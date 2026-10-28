#!/usr/bin/env python3
"""Compare disposable wallets with a separately compiled original Qt backend."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

if len(sys.argv) != 4:
    sys.exit('Usage: original-backend.py QT_ORACLE NATIVE_INTEROP NATIVE_GPG')
oracle, interop, gpg_test = [str(Path(p).resolve()) for p in sys.argv[1:]]
with tempfile.TemporaryDirectory(prefix='dome-wallet-original-') as tmp:
    root = Path(tmp)
    for name in ['home', 'data', 'config', 'gnupg']:
        (root / name).mkdir(mode=0o700)
    env = dict(os.environ, HOME=str(root/'home'), XDG_DATA_HOME=str(root/'data'),
               XDG_CONFIG_HOME=str(root/'config'), GNUPGHOME=str(root/'gnupg'))
    def run(*args, **kwargs):
        return subprocess.run(args, env=env, check=True, **kwargs)
    wallet = str(root/'data/kwalletd/interop.kwl')
    run(oracle, 'create', env['XDG_DATA_HOME'])
    run(interop, wallet)
    run(oracle, 'check', env['XDG_DATA_HOME'])
    print('PASS original Qt -> native -> original Qt: password/map/binary/Unicode', flush=True)
    for path in (root/'data/kwalletd').iterdir():
        path.unlink()
    try:
        run('gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
            '--quick-generate-key', 'Disposable Wallet Interop <wallet-test@example.invalid>',
            'future-default', 'default', '0', stdout=subprocess.DEVNULL)
        result = run('gpg', '--batch', '--with-colons', '--list-secret-keys', capture_output=True, text=True)
        fingerprint = next(line.split(':')[9] for line in result.stdout.splitlines() if line.startswith('fpr:'))
        run(gpg_test, 'create', wallet, fingerprint)
        run(oracle, 'check-update', env['XDG_DATA_HOME'])
        run(gpg_test, 'check', wallet)
        run(oracle, 'check', env['XDG_DATA_HOME'])
        print('PASS native -> original Qt -> native -> original Qt: OpenPGP wallet', flush=True)
    finally:
        subprocess.run(['gpgconf', '--kill', 'gpg-agent'], env=env, check=False)
