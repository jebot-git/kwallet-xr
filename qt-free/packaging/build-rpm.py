#!/usr/bin/env python3
"""Package an already built /usr Release stage without building as root."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('stage', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
if os.geteuid() == 0:
    parser.error('Build and package as the regular user')
stage, output = args.stage.resolve(), args.output.resolve()
binary = stage / 'usr/libexec/domed/dome-walletd'
if not binary.is_file() or (stage / 'usr/local').exists():
    parser.error('Expected a staged native Release build with CMAKE_INSTALL_PREFIX=/usr')
subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / 'tests/dependencies.py'), str(binary)], check=True)
for directory in ['BUILD', 'BUILDROOT', 'SOURCES', 'SPECS', 'RPMS', 'SRPMS']:
    (output / directory).mkdir(parents=True, exist_ok=True)
with tarfile.open(output / 'SOURCES/native-payload.tar.gz', 'w:gz') as archive:
    archive.add(stage / 'usr', arcname='usr')
spec = output / 'SPECS/domed-kwallet-backend.spec'
shutil.copy2(Path(__file__).with_name(spec.name), spec)
subprocess.run(['rpmbuild', '-bb', '--define', f'_topdir {output}', str(spec)], check=True)
