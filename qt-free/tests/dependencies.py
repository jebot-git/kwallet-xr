#!/usr/bin/env python3
"""Audit actual transitive runtime dependencies, including transitive shared libraries."""
import re,subprocess,sys
from pathlib import Path
binary=Path(sys.argv[1]).resolve()
result=subprocess.run(['ldd',str(binary)],capture_output=True,text=True,check=True)
assert 'not found' not in result.stdout,result.stdout
assert not re.search(r'lib(?:Qt[456]|KF[456])',result.stdout),result.stdout
assert 'libgcrypt' in result.stdout and 'libgio-2.0' in result.stdout,result.stdout
print('PASS Qt/KDE-free transitive runtime dependencies')
