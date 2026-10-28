#!/usr/bin/python3
"""Test-only Assuan peer; refuses operation outside an explicit private /tmp fixture."""
import json,os,stat,sys,time
from pathlib import Path
root=Path(os.environ['DOME_WALLET_TEST_ROOT'])
assert str(root).startswith('/tmp/dome-wallet-')
s=root.stat();assert s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700
print('OK fixture',flush=True)
for line in sys.stdin:
 command=line.strip().split(' ',1)[0]
 if command in ['GETPIN','CONFIRM']:
  path=root/'prompt-queue.json'
  queue=json.loads(path.read_text());assert queue and queue[0]['command']==command
  response=queue.pop(0);path.write_text(json.dumps(queue));path.chmod(0o600)
  if response.get('wait'):
   (root/'prompt-active').touch();time.sleep(60)
  if response.get('cancel'):print('ERR 83886179 Operation cancelled',flush=True)
  else:
   if command=='GETPIN':
    value=response['value'].encode();encoded=''.join(chr(b) if 32<=b<127 and b!=37 else '%%%02X'%b for b in value)
    print('D '+encoded,flush=True)
   print('OK',flush=True)
 elif command=='BYE':break
 else:print('OK',flush=True)
