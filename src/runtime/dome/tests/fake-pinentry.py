#!/usr/bin/python3
"""Disposable Assuan fixture. Never used by the installed daemon."""
import os,sys,time
mode=os.environ.get('DOME_PROMPT_TEST','success')
if mode=='early-exit':sys.exit(1)
print('OK fixture',flush=True)
for line in sys.stdin:
 if path:=os.environ.get('DOME_PROMPT_TEST_LOG'):
  with open(path,'a') as f:f.write(line)
 cmd=line.strip()
 if cmd in ('GETPIN','CONFIRM','MESSAGE'):
  if mode=='hang':time.sleep(20)
  elif mode=='cancel':print('ERR 83886179 cancelled',flush=True)
  elif mode=='other':print('ERR 83886194 not confirmed',flush=True)
  elif cmd=='GETPIN':
   if mode=='empty':print('OK',flush=True)
   elif mode=='malformed':print('D wrong%QZ\nOK',flush=True)
   elif mode=='nul':print('D wrong%00value\nOK',flush=True)
   elif mode=='oversized':print('D '+('x'*20000)+'\nOK',flush=True)
   elif mode=='data-error':print('D discard-me\nERR 83886179 cancelled',flush=True)
   else:
    sys.stdout.write('D fake%25');sys.stdout.flush();time.sleep(.01)
    print('pin%0Aline\nOK',flush=True)
  else:print('OK',flush=True)
 else:print('OK',flush=True)
