#!/usr/bin/python3
import hashlib,json,os,subprocess,sys,tempfile,time
binary=sys.argv[1]
for mode in ['success','empty','cancel','malformed','nul','oversized','data-error','early-exit','hang']:
 with tempfile.NamedTemporaryFile() as transcript:
  started=time.monotonic()
  result=subprocess.run([binary],env={**os.environ,'DOME_PROMPT_TEST':mode,'DOME_PROMPT_TEST_LOG':transcript.name},capture_output=True,text=True,check=True,timeout=4)
  out=json.loads(result.stdout)
  expected=b'fake%pin\nline' if mode=='success' else b''
  assert out['accepted']==(mode in ['success','empty']),(mode,out)
  assert out['size']==len(expected) and out['hash']==hashlib.sha256(expected).hexdigest(),(mode,out)
  assert time.monotonic()-started<4
  if mode=='success':
   transcript.seek(0);lines=transcript.read().decode().splitlines()
   assert 'SETDESC A&B%25%0Aline%0AGETPIN' in lines,lines
   assert lines.count('GETPIN')==1,lines
  print('PASS',mode,flush=True)
for mode,expected in [('success',0),('other',1),('cancel',2)]:
 out=json.loads(subprocess.check_output([binary,'confirm'],env={**os.environ,'DOME_PROMPT_TEST':mode},text=True))
 assert out['choice']==expected,out
 print('PASS confirmation',mode,flush=True)
