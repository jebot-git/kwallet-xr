#!/usr/bin/env python3
"""Actual FLTK helper on a private Xvfb/bus with disposable encrypted storage."""
import asyncio,os,subprocess,sys,tempfile,time
from pathlib import Path
from Xlib import X,XK,display,error
from Xlib.ext import xtest
from dbus_next import Message,MessageType
from dbus_next.aio import MessageBus
binary=Path(sys.argv[1]).resolve()
async def main():
 with tempfile.TemporaryDirectory(prefix='dome-wallet-fltk-') as tmp:
  root=Path(tmp);children=[];bus=None;d=None
  for name in ['home','config','data','runtime','wallets']:(root/name).mkdir(mode=0o700)
  env=dict(os.environ,HOME=str(root/'home'),XDG_CONFIG_HOME=str(root/'config'),XDG_DATA_HOME=str(root/'data'),XDG_RUNTIME_DIR=str(root/'runtime'),FLTK_BACKEND='x11')
  for key in ['WAYLAND_DISPLAY','WAYLAND_SOCKET']:env.pop(key,None)
  log=(root/'native.log').open('w')
  try:
   rd,wr=os.pipe();xv=subprocess.Popen(['Xvfb','-displayfd',str(wr),'-screen','0','1280x900x24','-nolisten','tcp'],pass_fds=(wr,),stdout=log,stderr=log);children.append(xv);os.close(wr)
   with os.fdopen(rd) as pipe:env['DISPLAY']=':'+pipe.readline().strip()
   d=display.Display(env['DISPLAY'])
   server=subprocess.Popen(['dbus-daemon','--session','--nofork','--print-address=1'],env=env,stdout=subprocess.PIPE,stderr=log,text=True);children.append(server);env['DBUS_SESSION_BUS_ADDRESS']=server.stdout.readline().strip()
   bus=await MessageBus(bus_address=env['DBUS_SESSION_BUS_ADDRESS']).connect()
   daemon=subprocess.Popen([str(binary),'--storage-dir',str(root/'wallets')],env=env,stdout=log,stderr=log);children.append(daemon)
   async def call(member,sig='',body=()):
    reply=await asyncio.wait_for(bus.call(Message(destination='org.kde.kwalletd6',path='/modules/kwalletd6',interface='org.kde.KWallet',member=member,signature=sig,body=list(body))),20)
    assert reply.message_type!=MessageType.ERROR,(member,reply.error_name,reply.body);return reply.body
   for _ in range(100):
    reply=await bus.call(Message(destination='org.freedesktop.DBus',path='/org/freedesktop/DBus',interface='org.freedesktop.DBus',member='NameHasOwner',signature='s',body=['org.kde.kwalletd6']))
    if reply.body[0]:break
    assert daemon.poll() is None;await asyncio.sleep(.03)
   def windows():
    found=[]
    for w in d.screen().root.query_tree().children:
     try:
      if w.get_attributes().map_state!=X.IsViewable:continue
      cls=str(w.get_wm_class()).lower()
      assert 'kwalletd' not in cls and 'ksecretd' not in cls,cls
      if 'pinentry' in cls:found.append(w)
     except error.BadWindow:pass
    return found
   def key(name):
    code=d.keysym_to_keycode(XK.string_to_keysym(name));xtest.fake_input(d,X.KeyPress,code);xtest.fake_input(d,X.KeyRelease,code);d.sync()
   async def answer(actions):
    previous=None
    for action in actions:
     deadline=time.monotonic()+12
     while time.monotonic()<deadline:
      found=windows()
      if found:
       w=found[0];pid=w.get_full_property(d.intern_atom('_NET_WM_PID'),X.AnyPropertyType);token=(w.id,tuple(pid.value) if pid else None)
       if token!=previous:previous=token;break
      await asyncio.sleep(.03)
     else:raise AssertionError('Missing FLTK dialog for '+action)
     w.set_input_focus(X.RevertToParent,X.CurrentTime);d.sync();await asyncio.sleep(.12)
     if action=='confirm':
      g=w.get_geometry();xtest.fake_input(d,X.MotionNotify,x=g.x+g.width-45,y=g.y+g.height-22);xtest.fake_input(d,X.ButtonPress,1);xtest.fake_input(d,X.ButtonRelease,1);d.sync()
     elif action=='cancel':key('Escape')
     else:
      for char in action:key(char);await asyncio.sleep(.01)
      key('Return')
     await asyncio.sleep(.12)
   async def prompted(operation,actions):return (await asyncio.gather(operation,answer(actions)))[0]
   h=(await prompted(call('open','sxs',['fixture',0,'FLTK fixture']),['confirm','dome123','dome123']))[0];assert h>0
   assert (await call('createFolder','iss',[h,'Passwords','FLTK fixture']))==[True]
   assert (await call('writePassword','issss',[h,'Passwords','test','disposable-value','FLTK fixture']))==[0]
   await call('close','sb',['fixture',True]);h=(await prompted(call('open','sxs',['fixture',0,'FLTK fixture']),['cancel']))[0];assert h<0
   h=(await prompted(call('open','sxs',['fixture',0,'FLTK fixture']),['wrong','dome123']))[0];assert h>0
   await prompted(call('changePassword','sxs',['fixture',0,'FLTK fixture']),['dome456','dome456'])
   await call('close','sb',['fixture',True]);h=(await prompted(call('open','sxs',['fixture',0,'FLTK fixture']),['dome456']))[0];assert h>0
   assert (await call('readPassword','isss',[h,'Passwords','test','FLTK fixture']))==['disposable-value']
   print('PASS actual FLTK create/repeat, cancellation, wrong-password retry, password-change/reopen and no Qt windows',flush=True)
  except BaseException:
   log.flush();print((root/'native.log').read_text(),file=sys.stderr);raise
  finally:
   if bus:bus.disconnect()
   if d:d.close();d=None
   for child in reversed(children):
    if child.poll() is None:child.terminate()
    try:child.wait(timeout=4)
    except subprocess.TimeoutExpired:child.kill();child.wait()
   if d:d.close()
   log.close()
asyncio.run(main())
