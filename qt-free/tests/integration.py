#!/usr/bin/env python3
"""Private bus/HOME/disposable encrypted wallets; never activates a host provider."""
import asyncio,hashlib,json,os,secrets,stat,struct,subprocess,sys,tempfile,socket
from pathlib import Path
from dbus_next import Message,MessageType,Variant
from dbus_next.aio import MessageBus
from cryptography.hazmat.primitives import hashes,padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
BINARY=Path(sys.argv[1]).resolve()
PRIME=int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF',16)
ROOT='/org/freedesktop/secrets';S='org.freedesktop.secrets';SI='org.freedesktop.Secret.Service';CI='org.freedesktop.Secret.Collection';II='org.freedesktop.Secret.Item';P='org.freedesktop.DBus.Properties'
def qs(s):
 b=s.encode('utf-16-be');return struct.pack('>I',len(b))+b
async def main():
 with tempfile.TemporaryDirectory(prefix='dome-wallet-integration-') as tmp:
  path=Path(tmp);os.chmod(path,0o700)
  for d in ['home','config','data','wallets','gpg']:(path/d).mkdir(mode=0o700)
  metadata={'$fdo_created':'100','Passwords/unicode':{'attributes':{'application':'legacy-fixture','xdg:schema':'org.kde.KWallet.Password'},'$fdo_created':'123','$fdo_modified':'456','$fdo_mime_type':'text/plain;charset=utf-8'}}
  (path/'wallets/fixture_attributes.json').write_text(json.dumps(metadata));(path/'wallets/fixture_attributes.json').chmod(0o600)
  (path/'wallets').chmod(0o755)  # Existing stock KWallet directory mode.
  (path/'config/kwalletrc').write_text('[Wallet]\nDefault Wallet=fixture\n')
  env=dict(os.environ,HOME=str(path/'home'),XDG_DATA_HOME=str(path/'data'),XDG_CONFIG_HOME=str(path/'config'),GNUPGHOME=str(path/'gpg'),DOME_WALLET_TEST_ROOT=tmp)
  busproc=subprocess.Popen(['dbus-daemon','--session','--nofork','--print-address=1'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
  address=busproc.stdout.readline().strip();assert address;env['DBUS_SESSION_BUS_ADDRESS']=address
  a=await MessageBus(bus_address=address,negotiate_unix_fd=True).connect();b=await MessageBus(bus_address=address).connect()
  daemon=None;log=(path/'daemon.log').open('w')
  def queue(*responses):
   p=path/'prompt-queue.json';p.write_text(json.dumps(list(responses)));p.chmod(0o600)
  def confirm(cancel=False):return {'command':'CONFIRM','cancel':cancel}
  def pin(value='',cancel=False):return {'command':'GETPIN','value':value,'cancel':cancel}
  async def rpc(member,signature='',body=(),dest=S,object=ROOT,interface=SI,bus=a,error=False,unix_fds=()):
   result=await asyncio.wait_for(bus.call(Message(destination=dest,path=object,interface=interface,member=member,signature=signature,body=list(body),unix_fds=list(unix_fds))),8)
   if error:
    assert result.message_type==MessageType.ERROR,(member,result.body);return result
   assert result.message_type!=MessageType.ERROR,(member,result.error_name,result.body)
   return result.body
  async def wallet(member,signature='',body=(),bus=a,error=False):return await rpc(member,signature,body,dest='org.kde.kwalletd6',object='/modules/kwalletd6',interface='org.kde.KWallet',bus=bus,error=error)
  async def launch():
   nonlocal daemon
   daemon=subprocess.Popen([str(BINARY),'--storage-dir',str(path/'wallets')],env=env,stdout=log,stderr=log)
   for _ in range(100):
    result=await rpc('NameHasOwner','s',[S],dest='org.freedesktop.DBus',object='/org/freedesktop/DBus',interface='org.freedesktop.DBus')
    if result[0]:
     pid=(await rpc('GetConnectionUnixProcessID','s',[S],dest='org.freedesktop.DBus',object='/org/freedesktop/DBus',interface='org.freedesktop.DBus'))[0];assert pid==daemon.pid
     return
    assert daemon.poll() is None,(daemon.returncode,(path/'daemon.log').read_text());await asyncio.sleep(.03)
   raise AssertionError('Daemon did not acquire private bus names')
  async def prompted(prompt_path,actions):
   queue(*actions);future=asyncio.get_running_loop().create_future()
   def signal(m):
    if m.message_type==MessageType.SIGNAL and m.path==prompt_path and m.interface=='org.freedesktop.Secret.Prompt' and m.member=='Completed' and not future.done():future.set_result(m.body)
   a.add_message_handler(signal)
   await rpc('AddMatch','s',["type='signal',interface='org.freedesktop.Secret.Prompt'"],dest='org.freedesktop.DBus',object='/org/freedesktop/DBus',interface='org.freedesktop.DBus')
   try:
    await rpc('Prompt','s',[''],object=prompt_path,interface='org.freedesktop.Secret.Prompt')
    result=await asyncio.wait_for(future,8);return result
   finally:a.remove_message_handler(signal)
  try:
   await launch();assert (await wallet('wallets'))==[[]]
   assert stat.S_IMODE((path/'wallets').stat().st_mode)==0o700
   import xml.etree.ElementTree as E
   actual=(await rpc('Introspect',dest='org.kde.kwalletd6',object='/modules/kwalletd6',interface='org.freedesktop.DBus.Introspectable'))[0]
   def api(node):
    return {(m.attrib['name'],''.join(a.attrib['type'] for a in m.findall('arg') if a.attrib.get('direction','in')=='in'),''.join(a.attrib['type'] for a in m.findall('arg') if a.attrib.get('direction')=='out')) for m in node.findall('.//interface[@name="org.kde.KWallet"]/method')}
   original=Path(__file__).resolve().parents[2]/'src/api/KWallet/org.kde.KWallet.xml'
   assert api(E.fromstring(actual))==api(E.parse(original).getroot())

   queue(confirm(True));assert (await wallet('open','sxs',['cancelled',0,'test-app']))[0]<0;assert not (path/'wallets/cancelled.kwl').exists()
   queue(confirm(),pin('test-password'));h=(await wallet('open','sxs',['fixture',0,'test-app']))[0];assert h>0
   assert (await wallet('createFolder','iss',[h,'Passwords','test-app']))==[True]
   assert (await wallet('writePassword','issss',[h,'Passwords','unicode','příliš 日本語 🔒','test-app']))==[0]
   assert (await wallet('readPassword','isss',[h,'Passwords','unicode','test-app']))==['příliš 日本語 🔒']
   assert (await wallet('readEntry','isss',[h,'Passwords','unicode','test-app']))==[qs('příliš 日本語 🔒')]
   mapdata=struct.pack('>I',2)+qs('username')+qs('uživatel')+qs('password')+qs('only-fixture')
   assert (await wallet('writeMap','issays',[h,'Passwords','form',mapdata,'test-app']))==[0]
   assert (await wallet('readMap','isss',[h,'Passwords','form','test-app']))==[mapdata]
   assert (await wallet('writeEntry','issayis',[h,'Passwords','bytes',b'\0\x01\xff',2,'test-app']))==[0]
   assert (await wallet('writeEntry','issays',[h,'Passwords','other',b'abc','test-app']))==[0]
   await wallet('readPassword','isss',[h,'Passwords','unicode','test-app'],bus=b,error=True)
   await wallet('readPassword','isss',[h,'Passwords','unicode','spoofed'],error=True)
   queue(confirm(True));assert (await wallet('open','sxs',['fixture',0,'test-app'],bus=b))[0]<0
   queue(confirm());hb=(await wallet('open','sxs',['fixture',0,'second-app'],bus=b))[0];assert hb>h
   assert (await wallet('readPassword','isss',[hb,'Passwords','unicode','second-app'],bus=b))==['příliš 日本語 🔒']
   assert (await wallet('renameEntry','issss',[h,'Passwords','other','renamed','test-app']))==[0]
   assert (await wallet('hasEntry','isss',[h,'Passwords','renamed','test-app']))==[True]
   assert (await wallet('entryType','isss',[h,'Passwords','renamed','test-app']))==[2]
   assert (await wallet('removeEntry','isss',[h,'Passwords','renamed','test-app']))==[0]
   assert set((await wallet('entriesList','iss',[h,'Passwords','test-app']))[0])=={'unicode','form','bytes'}
   assert set((await wallet('passwordList','iss',[h,'Passwords','test-app']))[0])=={'unicode'}
   print('PASS KWallet password/map/binary/overloaded APIs and caller/handle isolation',flush=True)
   await wallet('close','sb',['fixture',True]);before=hashlib.sha256((path/'wallets/fixture.kwl').read_bytes()).digest()
   queue(pin(cancel=True));assert (await wallet('open','sxs',['fixture',0,'test-app']))[0]<0
   assert hashlib.sha256((path/'wallets/fixture.kwl').read_bytes()).digest()==before
   queue(pin('wrong'),pin('test-password'));h=(await wallet('open','sxs',['fixture',0,'test-app']))[0];assert h>0
   queue(pin('replacement-password'));await wallet('changePassword','sxs',['fixture',0,'test-app'])
   await wallet('close','sb',['fixture',True]);queue(pin('test-password'),pin('replacement-password'));h=(await wallet('open','sxs',['fixture',0,'test-app']))[0];assert h>0
   assert (await wallet('readPassword','isss',[h,'Passwords','unicode','test-app']))==['příliš 日本語 🔒']
   print('PASS cancellation, wrong-password retry, password change and encrypted data retention',flush=True)
   session=(await rpc('OpenSession','sv',['plain',Variant('s','')]))[1]
   legacy=(await rpc('SearchItems','a{ss}',[{'application':'legacy-fixture'}]))[0];assert len(legacy)==1
   old=(await rpc('GetSecret','o',[session],object=legacy[0],interface=II))[0];assert old[2]=='příliš 日本語 🔒'.encode() and old[3]=='text/plain;charset=utf-8'
   assert (await rpc('Get','ss',[II,'Created'],object=legacy[0],interface=P))[0].value==123
   assert (await rpc('Get','ss',[II,'Modified'],object=legacy[0],interface=P))[0].value==456
   assert (await rpc('Get','ss',[II,'Type'],object=legacy[0],interface=P))[0].value=='org.kde.KWallet.Password'
   await rpc('SetSecret','(oayays)',[[session,b'','příliš 日本語 🔒'.encode(),'text/plain;charset=utf-8']],object=legacy[0],interface=II)
   assert (await wallet('entryType','isss',[h,'Passwords','unicode','test-app']))==[1]
   assert (await wallet('readPassword','isss',[h,'Passwords','unicode','test-app']))==['příliš 日本語 🔒']
   print('PASS original KWallet Secret Service attributes/MIME/timestamp/schema metadata and password-entry update',flush=True)
   collections=(await rpc('Get','ss',[SI,'Collections'],interface=P))[0].value;assert len(collections)==1;coll=collections[0]
   props={II+'.Label':Variant('s','test secret'),II+'.Attributes':Variant('a{ss}',{'application':'test','id':'1'})}
   sec=[session,b'',b'plain\0secret','application/octet-stream']
   created=await rpc('CreateItem','a{sv}(oayays)b',[props,sec,False],object=coll,interface=CI);entry=created[0];assert created[1]=='/'
   assert (await rpc('GetSecret','o',[session],object=entry,interface=II))[0][2]==b'plain\0secret'
   assert (await rpc('SearchItems','a{ss}',[{'application':'test'}]))==[[entry],[]]
   props=(await rpc('GetAll','s',[II],object=entry,interface=P))[0];assert props['Attributes'].value['id']=='1'
   private=secrets.randbits(256);client=pow(2,private,PRIME).to_bytes(128,'big')
   output,sid=await rpc('OpenSession','sv',['dh-ietf1024-sha256-aes128-cbc-pkcs7',Variant('ay',client)])
   public=int.from_bytes(output.value,'big');shared=pow(public,private,PRIME).to_bytes(128,'big');key=HKDF(algorithm=hashes.SHA256(),length=16,salt=None,info=b'').derive(shared)
   enc=(await rpc('GetSecret','o',[sid],object=entry,interface=II))[0]
   cipher=Cipher(algorithms.AES(key),modes.CBC(enc[1])).decryptor();padded=cipher.update(enc[2])+cipher.finalize();unpad=padding.PKCS7(128).unpadder();assert unpad.update(padded)+unpad.finalize()==b'plain\0secret'
   iv=os.urandom(16);pad=padding.PKCS7(128).padder();padded=pad.update(b'changed\0binary')+pad.finalize();cipher=Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor();encrypted=cipher.update(padded)+cipher.finalize()
   await rpc('SetSecret','(oayays)',[[sid,iv,encrypted,'application/octet-stream']],object=entry,interface=II)
   assert (await rpc('GetSecret','o',[session],object=entry,interface=II))[0][2]==b'changed\0binary'
   await rpc('GetSecret','o',[sid],object=entry,interface=II,bus=b,error=True)
   await rpc('OpenSession','sv',['dh-ietf1024-sha256-aes128-cbc-pkcs7',Variant('ay',b'\0')],error=True)
   await rpc('OpenSession','ss',['plain','wrong type'],error=True)
   await rpc('Get','s',['wrong signature'],interface=P,error=True)
   await rpc('SetSecret','(oayays)',[[sid,b'bad iv',encrypted,'application/octet-stream']],object=entry,interface=II,error=True)
   print('PASS plain/encrypted Secret Service sessions, independent DH/AES verification and session-owner isolation',flush=True)
   await rpc('Lock','ao',[[coll]]);locked_error=await rpc('GetSecret','o',[session],object=entry,interface=II,error=True);assert locked_error.error_name=='org.freedesktop.Secret.Error.IsLocked'
   assert (await rpc('Get','ss',[CI,'Locked'],object=coll,interface=P))[0].value
   assert (await rpc('SearchItems','a{ss}',[{'application':'test'}]))==[[],[entry]]
   unlocked,request=await rpc('Unlock','ao',[[coll]]);assert not unlocked and request!='/'
   await rpc('Prompt','s',[''],object=request,interface='org.freedesktop.Secret.Prompt',bus=b,error=True)
   result=await prompted(request,[pin(cancel=True)]);assert result[0]
   assert (await rpc('Get','ss',[CI,'Locked'],object=coll,interface=P))[0].value
   unlocked,waiting=await rpc('Unlock','ao',[[coll]]);queue({'command':'GETPIN','wait':True,'value':'unused'})
   future=asyncio.get_running_loop().create_future()
   def completed(m):
    if m.message_type==MessageType.SIGNAL and m.path==waiting and m.member=='Completed' and not future.done():future.set_result(m.body)
   a.add_message_handler(completed)
   try:
    await rpc('Prompt','s',[''],object=waiting,interface='org.freedesktop.Secret.Prompt')
    for _ in range(100):
     if (path/'prompt-active').exists():break
     await asyncio.sleep(.02)
    assert (path/'prompt-active').exists()
    assert (await rpc('Get','ss',[CI,'Locked'],object=coll,interface=P))[0].value
    await rpc('Dismiss',object=waiting,interface='org.freedesktop.Secret.Prompt')
    assert (await asyncio.wait_for(future,4))[0]
    assert (await rpc('Get','ss',[CI,'Locked'],object=coll,interface=P))[0].value
   finally:a.remove_message_handler(completed)
   unlocked,request=await rpc('Unlock','ao',[[coll]]);result=await prompted(request,[pin('replacement-password')]);assert not result[0] and result[1].value==[coll]
   assert not (await rpc('Get','ss',[CI,'Locked'],object=coll,interface=P))[0].value
   print('PASS Secret Service lock/search/unlock prompts and prompt-owner isolation',flush=True)
   await a.request_name('org.freedesktop.portal.Desktop');assert (await rpc('Get','ss',['org.freedesktop.impl.portal.Secret','version'],dest='org.freedesktop.impl.portal.desktop.kwallet',object='/org/freedesktop/portal/desktop',interface=P))[0].value==1
   readfd,writefd=os.pipe()
   try:
    result=await rpc('RetrieveSecret','osha{sv}',['/request/test','org.example.Test',0,{}],dest='org.freedesktop.impl.portal.desktop.kwallet',object='/org/freedesktop/portal/desktop',interface='org.freedesktop.impl.portal.Secret',unix_fds=[writefd]);assert result[0]==0
    secret=os.read(readfd,64);assert len(secret)==64
   finally:os.close(readfd);os.close(writefd)
   await rpc('RetrieveSecret','osha{sv}',['/request/test','org.example.Test',0,{}],dest='org.freedesktop.impl.portal.desktop.kwallet',object='/org/freedesktop/portal/desktop',interface='org.freedesktop.impl.portal.Secret',bus=b,error=True)
   print('PASS Secret portal Unix-FD delivery and trusted-portal caller restriction',flush=True)
   _,request=await rpc('CreateCollection','a{sv}s',[{CI+'.Label':Variant('s','Second')},'default']);result=await prompted(request,[confirm(),pin('second-password')]);assert not result[0];second=result[1].value
   assert (await rpc('ReadAlias','s',['default']))==[second]
   props=(await rpc('GetAll','s',[CI],object=second,interface=P))[0];assert props['Label'].value=='Second'
   request=(await rpc('Delete',object=second,interface=CI))[0];result=await prompted(request,[confirm(True)]);assert result[0];assert (path/'wallets/Second.kwl').exists()
   request=(await rpc('Delete',object=second,interface=CI))[0];result=await prompted(request,[confirm()]);assert not result[0];assert not (path/'wallets/Second.kwl').exists()
   assert (await rpc('ReadAlias','s',['default']))==['/']
   print('PASS prompted collection creation/deletion, cancellation and aliases',flush=True)
   daemon.terminate();daemon.wait(timeout=4)
   for _ in range(100):
    if not (await rpc('NameHasOwner','s',[S],dest='org.freedesktop.DBus',object='/org/freedesktop/DBus',interface='org.freedesktop.DBus'))[0]:break
    await asyncio.sleep(.01)
   await launch();queue(pin('replacement-password'));h=(await wallet('open','sxs',['fixture',0,'test-app']))[0]
   assert (await wallet('readPassword','isss',[h,'Passwords','unicode','test-app']))==['příliš 日本語 🔒']
   for p in (path/'wallets').iterdir():
    if p.is_file():assert stat.S_IMODE(p.stat().st_mode)==0o600
   contents=(path/'wallets/fixture.kwl').read_bytes();assert b'replacement-password' not in contents and b'changed\0binary' not in contents
   print('PASS encrypted persistence across daemon restart and private file permissions',flush=True)
   daemon.terminate();daemon.wait(timeout=4)
   for _ in range(100):
    if not (await rpc('NameHasOwner','s',[S],dest='org.freedesktop.DBus',object='/org/freedesktop/DBus',interface='org.freedesktop.DBus'))[0]:break
    await asyncio.sleep(.01)
   hash_read,hash_write=os.pipe();listener=socket.socket(socket.AF_UNIX);listener.bind(str(path/'pam-env'));listener.listen(1)
   daemon=subprocess.Popen([str(BINARY),'--storage-dir',str(path/'wallets'),'--pam-login',str(hash_read),str(listener.fileno())],env=env,stdout=log,stderr=log,pass_fds=(hash_read,listener.fileno()))
   os.close(hash_read);salt=(path/'wallets/fixture.salt').read_bytes();key=hashlib.pbkdf2_hmac('sha512',b'replacement-password',salt,50000,56);os.write(hash_write,key);os.close(hash_write)
   peer=socket.socket(socket.AF_UNIX);peer.connect(str(path/'pam-env'));peer.sendall(('DBUS_SESSION_BUS_ADDRESS='+address+'\n').encode());peer.close();listener.close()
   for _ in range(100):
    if (await rpc('NameHasOwner','s',[S],dest='org.freedesktop.DBus',object='/org/freedesktop/DBus',interface='org.freedesktop.DBus'))[0]:break
    assert daemon.poll() is None;await asyncio.sleep(.03)
   assert (await wallet('isOpen','s',['fixture']))==[True]
   queue(confirm());h=(await wallet('open','sxs',['fixture',0,'pam-client']))[0];assert h>0
   assert (await wallet('readPassword','isss',[h,'Passwords','unicode','pam-client']))==['příliš 日本語 🔒']
   print('PASS PAM pre-hashed login pipe/environment socket handoff without password prompt',flush=True)

  except BaseException:
   log.flush();print((path/'daemon.log').read_text(),file=sys.stderr);raise
  finally:
   if daemon is not None and daemon.poll() is None:
    daemon.terminate()
    try:daemon.wait(timeout=4)
    except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
   a.disconnect();b.disconnect();busproc.terminate();busproc.wait(timeout=3);log.close()
asyncio.run(main())
