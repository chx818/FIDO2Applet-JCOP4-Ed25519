"""Deterministic malformed-CBOR/command-chain campaign against the reference simulator."""
import hashlib,json,random,sys,time
from pathlib import Path
from simulator import Bridge,ctap,ROOT,COMPILED_CONFIG
from fido2 import cbor
from fido2.hid import CTAPHID
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError

def main():
 rnd=random.Random(20261012);b=Bridge();report={'seed':20261012,'status':'RUNNING','requests':0,'recovery_checks':0,'compiled_provenance':COMPILED_CONFIG['provenance']['fork']}
 out=ROOT/'build/test-logs/malformed-campaign.json'
 try:
  b.install();client=ctap(b);rp='audit.example';anchors=[]
  for alg in [-7,-8]:
   h=bytes([abs(alg)])*32;r=client.make_credential(h,{'id':rp},{'id':bytes([abs(alg)]),'name':'anchor'},[{'alg':alg,'type':'public-key'}],options={'rk':True})
   r.auth_data.credential_data.public_key.verify(r.auth_data+h,r.att_stmt['sig']);anchors.append(r.auth_data.credential_data)
  templates=[bytes([1])+cbor.encode({1:b'a'*32,2:{'id':rp},3:{'id':b'new','name':'n'},4:[{'alg':-8,'type':'public-key'},{'alg':-7,'type':'public-key'}],7:{'rk':False}}),bytes([2])+cbor.encode({1:rp,2:b'b'*32,3:[{'type':'public-key','id':anchors[0].credential_id}]})]
  for i in range(1200):
   original=templates[i%len(templates)];data=bytearray(original)
   mode=i%5
   if mode==0:data=data[:rnd.randrange(1,len(data)+1)]
   elif mode==1:
    for _ in range(1+rnd.randrange(5)):data[rnd.randrange(1,len(data))]=rnd.randrange(256)
   elif mode==2:
    pos=rnd.randrange(1,len(data));data[pos:pos]=bytes(rnd.randrange(256) for _ in range(rnd.randrange(1,35)))
   elif mode==3:data.extend(bytes([0xa1,0x01,0x58,0xff]))
   else:data=bytearray([data[0],rnd.randrange(256)])+bytearray(rnd.randrange(256) for _ in range(rnd.randrange(0,400)))
   try:client.device.call(CTAPHID.CBOR,bytes(data))
   except (CtapError,ApduError):pass
   report['requests']+=1
   # No reset/reinstallation between bad request and valid use: check state recovery.
   if i%20==0:
    client.get_info()
    for anchor in anchors:
     h=hashlib.sha256(str(i).encode()+bytes([abs(anchor.public_key[3])])).digest()
     a=client.get_assertion(rp,h,[{'type':'public-key','id':anchor.credential_id}]);anchor.public_key.verify(a.auth_data+h,a.signature)
     report['recovery_checks']+=1
   if i%200==0:print('malformed requests',i,flush=True)
  report['status']='PASS'
 except BaseException as e:report['status']='FAIL';report['error']=str(e);raise
 finally:b.close();out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print('PASS',report['requests'],'malformed requests;',report['recovery_checks'],'signed recovery checks')
if __name__=='__main__':main()
