"""Explicit opt-in hardware interoperability smoke test. Never installs, deletes or resets applets."""
import argparse,getpass,hashlib,json,secrets,time
from pathlib import Path
from fido2.pcsc import CtapPcscDevice
from fido2.ctap2 import Ctap2,ClientPin,PinProtocolV2
from fido2.ctap import CtapError
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--reader',required=True,help='PC/SC reader filter; must match exactly one FIDO device')
 ap.add_argument('--create-test-credentials',action='store_true',required=True,help='Acknowledge generating two nonresident test credentials and advancing signature counters')
 ap.add_argument('--pin',action='store_true',help='Prompt for an existing PIN without storing it')
 ap.add_argument('--rounds',type=int,default=10)
 ap.add_argument('--report',type=Path,default=Path('hardware-smoke.json'))
 args=ap.parse_args()
 if not 1<=args.rounds<=1000:ap.error('rounds must be 1..1000')
 devices=list(CtapPcscDevice.list_devices(args.reader))
 if len(devices)!=1:raise SystemExit('Expected exactly one FIDO device; found '+str(len(devices)))
 dev=devices[0];results=[]
 try:
  ctap=Ctap2(dev)
  if not {-7,-8}.issubset({p['alg'] for p in ctap.info.algorithms or []}):raise SystemExit('Selected applet does not advertise ES256 and Ed25519; no credentials generated')
  rp='ed25519-test.invalid';pin=getpass.getpass('Existing FIDO PIN: ') if args.pin else None
  cp=ClientPin(ctap,PinProtocolV2()) if pin is not None else None
  def auth(challenge,permission):
   if cp is None:return {}
   token=cp.get_pin_token(pin,permissions=permission,permissions_rpid=rp)
   return {'pin_uv_protocol':cp.protocol.VERSION,'pin_uv_param':cp.protocol.authenticate(token,challenge)}
  creds={}
  for alg in [-7,-8]:
   h=secrets.token_bytes(32)
   r=ctap.make_credential(h,{'id':rp},{'id':secrets.token_bytes(16),'name':'temporary interoperability test'},[{'type':'public-key','alg':alg}],options={'rk':False},**auth(h,ClientPin.PERMISSION.MAKE_CREDENTIAL))
   cd=r.auth_data.credential_data
   if cd.public_key[3]!=alg or len(cd.credential_id)!=112:raise RuntimeError('Incorrect credential format/algorithm')
   if 'x5c' in r.att_stmt:
    if r.att_stmt['alg']!=-7:raise RuntimeError('Incorrect basic attestation algorithm')
    x509.load_der_x509_certificate(r.att_stmt['x5c'][0]).public_key().verify(r.att_stmt['sig'],r.auth_data+h,ECDSA(SHA256()))
   else:
    if r.att_stmt['alg']!=alg:raise RuntimeError('Incorrect self attestation algorithm')
    cd.public_key.verify(r.auth_data+h,r.att_stmt['sig'])
   creds[alg]=cd
  for _ in range(args.rounds):
   for alg,cd in creds.items():
    h=secrets.token_bytes(32);kw=auth(h,ClientPin.PERMISSION.GET_ASSERTION);start=time.perf_counter_ns()
    r=ctap.get_assertion(rp,h,[{'type':'public-key','id':cd.credential_id}],**kw)
    elapsed=time.perf_counter_ns()-start
    if alg==-8 and len(r.signature)!=64:raise RuntimeError('Wrong Ed25519 signature length')
    if r.auth_data.rp_id_hash!=hashlib.sha256(rp.encode()).digest():raise RuntimeError('Wrong RP hash')
    cd.public_key.verify(r.auth_data+h,r.signature)
    results.append({'alg':alg,'verified':True,'elapsed_ns':elapsed,'counter':r.auth_data.counter})
  report={'status':'PASS','test':'hardware interoperability only; not side-channel certification','resident_credentials_created':0,'reset_or_install_performed':False,'results':results}
  args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print('PASS:',args.report)
 finally:dev.close()
if __name__=='__main__':main()
