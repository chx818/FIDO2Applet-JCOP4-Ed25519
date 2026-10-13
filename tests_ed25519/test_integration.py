import hashlib,json,secrets,sys,unittest
from datetime import datetime,timezone
from simulator import Bridge,ctap,ROOT,COMPILED_CONFIG
from cryptography.exceptions import InvalidSignature
from fido2.ctap import CtapError
from fido2.ctap1 import Ctap1,ApduError
from fido2.ctap2 import ClientPin,PinProtocolV1,PinProtocolV2,CredentialManagement,Config
from fido2 import cbor

class Ed25519Integration(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.b=Bridge()
 @classmethod
 def tearDownClass(cls):cls.b.close()
 def setUp(self):
  self.b.command('FAULT 0');self.b.install();self.ctap=ctap(self.b);self.rp='isolation.example'
 def make(self,algs=(-8,),resident=False,user=None,extensions=None,auth=None):
  challenge=secrets.token_bytes(32)
  kw=dict(client_data_hash=challenge,rp={'id':self.rp},user={'id':user or secrets.token_bytes(16),'name':'test'},key_params=[{'type':'public-key','alg':a} for a in algs],options={'rk':resident})
  if extensions:kw['extensions']=extensions
  if auth:
   protocol,token=auth;kw.update(pin_uv_param=protocol.authenticate(token,challenge),pin_uv_protocol=protocol.VERSION)
  response=self.ctap.make_credential(**kw)
  cd=response.auth_data.credential_data
  self.assertEqual(len(cd.credential_id),112)
  if 'x5c' in response.att_stmt:
   from cryptography import x509
   from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
   from cryptography.hazmat.primitives.hashes import SHA256
   self.assertEqual(response.att_stmt['alg'],-7)
   x509.load_der_x509_certificate(response.att_stmt['x5c'][0]).public_key().verify(response.att_stmt['sig'],response.auth_data+challenge,ECDSA(SHA256()))
  else:
   self.assertEqual(response.att_stmt['alg'],cd.public_key[3])
   cd.public_key.verify(response.auth_data+challenge,response.att_stmt['sig'])
  if cd.public_key[3]==-8:
   self.assertEqual(dict(cd.public_key),{1:1,3:-8,-1:6,-2:cd.public_key[-2]})
   self.assertEqual(len(cd.public_key[-2]),32)
   if 'x5c' not in response.att_stmt:self.assertEqual(len(response.att_stmt['sig']),64)
  return response
 def assert_credential(self,cred,*,auth=None):
  challenge=secrets.token_bytes(32);cd=cred.auth_data.credential_data
  kw=dict(rp_id=self.rp,client_data_hash=challenge,allow_list=[{'type':'public-key','id':cd.credential_id}])
  if auth:
   p,t=auth;kw.update(pin_uv_param=p.authenticate(t,challenge),pin_uv_protocol=p.VERSION)
  response=self.ctap.get_assertion(**kw)
  cd.public_key.verify(response.auth_data+challenge,response.signature)
  with self.assertRaises(InvalidSignature):cd.public_key.verify(response.auth_data+b'\0'*32,response.signature)
  self.assertEqual(hashlib.sha256(self.rp.encode()).digest(),response.auth_data.rp_id_hash)
  return response
 def test_algorithm_preference_and_mixed_lifecycle(self):
  creds=[]
  for algs,expected in [((-8,-7),-8),((-7,-8),-7),((-257,-8,-7),-8),((-999,-7,-8),-7)]:
   c=self.make(algs);self.assertEqual(c.auth_data.credential_data.public_key[3],expected);creds.append(c)
  for action in [lambda:None,self.b.deselect,self.b.reset]:
   action()
   for c in creds:self.assert_credential(c)
 def test_resident_mixed_discovery_and_iteration(self):
  creds=[self.make((a,),True) for a in (-7,-8,-8,-7)];byid={c.auth_data.credential_data.credential_id:c for c in creds}
  challenge=secrets.token_bytes(32)
  assertions=self.ctap.get_assertions(self.rp,challenge)
  self.assertEqual(len(assertions),4)
  for a in assertions:
   cd=byid[a.credential['id']].auth_data.credential_data;cd.public_key.verify(a.auth_data+challenge,a.signature)
  self.b.deselect()
  for c in creds:self.assert_credential(c)
 def test_tamper_every_credential_byte_and_wrong_rp(self):
  for alg in (-8,-7):
   c=self.make((alg,));cid=c.auth_data.credential_data.credential_id
   for i in range(len(cid)):
    bad=bytearray(cid);bad[i]^=1
    with self.assertRaises(CtapError):self.ctap.get_assertion(self.rp,secrets.token_bytes(32),[{'type':'public-key','id':bytes(bad)}])
   with self.assertRaises(CtapError):self.ctap.get_assertion('wrong.example',secrets.token_bytes(32),[{'type':'public-key','id':cid}])
   self.assert_credential(c)
 def test_ed_fault_does_not_break_ecdsa(self):
  ec=self.make((-7,));ed=self.make((-8,))
  for mode in (1,2,3):
   self.b.command('FAULT '+str(mode))
   try:
    with self.assertRaises((CtapError,ApduError)):self.make((-8,))
    self.assert_credential(ec);self.make((-7,))
    if mode in (1,2):
     with self.assertRaises((CtapError,ApduError)):self.assert_credential(ed)
   finally:self.b.command('FAULT 0')
   self.assert_credential(ed);self.assert_credential(ec)
 def test_failed_ed_registration_preserves_existing_resident_keys(self):
  # Exercise replacement of a non-last slot and creation under an entirely new RP.
  user=b'same-user';old=self.make((-7,),True,user=user);other=self.make((-7,),True)
  self.b.command('FAULT 4')
  try:
   with self.assertRaises((CtapError,ApduError)):self.make((-8,),True,user=user)
   self.assert_credential(old);self.assert_credential(other)
   self.assertEqual(len(self.ctap.get_assertions(self.rp,secrets.token_bytes(32))),2)
   self.rp='failed-new-rp.example'
   with self.assertRaises((CtapError,ApduError)):self.make((-8,),True)
   with self.assertRaises(CtapError) as err:self.ctap.get_assertions(self.rp,secrets.token_bytes(32))
   self.assertEqual(err.exception.code,CtapError.ERR.NO_CREDENTIALS)
  finally:self.b.command('FAULT 0');self.rp='isolation.example'
  # Successful replacement keeps list/count/most-recent semantics and invalidates old ID.
  replacement=self.make((-8,),True,user=user)
  self.assert_credential(replacement);self.assert_credential(other)
  self.assertEqual(len(self.ctap.get_assertions(self.rp,secrets.token_bytes(32))),2)
  with self.assertRaises(CtapError):self.assert_credential(old)
 def test_u2f_rejects_ed_credentials(self):
  sys.path.insert(0,str(ROOT/'python_tests'))
  from ctap.ctap_test import BasicAttestationTestCase
  fixture=BasicAttestationTestCase();fixture.ctap2=self.ctap;fixture.install_attestation_cert()
  for alg in (-8,-7):
   c=self.make((alg,));cd=c.auth_data.credential_data
   u=Ctap1(self.ctap.device)
   if alg==-8:
    for check in (False,True):
     with self.assertRaises(ApduError) as raised:u.authenticate(secrets.token_bytes(32),hashlib.sha256(self.rp.encode()).digest(),cd.credential_id,check_only=check)
     self.assertEqual(raised.exception.code,0x6a80)
   else:
    challenge=secrets.token_bytes(32);a=u.authenticate(challenge,hashlib.sha256(self.rp.encode()).digest(),cd.credential_id)
    a.verify(hashlib.sha256(self.rp.encode()).digest(),challenge,b'\x04'+cd.public_key[-2]+cd.public_key[-3])
 def test_pin_retry_limit_survives_deselect(self):
  for protocol in (PinProtocolV1(),PinProtocolV2()):
   self.b.install();self.ctap=ctap(self.b);cp=ClientPin(self.ctap,protocol);cp.set_pin('123456')
   for i in range(3):
    with self.assertRaises(CtapError) as err:cp.get_pin_token('999999')
    self.assertEqual(err.exception.code,CtapError.ERR.PIN_AUTH_BLOCKED if i==2 else CtapError.ERR.PIN_INVALID)
    self.b.deselect()
   self.assertEqual(cp.get_pin_retries(),(5,True))
   with self.assertRaises(CtapError) as err:cp.get_pin_token('123456')
   self.assertEqual(err.exception.code,CtapError.ERR.PIN_AUTH_BLOCKED)
   self.b.reset();self.assertEqual(cp.get_pin_retries(),(5,False));cp.get_pin_token('123456');self.assertEqual(cp.get_pin_retries()[0],8)
 def test_mixed_credential_management(self):
  cp=ClientPin(self.ctap,PinProtocolV2());cp.set_pin('123456');creds=[]
  for alg in (-7,-8):
   token=cp.get_pin_token('123456',permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,permissions_rpid=self.rp)
   creds.append(self.make((alg,),True,auth=(cp.protocol,token)))
  token=cp.get_pin_token('123456',permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
  cm=CredentialManagement(self.ctap,cp.protocol,token);entries=cm.enumerate_creds(hashlib.sha256(self.rp.encode()).digest())
  byid={c.auth_data.credential_data.credential_id:c.auth_data.credential_data.public_key for c in creds}
  self.assertEqual(len(entries),2)
  for e in entries:self.assertEqual(e[8],dict(byid[e[7]['id']]))
  for e in entries:
   token=cp.get_pin_token('123456',permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
   CredentialManagement(self.ctap,cp.protocol,token).delete_cred(e[7])
  for c in creds:
   with self.assertRaises(CtapError):self.assert_credential(c)
 def test_unsupported_and_malformed_algorithm_maps(self):
  with self.assertRaises(CtapError) as e:self.make((-257,-999))
  self.assertEqual(e.exception.code,CtapError.ERR.UNSUPPORTED_ALGORITHM)
  # A supported first entry must not hide malformed later entries.
  req={1:b'0'*32,2:{'id':self.rp},3:{'id':b'user'},4:[{'alg':-8,'type':'public-key'}, {'alg':b'bad','type':'public-key'}]}
  with self.assertRaises(CtapError):self.ctap.send_cbor(1,req)
  self.make((-7,));self.make((-8,))
 def test_extended_apdus(self):
  self.ctap=ctap(self.b,True);c=self.make((-8,),True,extensions={'credBlob':b'B'*32,'hmac-secret':True,'credProtect':2});self.assert_credential(c)
 def test_ed_assertion_fault_detection_after_seed_restore(self):
  resident=self.make((-8,),True);nonresident=self.make((-8,));ec=self.make((-7,))
  self.b.deselect()
  self.b.command('FAULT 3')
  try:
   with self.assertRaises((CtapError,ApduError)):self.assert_credential(resident)
   self.assert_credential(ec)
  finally:self.b.command('FAULT 0')
  self.b.command('FAULT 6')
  try:
   with self.assertRaises((CtapError,ApduError)):self.assert_credential(nonresident)
   self.assert_credential(ec)
  finally:self.b.command('FAULT 0')
  self.assert_credential(resident);self.assert_credential(nonresident)
 def test_minimal_ram_scratch_and_protection_matrix(self):
  # Leave less than one 32-byte crypto block in BufferManager RAM; force flash/APDU fallback.
  for high_security in (False,True):
   params={9:24}
   if high_security:params.update({1:False,3:False})
   self.b.install(cbor.encode(params));self.ctap=ctap(self.b)
   cp=ClientPin(self.ctap,PinProtocolV2());cp.set_pin('123456')
   for alg in (-7,-8):
    for resident in (False,True):
     for protection in (1,2,3):
      token=cp.get_pin_token('123456',permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,permissions_rpid=self.rp)
      cred=self.make((alg,),resident,extensions={'credProtect':protection,'credBlob':b'x'},auth=(cp.protocol,token))
      self.b.deselect()
      if protection==3 or (high_security and resident):
       with self.assertRaises(CtapError):self.assert_credential(cred)
      token=cp.get_pin_token('123456',permissions=ClientPin.PERMISSION.GET_ASSERTION,permissions_rpid=self.rp)
      self.assert_credential(cred,auth=(cp.protocol,token))
 def test_native_cleanup_failure_preserves_existing_resident_key(self):
  user=b'same-user';old=self.make((-7,),True,user=user)
  self.b.command('FAULT 5')
  try:
   with self.assertRaises((CtapError,ApduError)):self.make((-8,),True,user=user)
   self.assert_credential(old)
  finally:self.b.command('FAULT 0');self.b.deselect()
  self.assert_credential(old);self.assertEqual(len(self.ctap.get_assertions(self.rp,secrets.token_bytes(32))),1)
 def test_pin_ecdh_rotation_and_old_token_rejected_after_deselect(self):
  for protocol in (PinProtocolV1(),PinProtocolV2()):
   self.b.install();self.ctap=ctap(self.b);cp=ClientPin(self.ctap,protocol);cp.set_pin('123456')
   key_before=self.ctap.client_pin(protocol.VERSION,ClientPin.CMD.GET_KEY_AGREEMENT)[1]
   token=cp.get_pin_token('123456',permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,permissions_rpid=self.rp)
   self.b.deselect()
   key_after=self.ctap.client_pin(protocol.VERSION,ClientPin.CMD.GET_KEY_AGREEMENT)[1]
   self.assertNotEqual(key_before,key_after)
   with self.assertRaises(CtapError):self.make((-8,),auth=(protocol,token))
   token=cp.get_pin_token('123456',permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,permissions_rpid=self.rp)
   self.make((-8,),auth=(protocol,token))
 def test_chained_first_request_after_deselect(self):
  c=self.make((-7,));cid=c.auth_data.credential_data.credential_id
  self.b.deselect()
  challenge=secrets.token_bytes(32)
  # More than three short APDUs, exercising bufferMem near its tail before command dispatch.
  params=[{'alg':-257,'type':'public-key','unused':'a'*60} for _ in range(8)]
  params.append({'alg':-8,'type':'public-key'})
  response=self.ctap.make_credential(challenge,{'id':self.rp},{'id':b'new','name':'n'},params)
  response.auth_data.credential_data.public_key.verify(response.auth_data+challenge,response.att_stmt['sig'])
  self.assertEqual(response.att_stmt['alg'],-8);self.assert_credential(c)
 def test_default_attestation_provisioning_and_reset_lifecycle(self):
  self.b.install(b'');self.ctap=ctap(self.b)
  sys.path.insert(0,str(ROOT/'python_tests'))
  from ctap.ctap_test import BasicAttestationTestCase
  fixture=BasicAttestationTestCase();fixture.ctap2=self.ctap
  cert=fixture.gen_attestation_cert()
  self.make((-8,))
  with self.assertRaises(CtapError):self.ctap.send_cbor(0x46,{1:cert})
  self.ctap.reset()  # Unprovisioned identity becomes eligible again, no install option required.
  self.ctap.send_cbor(0x46,{1:cert})
  aaguid=self.ctap.get_info().aaguid
  for alg in (-7,-8):self.make((alg,))
  self.ctap.reset()
  self.assertEqual(self.ctap.get_info().aaguid,aaguid)
  # Reset preserves the installed identity, and must not permit an unauthenticated replacement.
  with self.assertRaises(CtapError):self.ctap.send_cbor(0x46,{1:fixture.gen_attestation_cert()})
  self.make((-7,));self.make((-8,))
 def test_all_authdata_extension_combinations(self):
  candidates=[('hmac-secret',True),('credProtect',2),('credBlob',b'abc'),('uvm',True),('minPinLength',True)]
  for verified in (False,True):
   self.b.install();self.ctap=ctap(self.b)
   Config(self.ctap).set_min_pin_length(min_pin_length=4,rp_ids=[self.rp])
   cp=ClientPin(self.ctap,PinProtocolV2())
   if verified:cp.set_pin('123456')
   for alg in (-7,-8):
    for mask in range(32):
     extensions={k:v for i,(k,v) in enumerate(candidates) if mask&(1<<i)}
     auth=None
     if verified:auth=(cp.protocol,cp.get_pin_token('123456',permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,permissions_rpid=self.rp))
     # Reuse one RK identity so this matrix tests encoding, not simulator flash capacity.
     c=self.make((alg,),True,user=b'extension-matrix',extensions=extensions,auth=auth)
     returned=c.auth_data.extensions or {}
     for key in extensions:self.assertIn(key,returned)
     if 'uvm' in extensions:self.assertEqual(returned['uvm'][0][0],0x0800 if verified else 1)
 def test_oversized_chained_request_reports_error_and_recovers(self):
  old_limit=self.ctap._max_msg_size;self.ctap._max_msg_size=4096
  try:
   with self.assertRaises(CtapError) as error:self.ctap.send_cbor(1,{1:b'x'*2500})
   self.assertEqual(error.exception.code,CtapError.ERR.REQUEST_TOO_LARGE)
  finally:self.ctap._max_msg_size=old_limit
  self.ctap.get_info();self.make((-7,));self.make((-8,))
 def test_repeated_native_errors_preserve_allocator_capacity(self):
  self.b.install(cbor.encode({9:24}));self.ctap=ctap(self.b)
  ec=self.make((-7,),True)
  self.b.command('FAULT 1')
  try:
   for i in range(40):
    with self.assertRaises((CtapError,ApduError)):self.make((-8,))
  finally:self.b.command('FAULT 0')
  # No reset, reselect or getInfo between faults and use of the pre-existing key.
  self.assert_credential(ec);self.make((-7,));self.make((-8,))
 def test_persistent_public_key_after_interrupted_command_and_scratch_bounds(self):
  self.assertEqual(self.b.command('PERSISTENCEPROBE'),'90009000')
  # Main applet was power-reset too; both algorithms must still work.
  self.make((-7,));self.make((-8,))
 def test_resident_padding_and_iv_domain_separation(self):
  self.assertEqual(self.b.command('STORAGEPROBE'),'9000')
 def test_adapter_transaction_guard_and_overlapping_io(self):
  self.assertEqual(self.b.command('PROBE'),'9000')
  self.make((-7,));self.make((-8,))
 def test_many_alternating_operations(self):
  for i in range(20):
   c=self.make((-8 if i%2 else -7,));self.assert_credential(c)
   if i%4==0:self.b.deselect()

if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Ed25519Integration))
 (ROOT/'build/test-logs/ed25519-integration.json').write_text(json.dumps({'finished_at_utc':datetime.now(timezone.utc).isoformat(),'compiled_provenance':COMPILED_CONFIG['provenance']['fork'],'testsRun':result.testsRun,'failures':[(t.id(),m) for t,m in result.failures],'errors':[(t.id(),m) for t,m in result.errors]},indent=2),encoding='utf-8')
 raise SystemExit(not result.wasSuccessful())
