import json,sys,unittest,queue,argparse
from pathlib import Path
from datetime import datetime,timezone
from simulator import Bridge,ROOT,COMPILED_CONFIG

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--variant',choices=['upstream','fork','production'],default='fork');ap.add_argument('--failfast',action='store_true');ap.add_argument('--ed25519',action='store_true');ap.add_argument('--pattern',default='test_*.py');args=ap.parse_args()
 sys.path.insert(0,str(ROOT/'python_tests'))
 import ctap.ctap_test as base
 base.CTAPTestCase.EXPECTED_ALGORITHMS=[{'alg':-7,'type':'public-key'}]+([{'alg':-8,'type':'public-key'}] if args.variant=='fork' else [])
 base.CTAPTestCase.EXPECTED_CREDENTIAL_ALGORITHM=-8 if args.ed25519 else -7
 if args.ed25519:
  if args.variant!='fork':raise ValueError('Ed25519 requires fork')
  from fido2.webauthn import PublicKeyCredentialParameters,PublicKeyCredentialType
  original_setup=base.CTAPTestCase.setUp
  def ed_setup(self,*a,**kw):
   original_setup(self,*a,**kw)
   self.basic_makecred_params['key_params']=[{'alg':-8,'type':'public-key'}]
  base.CTAPTestCase.setUp=ed_setup
  original_opts=base.CTAPTestCase.get_high_level_make_cred_options
  def ed_opts(self,*a,**kw):
   import dataclasses
   opts=original_opts(self,*a,**kw)
   return dataclasses.replace(opts,pub_key_cred_params=[PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY,alg=-8)])
  base.CTAPTestCase.get_high_level_make_cred_options=ed_opts
 class CommandQueue:
  def __init__(self,b,q):self.b=b;self.q=q
  def put(self,item):
   typ,data=item
   if typ==base.CommandType.APPLET_REINSTALL:r=self.b.command('INSTALL '+bytes(data).hex());r=None
   elif typ==base.CommandType.SOFT_RESET:self.b.reset();r=None
   else:r=list(self.b.transmit(data))
   self.q.put(r)
 def setup(cls):
  b=Bridge(args.variant);cls.p=[b];cls.q_in=queue.Queue();cls.q_out=CommandQueue(b,cls.q_in)
 def teardown(cls):
  for b in cls.p:b.close()
  cls.p=[]
 base.JCardSimTestCase.setUpClass=classmethod(setup);base.JCardSimTestCase.tearDownClass=classmethod(teardown)
 suite=unittest.defaultTestLoader.discover(str(ROOT/'python_tests/ctap'),pattern=args.pattern,top_level_dir=str(ROOT/'python_tests'))
 if args.ed25519:
  def flatten(node):
   for test in node:
    if isinstance(test,unittest.TestSuite):yield from flatten(test)
    elif not test.id().startswith('ctap.test_u2f.'):yield test
  suite=unittest.TestSuite(flatten(suite))
 result=unittest.TextTestRunner(verbosity=1,failfast=args.failfast).run(suite)
 cfg=COMPILED_CONFIG
 report={'finished_at_utc':datetime.now(timezone.utc).isoformat(),'compiled_provenance':cfg['provenance'][args.variant],'variant':args.variant,'pattern':args.pattern,'ed25519_mode':args.ed25519,'testsRun':result.testsRun,'failures':[(t.id(),m) for t,m in result.failures],'errors':[(t.id(),m) for t,m in result.errors],'skipped':[(t.id(),m) for t,m in result.skipped]}
 dst=ROOT/'build/test-logs'/('upstream-tests-'+args.variant+('-ed25519' if args.ed25519 else '')+'-'+args.pattern.replace('*','all')+'.json');dst.write_text(json.dumps(report,indent=2),encoding='utf-8')
 print(dst);raise SystemExit(not result.wasSuccessful())
if __name__=='__main__':main()
