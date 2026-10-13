"""Inspect/run embedded JVM classes from a user-supplied CAP in the reference simulator.
This is NOT execution of converted CAP bytecode and not a hardware-equivalence proof.
"""
import argparse,hashlib,json,shutil,tempfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--cap',type=Path,required=True);args=ap.parse_args()
cfgpath=ROOT/'build/simulator/config.json';cfg=json.loads(cfgpath.read_text())
base=Path(cfg['classes']['upstream']);out=Path(tempfile.mkdtemp(prefix='production-',dir=ROOT/'build/simulator'))
# Test harness/dependencies only; overwrite every production class from the supplied archive.
shutil.copytree(base,out,dirs_exist_ok=True)
embedded={}
with zipfile.ZipFile(args.cap) as z:
 for n in z.namelist():
  if n.startswith('APPLET-INF/classes/') and n.endswith('.class'):
   rel=n[len('APPLET-INF/classes/'):];p=(out/rel).resolve()
   if not p.is_relative_to(out.resolve()):raise RuntimeError('Unsafe archive path')
   data=z.read(n);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);embedded[n]=hashlib.sha256(data).hexdigest()
if len(embedded)!=9 or 'APPLET-INF/classes/us/q3q/fido2/FIDO2Applet.class' not in embedded:raise RuntimeError('Unexpected original CAP classes; refuse mixed baseline')
cfg['classes']['production']=str(out)
cfg['provenance']['production']={'source_sha256':{},'embedded_class_sha256':embedded,'input_cap_sha256':hashlib.sha256(args.cap.read_bytes()).hexdigest(),'execution_notice':'Embedded JVM classes with jCardSim; not native/converted CAP execution','test_backend_sha256':cfg['provenance']['upstream']['test_backend_sha256']}
cfgpath.write_text(json.dumps(cfg,indent=2)+'\n',encoding='utf-8');print('Prepared',len(embedded),'original JVM classes:',cfg['provenance']['production']['input_cap_sha256'])
