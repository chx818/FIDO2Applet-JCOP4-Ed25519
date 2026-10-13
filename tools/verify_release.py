"""Check whole-CAP/source/test provenance, without touching a reader."""
import argparse,hashlib,json,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def digest(data):return hashlib.sha256(data).hexdigest()
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--artifact-only',action='store_true',help='Check artifact and inputs without requiring archived test reports')
 args=parser.parse_args()
 manifest=json.loads((ROOT/'dist/build-manifest.json').read_text(encoding='utf-8'))
 for name,h in manifest['source_sha256'].items():
  path=(ROOT/name).resolve()
  if not path.is_relative_to(ROOT) or digest(path.read_bytes().replace(b'\r\n',b'\n'))!=h:raise RuntimeError('Wrong/missing build input: '+name)
 for name,h in manifest['binary_dependencies'].items():
  if digest((ROOT/'lib'/name).read_bytes())!=h:raise RuntimeError('Wrong dependency: '+name)
 cap=ROOT/'dist/FIDO2-Ed25519.cap'
 if digest(cap.read_bytes())!=manifest['cap_sha256']:raise RuntimeError('Wrong whole CAP')
 sums=(ROOT/'dist/SHA256SUMS').read_text().split()
 if sums!=[manifest['cap_sha256'],'FIDO2-Ed25519.cap']:raise RuntimeError('Wrong SHA256SUMS')
 with zipfile.ZipFile(cap) as z:
  names=z.namelist()
  if len(names)!=len(set(names)):raise RuntimeError('Duplicate CAP ZIP entries')
  actual={n:digest(z.read(n)) for n in names if n.endswith('.cap')}
  if actual!=manifest['cap_components_sha256']:raise RuntimeError('Wrong CAP components')
  for n in names:
   if any(marker in n for marker in ['AdapterProbe','StorageProbe','PersistenceProbe','CorPressure','SimulatorBridge','org/suut/','org/bouncycastle/']):raise RuntimeError('Test/dependency code bundled into production CAP: '+n)
 summary_path=ROOT/'reports/final-summary.json'
 if not summary_path.exists():
  args.artifact_only=True
 if not args.artifact_only:
  summary=json.loads(summary_path.read_text(encoding='utf-8'))
  if summary['cap_sha256']!=manifest['cap_sha256']:raise RuntimeError('Stale audit/test report')
  for test in summary['simulator_suites']:
   path=(ROOT/test['report']).resolve()
   if not path.is_relative_to(ROOT) or digest(path.read_bytes())!=test['sha256']:raise RuntimeError('Wrong report hash: '+test['report'])
   report=json.loads(path.read_text(encoding='utf-8'))
   expected={n:h for n,h in manifest['source_sha256'].items() if n.startswith('src/main/java/')}
   compiled={n:h for n,h in report['compiled_provenance']['source_sha256'].items() if n.startswith('src/main/java/')}
   if compiled!=expected:raise RuntimeError('Tests compiled different source: '+test['report'])
   if report.get('failures') or report.get('errors') or report.get('exit_code',0):raise RuntimeError('Tests failed: '+test['report'])
   for case in report.get('cases',[]):
    if case['failures'] or case['errors']:raise RuntimeError('Java test failed')
  campaign=json.loads((ROOT/summary['malformed_campaign']['report']).read_text(encoding='utf-8'))
  if campaign['status']!='PASS' or campaign['compiled_provenance']['source_sha256']!=expected:
   raise RuntimeError('Malformed campaign not passing/current')
  for item in summary.get('historical_hardware_reports',[]):
   path=ROOT/item['report']
   if digest(path.read_bytes())!=item['sha256']:raise RuntimeError('Historical report hash mismatch')
   report=json.loads(path.read_text(encoding='utf-8'))
   if report['candidate']['cap_sha256']!=item['cap_sha256']:raise RuntimeError('Historical revision mismatch')
   if item['applies_to_current_CAP'] != (item['cap_sha256']==manifest['cap_sha256']):
    raise RuntimeError('Historical report attributed to the wrong CAP')
  for item in summary.get('hardware_reports',[]):
   path=(ROOT/item['report']).resolve()
   if not path.is_relative_to(ROOT) or digest(path.read_bytes())!=item['sha256']:raise RuntimeError('Wrong current hardware report hash')
   report=json.loads(path.read_text(encoding='utf-8'))
   if report['candidate']['cap_sha256']!=manifest['cap_sha256']:raise RuntimeError('Hardware report belongs to another CAP')
   if report['status']!='PASS':raise RuntimeError('Hardware report not passing')
  for key in ['card_reconciliation','other_applets_select_check']:
   if key in summary:
    item=summary[key];path=(ROOT/item['report']).resolve()
    if not path.is_relative_to(ROOT) or digest(path.read_bytes())!=item['sha256']:
     raise RuntimeError('Wrong card evidence hash: '+key)
  for label,item in summary.get('memory_comparison',{}).items():
   path=(ROOT/item['report']).resolve()
   if not path.is_relative_to(ROOT) or digest(path.read_bytes())!=item['sha256']:raise RuntimeError('Wrong memory report hash')
   report=json.loads(path.read_text(encoding='utf-8'))
   if report['status']!='PASS':raise RuntimeError('Memory comparison did not pass')
   artifact=report['build'].get('cap_sha256',report['build'].get('sha256'))
   if artifact!=item['artifact_sha256']:raise RuntimeError('Memory artifact identity mismatch')
   if label=='latest' and artifact!=manifest['cap_sha256']:raise RuntimeError('Memory report is stale')
 print('PASS artifact' if args.artifact_only else 'PASS artifact + current offline evidence + historical hardware attribution',manifest['cap_sha256'])
if __name__=='__main__':main()
