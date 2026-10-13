"""Run upstream Java tests using the pinned local simulator classpath."""
import argparse,json,os,subprocess,xml.etree.ElementTree as ET
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--variant',choices=['fork','upstream'],default='fork');args=parser.parse_args()
cfg=json.loads((ROOT/'build/simulator/config.json').read_text())
out=ROOT/'build/test-logs'/('junit-'+args.variant);out.mkdir(parents=True,exist_ok=True)
cp=os.pathsep.join([cfg['classes'][args.variant],*cfg['deps']])
result=subprocess.run([cfg['java'],'-cp',cp,'org.junit.platform.console.ConsoleLauncher','--select-class','us.q3q.fido2.AppletBasicTest','--reports-dir',str(out),'--disable-ansi-colors'],capture_output=True)
text=(result.stdout+result.stderr).decode('utf-8',errors='replace');(out/'console.log').write_text(text,encoding='utf-8');print(text[-3500:])
tests=[]
for p in out.glob('TEST-*.xml'):
 for t in ET.parse(p).getroot().iter('testcase'):
  tests.append({'name':t.attrib.get('name'),'class':t.attrib.get('classname'),'failures':[e.text for e in t.findall('failure')],'errors':[e.text for e in t.findall('error')],'skipped':bool(t.findall('skipped'))})
report={'variant':args.variant,'finished_at_utc':datetime.now(timezone.utc).isoformat(),'compiled_provenance':cfg['provenance'][args.variant],'exit_code':result.returncode,'testsRun':len(tests),'cases':tests}
(out.parent/('junit-'+args.variant+'.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
raise SystemExit(result.returncode)
