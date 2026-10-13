"""Compile actual applet sources plus an explicitly test-only Ed25519 reference backend."""
import argparse,hashlib,json,os,subprocess,tempfile
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--jdk',type=Path,default=ROOT.parent/'build_tools/jdk_extracted/jdk-11.0.32.1+1')
 args=parser.parse_args();jdk=args.jdk.resolve()
 built={};provenance={}
 deps=ROOT/'simulator-support/deps';lock=json.loads((deps.parent/'dependencies.json').read_text(encoding='utf-8-sig'))
 for name,entry in lock.items():
  if hashlib.sha256((deps/name).read_bytes()).hexdigest()!=entry['sha256']: raise RuntimeError(name)
 cp=os.pathsep.join(str(deps/n) for n in sorted(lock))
 testsrc=sorted((ROOT/'simulator-support/src').rglob('*.java'))+sorted((ROOT/'src/test/java').rglob('*.java'))
 commit='3bddc3d4ce05c2668d79ff4542faa2c477adc908'
 for variant in ['upstream','fork']:
  parent=ROOT/'build/simulator';parent.mkdir(parents=True,exist_ok=True)
  out=Path(tempfile.mkdtemp(prefix=variant+'-',dir=parent));built[variant]=str(out)
  src=list((ROOT/'src/main/java').rglob('*.java'))
  if variant=='upstream':
   src=[]
   names=subprocess.check_output(['git','ls-tree','-r','--name-only',commit,'src/main/java'],cwd=ROOT,text=True).splitlines()
   for name in names:
    p=ROOT/'build/baseline-source'/name;p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(subprocess.check_output(['git','show',commit+':'+name],cwd=ROOT));src.append(p)
  if variant=='upstream':
   # Probe class is compiled against the fork API but never called in baseline runs.
   src.append(ROOT/'src/main/java/us/q3q/fido2/Ed25519Credentials.java')
  provenance[variant]={'source_sha256':{str(p.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(p.read_bytes().replace(b'\r\n',b'\n')).hexdigest() for p in src},'test_backend_sha256':{str(p.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(p.read_bytes().replace(b'\r\n',b'\n')).hexdigest() for p in testsrc}}
  cmd=[str(jdk/'bin'/('javac.exe' if os.name=='nt' else 'javac')),'-J-Duser.language=en','-J-Dfile.encoding=UTF-8','-encoding','UTF-8','-source','7','-target','7','-cp',cp,'-d',str(out),*map(str,src),*map(str,testsrc)]
  result=subprocess.run(cmd,cwd=ROOT,capture_output=True)
  print(variant,result.returncode,flush=True)
  log=(result.stdout+result.stderr).decode('utf-8',errors='replace');(out/'compile.log').write_text(log,encoding='utf-8')
  if result.returncode:print(log);raise SystemExit(result.returncode)
 config={'java':str(jdk/'bin'/('java.exe' if os.name=='nt' else 'java')),'deps':[str(deps/n) for n in sorted(lock)],'classes':built,'provenance':provenance,'compiled_at_utc':datetime.now(timezone.utc).isoformat()}
 (ROOT/'build/simulator/config.json').write_text(json.dumps(config,indent=2),encoding='utf-8')
if __name__=='__main__':main()
