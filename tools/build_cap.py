"""Build/verify two independent Java Card 3.0.5 CAPs; never accesses a reader."""
import argparse,hashlib,io,json,os,subprocess,sys,tempfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PINNED={'Curve25519.cap':'f81943f52d2f22ea63d773d07736bebc34a0ed69d5c233633b043db6a8e5bb22','curve25519.jar':'5bc1df74c6dd30476fb854dde5465b2f44b27b3bfbf3051302d044d91b21c1e4'}
def sha(data):return hashlib.sha256(data).hexdigest()
def extract(jar,dest,prefix='',suffixes=('.class','.exp')):
 with zipfile.ZipFile(jar) as z:
  for n in z.namelist():
   if n.startswith(prefix) and n.endswith(suffixes):
    p=dest/n[len(prefix):];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(z.read(n))
def canonical(raw):
 out=io.BytesIO()
 with zipfile.ZipFile(io.BytesIO(raw)) as zin,zipfile.ZipFile(out,'w',compression=zipfile.ZIP_STORED) as zout:
  for name in sorted(zin.namelist()):
   if name.endswith('/'): continue
   data=zin.read(name)
   if name.upper()=='META-INF/MANIFEST.MF':
    # Converter includes creation time in the manifest; omit only volatile lines.
    lines=data.decode().replace('\r\n','\n').splitlines()
    data=('\r\n'.join(x for x in lines if not x.startswith(('Java-Card-CAP-Creation-Time:',)))+'\r\n').encode()
   info=zipfile.ZipInfo(name,(2000,1,1,0,0,0));info.compress_type=zipfile.ZIP_STORED;info.create_system=0;info.external_attr=0x20
   zout.writestr(info,data)
 return out.getvalue()
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--jdk',type=Path,default=ROOT.parent/'build_tools/jdk_extracted/jdk-11.0.32.1+1')
 ap.add_argument('--sdk305',type=Path,default=ROOT.parent/'SmartPGP-J3R452-Curve25519/sdks/jc305u3_kit')
 ap.add_argument('--sdk310',type=Path,default=ROOT.parent/'SmartPGP-J3R452-Curve25519/sdks/jc310r20210706_kit')
 args=ap.parse_args(); args.jdk=args.jdk.resolve();args.sdk305=args.sdk305.resolve();args.sdk310=args.sdk310.resolve()
 for n,h in PINNED.items():
  if sha((ROOT/'lib'/n).read_bytes())!=h: raise RuntimeError('Wrong dependency: '+n)
 sources={str(p.relative_to(ROOT)).replace('\\','/'):p.read_bytes().replace(b'\r\n',b'\n') for p in sorted((ROOT/'src/main/java').rglob('*.java'))}
 tools=[args.sdk310/'lib'/n for n in ['tools.jar','asm-8.0.1.jar','commons-cli-1.4.jar','commons-logging-1.2-9f99a00.jar','json.jar']]
 compiler=args.jdk/'bin'/('javac.exe' if os.name=='nt' else 'javac');java=args.jdk/'bin'/('java.exe' if os.name=='nt' else 'java')
 artifacts=[];work=ROOT/'build/verified';work.mkdir(parents=True,exist_ok=True)
 runroot=Path(tempfile.mkdtemp(prefix='build-',dir=work));logs=[]
 def call(cmd,cwd):
  p=subprocess.run(list(map(str,cmd)),cwd=cwd,capture_output=True)
  text=(p.stdout+p.stderr).decode('utf-8',errors='replace'); logs.append(text)
  (runroot/'build.log').write_text('\n'.join(logs),encoding='utf-8')
  print(Path(str(cmd[0])).name,p.returncode,flush=True)
  if p.returncode: print(text);raise RuntimeError('Build failed; see '+str(runroot/'build.log'))
 for idx in (1,2):
  run=runroot/str(idx);run.mkdir();api=run/'api';exports=run/'exports';classes=run/'classes';out=run/'out'
  for d in [api,exports,classes,out]:d.mkdir()
  extract(args.sdk305/'lib/api_classic.jar',api);extract(ROOT/'lib/curve25519.jar',api)
  extract(args.sdk310/'lib/tools.jar',exports,'api_export_files_3.0.5/',('.exp',))
  src=[]
  for n,data in sources.items():
   p=run/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);src.append(p)
  call([compiler,'-J-Duser.language=en','-J-Duser.country=US','-J-Dfile.encoding=UTF-8','-proc:none','-encoding','UTF-8','-source','7','-target','7','-g','-classpath',api,'-d',classes,*src],run)
  j=[java,'-Duser.language=en','-Duser.country=US','-Duser.timezone=UTC','-cp',os.pathsep.join(map(str,tools))]
  def aid(s):return ':'.join('0x'+s[i:i+2] for i in range(0,len(s),2))
  call(j+['com.sun.javacard.converter.Main','-verbose','-target','3.0.5','-classdir',classes,'-exportpath',str(exports)+os.pathsep+str(api),'-applet',aid('A0000006472F0001'),'us.q3q.fido2.FIDO2Applet','-d',out,'-out','CAP','EXP','us.q3q.fido2',aid('A000000647'),'0.5'],run)
  cap=out/'us/q3q/fido2/javacard/fido2.cap'
  exps=sorted([*exports.rglob('*.exp'),*api.rglob('*.exp')]);v=j+['com.sun.javacard.offcardverifier.Verifier','-target','3.0.5',*exps]
  call(v+[cap],run)
  data=canonical(cap.read_bytes());canon=run/'FIDO2-Ed25519.cap';canon.write_bytes(data);call(v+[canon],run);artifacts.append(data)
 if artifacts[0]!=artifacts[1]:raise RuntimeError('Independent builds differ')
 for n,data in sources.items():
  if (ROOT/n).read_bytes().replace(b'\r\n',b'\n')!=data:raise RuntimeError('Source changed during build')
 dist=ROOT/'dist';dist.mkdir(exist_ok=True);cap=artifacts[0];(dist/'FIDO2-Ed25519.cap').write_bytes(cap)
 inventory={n:sha(b) for n,b in sources.items()}
 inventory['tools/build_cap.py']=sha(Path(__file__).read_bytes().replace(b'\r\n',b'\n'))
 with zipfile.ZipFile(io.BytesIO(cap)) as z:
  components={n:sha(z.read(n)) for n in sorted(z.namelist()) if n.endswith('.cap')}
  component_bytes=sum(len(z.read(n)) for n in components)
 manifest={'cap_components_sha256':components,'cap_component_bytes':component_bytes,'hardware_tested':False,'upstream_commit':'3bddc3d4ce05c2668d79ff4542faa2c477adc908','target':'3.0.5','package_version':'0.5','cap_sha256':sha(cap),'source_sha256':inventory,'binary_dependencies':PINNED,'sdk_sha256':{p.name:sha(p.read_bytes()) for p in [args.sdk305/'lib/api_classic.jar',*tools]},'jdk_release':(args.jdk/'release').read_text(),'jdk_files_sha256':{str(p.relative_to(args.jdk)).replace('\\','/'):sha(p.read_bytes()) for p in [compiler,java,args.jdk/'lib/modules']},'verification':'two independent builds, raw and canonical CAPs verified; hardware not exercised by this build'}
 (dist/'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
 (dist/'SHA256SUMS').write_text(sha(cap)+'  FIDO2-Ed25519.cap\n',encoding='ascii')
 record={'independent_builds':2,'byte_identical':True,'oracle_offcard_verification':'raw and canonical CAP, both builds','cap_sha256':sha(cap),'build_log':str((runroot/'build.log').relative_to(ROOT)).replace('\\','/')}
 (work/'last-result.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
 print('PASS two builds identical:',sha(cap));print('Logs:',runroot)
if __name__=='__main__':main()
