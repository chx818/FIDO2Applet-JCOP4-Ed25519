"""Local reference simulator transport. Never enumerates/connects physical readers."""
import json,os,queue,subprocess,threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
COMPILED_CONFIG=json.loads((ROOT/'build/simulator/config.json').read_text())
class Bridge:
 def __init__(self,variant='fork'):
  cfg=COMPILED_CONFIG
  logs=ROOT/'build/test-logs';logs.mkdir(parents=True,exist_ok=True)
  self.log=(logs/(variant+'-java.log')).open('a',encoding='utf-8')
  cp=os.pathsep.join([cfg['classes'][variant],*cfg['deps']])
  self.p=subprocess.Popen([cfg['java'],'-cp',cp,'us.q3q.fido2.SimulatorBridge'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,text=True,bufsize=1,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
  self.responses=queue.Queue()
  def read():
   for line in self.p.stdout:self.responses.put(line.strip())
   self.responses.put('ERROR JVM exited')
  threading.Thread(target=read,daemon=True).start()
 def command(self,line):
  self.p.stdin.write(line+'\n');self.p.stdin.flush()
  try:r=self.responses.get(timeout=40)
  except queue.Empty:self.close();raise RuntimeError('Simulator response timed out; inspect build/test-logs')
  if r.startswith('ERROR'):raise RuntimeError(r)
  return r
 def install(self,params=bytes.fromhex('a100f5')):
  return self.command('INSTALL '+(bytes([1,95,1,86,len(params)])+params).hex())
 def reset(self):return self.command('RESET')
 def deselect(self):return self.command('DESELECT')
 def transmit(self,b):return bytes.fromhex(self.command(bytes(b).hex()))
 def is_alive(self):return self.p.poll() is None
 def kill(self):self.close()
 def join(self):pass
 def close(self):
  if self.p.poll() is None:self.p.kill();self.p.wait(timeout=10)
  self.p.stdin.close();self.p.stdout.close();self.log.close()
class Connection:
 def __init__(self,bridge):self.bridge=bridge
 def connect(self):pass
 def disconnect(self):pass
 def transmit(self,b,protocol=None):
  r=self.bridge.transmit(b);return list(r[:-2]),r[-2],r[-1]
def ctap(bridge,extended=False):
 from fido2.pcsc import CtapPcscDevice
 from fido2.ctap2 import Ctap2
 dev=CtapPcscDevice(Connection(bridge),'REFERENCE SIMULATOR (not a physical reader)');dev.use_ext_apdu=extended
 return Ctap2(dev)
