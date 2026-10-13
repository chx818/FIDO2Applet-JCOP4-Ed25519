"""Fetch ONLY locked public JVM test dependencies; does not access readers."""
import hashlib,json,urllib.request
from pathlib import Path
root=Path(__file__).resolve().parents[1]/'simulator-support'
lock=json.loads((root/'dependencies.json').read_text(encoding='utf-8-sig'))
(root/'deps').mkdir(exist_ok=True)
for name,record in lock.items():
 dest=root/'deps'/name
 data=dest.read_bytes() if dest.exists() else urllib.request.urlopen(record['url'],timeout=35).read()
 if hashlib.sha256(data).hexdigest()!=record['sha256']:raise RuntimeError('Dependency hash mismatch: '+name)
 if not dest.exists():dest.write_bytes(data)
 print('Verified',name)
