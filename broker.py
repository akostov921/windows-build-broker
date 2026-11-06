"""Generic Windows CI broker. Inputs are GitHub secrets; logs/results encrypted.

No credentials are needed to access another repository. Only standard public
Windows runners and encrypted release assets are used; no paid artifact/cache.
"""
import base64,hashlib,io,json,os,signal,subprocess,sys,tempfile,time,traceback,zipfile
from pathlib import Path,PurePosixPath
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC=b'PRIVATEBUILD1'
AAD=b'confidential-windows-build-v1'

def encrypt(key,plaintext):
 nonce=os.urandom(12)
 return MAGIC+nonce+AESGCM(key).encrypt(nonce,plaintext,AAD)

def decrypt(key,data):
 if not data.startswith(MAGIC):raise ValueError('Not an encrypted build bundle')
 data=data[len(MAGIC):]
 return AESGCM(key).decrypt(data[:12],data[12:],AAD)

def safe_extract(source,destination):
 with zipfile.ZipFile(io.BytesIO(source)) as z:
  for item in z.infolist():
   p=PurePosixPath(item.filename)
   if p.is_absolute() or '..' in p.parts or '\\' in item.filename:raise ValueError('Unsafe input archive path')
   if item.file_size>20_000_000:raise ValueError('Input file too large')
  z.extractall(destination)

def build(source,key,output):
 status={'passed':False,'platform':sys.platform,'input_sha256':hashlib.sha256(source).hexdigest()}
 with tempfile.TemporaryDirectory(prefix='private-build-',ignore_cleanup_errors=True) as temp:
  root=Path(temp);app=root/'app';logs=root/'logs';app.mkdir();logs.mkdir()
  try:
   safe_extract(source,app)
   plan=json.loads((app/'ci/cloud-plan.json').read_text(encoding='utf-8'))
   env={k:v for k,v in os.environ.items() if not k.startswith('INPUT_') and k not in {'OUTPUT_KEY','GH_TOKEN','GITHUB_TOKEN'}}
   env.update(PYTHONUTF8='1',PYTHONIOENCODING='utf-8')
   deadline=time.monotonic()+900
   for i,step in enumerate(plan['steps']):
    command=[part.replace('{PYTHON}',sys.executable).replace('{NSIS}',str(Path(os.environ.get('ProgramFiles(x86)','C:/Program Files (x86)'))/'NSIS/makensis.exe')) for part in step]
    if not Path(command[0]).is_absolute() and ('/' in command[0] or '\\' in command[0]):command[0]=str(app/command[0])
    with (logs/f'step-{i}.log').open('wb') as log:
     remaining=deadline-time.monotonic()
     if remaining<=0:raise TimeoutError('Total build time limit reached')
     options={'creationflags':subprocess.CREATE_NEW_PROCESS_GROUP} if os.name=='nt' else {'start_new_session':True}
     p=subprocess.Popen(command,cwd=app,env=env,stdout=log,stderr=subprocess.STDOUT,**options)
     try:p.wait(timeout=remaining)
     except subprocess.TimeoutExpired:
      if os.name=='nt':subprocess.run(['taskkill','/PID',str(p.pid),'/T','/F'],stdout=log,stderr=subprocess.STDOUT,timeout=20)
      else:os.killpg(p.pid,signal.SIGKILL)
      p.wait(timeout=20)
      raise TimeoutError('Total build time limit reached')
    if p.returncode:raise RuntimeError('Build step '+str(i)+' failed')
   status['passed']=True
  except Exception:
   (logs/'failure.log').write_text(traceback.format_exc(),encoding='utf-8')
  status_file=logs/'status.json';status_file.write_text(json.dumps(status,indent=2),encoding='utf-8')
  payload=io.BytesIO()
  with zipfile.ZipFile(payload,'w',zipfile.ZIP_DEFLATED) as z:
   for path in logs.rglob('*'):
    if path.is_file():z.write(path,'diagnostics/'+str(path.relative_to(logs)))
   for pattern in ['dist/*.exe','dist/*.zip','ci-results/*']:
    for path in app.glob(pattern):
     if path.is_file():z.write(path,str(path.relative_to(app)))
  output.write_bytes(encrypt(key,payload.getvalue()))
 return status

def main():
 source=base64.b64decode(''.join(os.environ.get('INPUT_'+str(i),'') for i in range(20)),validate=True)
 if hashlib.sha256(source).hexdigest()!=os.environ.get('INPUT_SHA256'):raise ValueError('Private input checksum mismatch')
 key=base64.b64decode(os.environ['OUTPUT_KEY'],validate=True)
 if len(key)!=32:raise ValueError('Expected AES-256 key')
 status=build(source,key,Path('build-output.aes256gcm'))
 with Path(os.environ['GITHUB_OUTPUT']).open('a',encoding='utf-8') as f:f.write('passed='+str(status['passed']).lower()+'\n')
 print('Encrypted build result created. Passed:',status['passed'])

if __name__=='__main__':main()
