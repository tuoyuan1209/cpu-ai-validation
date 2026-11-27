from pathlib import Path
import os, json, hashlib, datetime as dt, uuid, time, subprocess
from .policy import BASE, clean_text, structured
from .transport import execute

def now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def new_id(prefix='run-'): return prefix+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ-')+uuid.uuid4().hex[:8]
def write_json(path,obj): Path(path).write_text(json.dumps(structured(obj),ensure_ascii=False,indent=2)+'\n')
def seal(p):
    p=Path(p); (p/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(p)}\n' for f in sorted(p.rglob('*')) if f.is_file() and f.name!='SHA256SUMS'))
def verify(p):
    p=Path(p); expected={}
    if p.is_symlink() or any(x.is_symlink() for x in p.rglob('*')): raise ValueError('symbolic links are not permitted in evidence')
    for line in (p/'SHA256SUMS').read_text().splitlines():
        h,sep,n=line.partition('  ')
        if not sep or n in expected or Path(n).is_absolute() or '..' in Path(n).parts or len(h)!=64: raise ValueError('invalid evidence manifest')
        expected[n]=h
    actual={str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob('*') if f.is_file() and f.name!='SHA256SUMS'}
    if actual!=expected: raise ValueError('evidence checksum mismatch or unexpected files')
    return hashlib.sha256((p/'SHA256SUMS').read_bytes()).hexdigest()

def overall(cases):
    statuses={c['status'] for c in cases}
    if 'FAIL' in statuses: return 'FAIL'
    if not statuses or statuses-{'PASS','WARN'}: return 'INCONCLUSIVE'
    return 'WARN' if 'WARN' in statuses else 'PASS'
class Run:
    def __init__(self,stage):
        os.umask(0o077); self.stage=stage; self.rid=os.getenv('CPU_VALIDATION_RUN_ID') or new_id(); self.path=BASE/'runs'/self.rid; self.e=self.path/'evidence'; self.e.mkdir(parents=True); (BASE/'logs').mkdir(exist_ok=True); self.cases=[]; self.log('START '+stage)
    def log(self,msg):
        msg=clean_text(f'{now()} [{self.rid}] {msg}'); print(msg,flush=True)
        for p in (self.path/'progress.log',BASE/'logs/live.log'):
            with p.open('a') as f:f.write(msg+'\n')
    def dump(self,name,obj): write_json(self.path/name,obj)
    def case(self,id,name,status,expected,actual):
        self.cases.append(dict(id=id,name=name,status=status,expected=expected,actual=actual,reason=f'expected={expected}; actual={actual}')); self.log(f'{id} {status}: {name}: {actual}')
    def run(self,label,cmd,root=False,timeout=25):
        self.log('START '+label); t=time.monotonic(); start=now(); out=err=''; rc=None
        try:
            r=execute(cmd,root,timeout); rc,out,err=r.returncode,r.stdout,r.stderr
        except subprocess.TimeoutExpired as e: out=e.stdout or ''; err=clean_text(e.stderr or '')+'\nTIMEOUT'
        except Exception as e: err=str(e)
        for k,x in [('stdout',out),('stderr',err)]: (self.e/(label+'.'+k)).write_text(clean_text(x))
        rec=dict(label=label,command=cmd,start=start,end=now(),elapsed_s=round(time.monotonic()-t,3),exit_code=rc,stdout_file=f'evidence/{label}.stdout',stderr_file=f'evidence/{label}.stderr')
        with (self.path/'execution.jsonl').open('a') as f:f.write(json.dumps(structured(rec),ensure_ascii=False)+'\n')
        self.log(f'END {label}: exit={rc}'); return rc,out.strip() if isinstance(out,str) else ''
    def finish(self):
        status=overall(self.cases); self.dump('result.json',dict(stage=self.stage,run_id=self.rid,overall=status,cases=self.cases)); (self.path/'report.md').write_text(clean_text(f'# {self.stage} {status}\n\n'+'\n'.join(f"- {c['id']} {c['status']} {c['name']}: {c['actual']}" for c in self.cases)+'\n')); self.log(f'FINISH {status}; evidence directory: {self.path}'); seal(self.path); return 0 if status=='PASS' else 2 if status=='WARN' else 1
