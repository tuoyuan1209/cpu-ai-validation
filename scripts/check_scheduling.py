#!/usr/bin/env python3
"""CPU-05 scheduling isolation; bounded sampling; policy-authorized VM start only."""
import csv, datetime as dt, hashlib, json, os, re, shlex, subprocess, sys, time, uuid
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml
BASE=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(BASE))
from common.policy import structured, validate, verify_only, workers
from common.transport import guest_ssh
os.umask(0o077)
RID=os.environ.get('CPU_VALIDATION_RUN_ID') or dt.datetime.now(dt.timezone.utc).strftime('run-%Y%m%dT%H%M%SZ-')+uuid.uuid4().hex[:8]
RUN=BASE/'runs'/RID; E=RUN/'evidence'; E.mkdir(parents=True); (BASE/'logs').mkdir(exist_ok=True)
SECRET=os.environ.get('SUT_SUDO_PASSWORD',''); CASES=[]; SSH=[]; ENV={}
def now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def safe(s):
    if isinstance(s,bytes): s=s.decode(errors='replace')
    for k in ('SUT_SUDO_PASSWORD','SUT_SSH_PASSWORD'):
        v=os.environ.get(k,'')
        if v: s=s.replace(v,'[REDACTED]')
    return s
def log(s):
    line=safe(f'{now()} [{RID}] {s}'); print(line,flush=True)
    for p in (RUN/'progress.log',BASE/'logs/live.log'):
        with p.open('a') as f: f.write(line+'\n')
def dump(name,obj): (RUN/name).write_text(json.dumps(structured(obj),ensure_ascii=False,indent=2)+'\n')
def case(i,name,status,expected,actual):
    CASES.append(dict(id=i,name=name,status=status,expected=str(expected),actual=str(actual),reason=f'expected={expected}; actual={actual}')); log(f'{i} {status}: {name}: {actual}')
def run(label,cmd,root=False):
    if root and ('\n' in SECRET or '\r' in SECRET): return None,''
    if root: cmd=('sudo -k -S -p ""' if SECRET else 'sudo -n')+' -- sh -c '+shlex.quote(cmd)
    argv=SSH+[cmd]; start=now(); t=time.monotonic(); rc=None; out=err=''; timed=False; log('START '+label)
    try:
        p=subprocess.run(argv,input=SECRET+'\n' if root and SECRET else '',text=True,capture_output=True,timeout=80,env={k:v for k,v in os.environ.items() if k not in ('SUT_SUDO_PASSWORD','SUT_SSH_PASSWORD')}); rc,out,err=p.returncode,p.stdout,p.stderr
    except subprocess.TimeoutExpired as ex: timed=True; out=ex.stdout or ''; err=ex.stderr or ''
    except OSError as ex: err=str(ex)
    for ext,data in [('stdout',out),('stderr',err)]: (E/f'{label}.{ext}').write_text(safe(data))
    rec=dict(label=label,argv=argv,start=start,end=now(),elapsed_s=round(time.monotonic()-t,3),exit_code=rc,timeout=timed,stdout_file=f'evidence/{label}.stdout',stderr_file=f'evidence/{label}.stderr')
    with (RUN/'execution.jsonl').open('a') as f: f.write(json.dumps(structured(rec),ensure_ascii=False)+'\n')
    log(f'END {label}: exit={rc}, timeout={timed}'); return rc,out.strip() if isinstance(out,str) else ''
def cpus(s):
    result=set()
    for part in s.strip().split(','):
        if not part: continue
        if not re.fullmatch(r'\d+(?:-\d+)?',part): raise ValueError('Unsupported CPU list: '+part)
        a=list(map(int,part.split('-')))
        if a[-1]<a[0] or a[-1]>1048575: raise ValueError('Invalid CPU range')
        result.update(range(a[0],a[-1]+1))
    return result
def mask(s):
    n=int(s.replace(',','').strip(),16); return {i for i in range(n.bit_length()) if n>>i&1}
def compare(i,name,rc,actual,expected,parse=lambda x:x):
    try: status='PASS' if rc==0 and parse(actual)==parse(expected) else 'FAIL' if rc==0 else 'INCONCLUSIVE'
    except (ValueError,TypeError): status='INCONCLUSIVE'
    case(i,name,status,expected,actual if rc==0 else '采集失败，查看证据')
PROBE = r"""
import ctypes, json, multiprocessing as mp, os, sys, time

def worker(idx, seconds, busy, start, queue):
    libc=ctypes.CDLL(None); libc.sched_getcpu.restype=ctypes.c_int
    allowed=sorted(os.sched_getaffinity(0)); start.wait(10)
    end=time.monotonic()+seconds; counts={}; begin=time.monotonic(); cpu_start=time.process_time()
    while time.monotonic()<end:
        c=libc.sched_getcpu()
        if c<0: raise RuntimeError('sched_getcpu failed')
        counts[c]=counts.get(c,0)+1
        if busy:
            for i in range(4000): x=i*i
        else: time.sleep(.01)
    queue.put(dict(index=idx,pid=os.getpid(),allowed=allowed,counts=counts,elapsed=time.monotonic()-begin,cpu_seconds=time.process_time()-cpu_start))
if __name__=='__main__':
    n=int(sys.argv[1]); seconds=int(sys.argv[2]); busy=bool(int(sys.argv[3])); event=mp.Event(); q=mp.Queue(); workers=[]
    try:
        for i in range(n):
            p=mp.Process(target=worker,args=(i,seconds,busy,event,q)); p.start(); workers.append(p)
        event.set(); rows=[q.get(timeout=seconds+8) for _ in workers]
        for p in workers: p.join(3)
        if any(p.exitcode!=0 for p in workers): raise RuntimeError('worker failed')
        print(json.dumps(rows))
    finally:
        for p in workers:
            if p.is_alive(): p.terminate()
            p.join(2)
"""
GUEST = r"""
import json, subprocess, time, sys

def stat():
    with open('/proc/stat') as f:
        a=list(map(int,next(f).split()[1:9])); return sum(a),a[3]+a[4]+a[7]
p=subprocess.Popen(['stress-ng','--cpu',sys.argv[1],'--cpu-method','matrixprod','--cpu-load','100','--timeout','32s','--metrics-brief'], stdout=sys.stderr, stderr=sys.stderr)
try:
    time.sleep(3)
    if p.poll() is not None: raise RuntimeError('stress exited before ready')
    a,b=stat(); print('READY',flush=True); time.sleep(18); c,d=stat()
    if p.poll() is not None: raise RuntimeError('stress exited during window')
    print('GUEST_BUSY '+json.dumps({'busy_fraction':1-(d-b)/(c-a),'ticks':c-a}),flush=True)
    if p.wait(timeout=15)!=0: raise RuntimeError('stress failed')
finally:
    if p.poll() is None: p.terminate(); p.wait(timeout=5)
"""
HOST_GUEST = r"""
import json, queue, threading, subprocess, sys, time
ssh_cmd=json.loads(sys.argv[1]); probe=json.loads(sys.argv[2]); p=subprocess.Popen(ssh_cmd,stdout=subprocess.PIPE,stderr=None,text=True,bufsize=1)
try:
    messages=queue.Queue()
    def reader():
        for line in p.stdout: messages.put(line)
        messages.put(None)
    threading.Thread(target=reader,daemon=True).start()
    deadline=time.monotonic()+18
    while True:
        try: line=messages.get(timeout=max(0,deadline-time.monotonic()))
        except queue.Empty: raise RuntimeError('guest READY timeout')
        if line is None: raise RuntimeError(f'guest stdout closed before READY; exit={p.poll()}')
        print('guest startup: '+line.rstrip(),file=sys.stderr,flush=True)
        if line.strip()=='READY': break
        if time.monotonic()>=deadline: raise RuntimeError('guest READY timeout')
    started=time.monotonic(); q=subprocess.run(probe,capture_output=True,text=True,timeout=20)
    elapsed=time.monotonic()-started
    if q.returncode: raise RuntimeError(q.stderr)
    print('host probe: '+q.stdout,file=sys.stderr,flush=True)
    out=[]; deadline=time.monotonic()+30
    while True:
        try: line=messages.get(timeout=max(0,deadline-time.monotonic()))
        except queue.Empty: raise RuntimeError('guest output timeout')
        if line is None: break
        out.append(line); print('guest output: '+line.rstrip(),file=sys.stderr,flush=True)
    p.wait(timeout=5)
    out=''.join(out)
    if p.returncode: raise RuntimeError('guest load failed')
    lines=[x for x in out.splitlines() if x.startswith('GUEST_BUSY ')]
    if len(lines)!=1: raise RuntimeError('guest utilization unavailable')
    print(json.dumps({'rows':json.loads(q.stdout),'guest':json.loads(lines[0][11:]),'probe_elapsed':elapsed}))
finally:
    if p.poll() is None: p.terminate(); p.wait(timeout=5)
"""
def inspect_rows(rows,n,seconds,allowed,require_broad=False):
    if not isinstance(rows,list) or len(rows)!=n or {r['index'] for r in rows}!=set(range(n)): raise ValueError('worker count mismatch')
    counts={}; masks=[]; cpu_time=0
    for row in rows:
        m=set(row['allowed']); masks.append(sorted(m)); cpu_time+=row['cpu_seconds']
        if not m or row['elapsed']<seconds*.95 or not row['counts'] or (require_broad and not allowed<=m): raise ValueError('incomplete sample or insufficient affinity coverage')
        for k,v in row['counts'].items():
            c=int(k)
            if c not in m or not isinstance(v,int) or v<=0: raise ValueError('invalid sampling evidence')
            counts[c]=counts.get(c,0)+v
    return counts,masks,cpu_time

def main():
    global SSH
    cfg=yaml.safe_load((BASE/'config.yaml').read_text()); policy=validate(yaml.safe_load((BASE/'isolation_policy.yaml').read_text()),load=True); verify_only(); a=cfg.get('auth') or {}; host=str(cfg['host']); user=str(cfg['ssh_user']); port=int(cfg.get('ssh_port',22)); key=Path(a.get('ssh_key') or cfg.get('ssh_key') or '~/.ssh/id_ed25519').expanduser()
    if not key.is_file() or not re.fullmatch(r'[A-Za-z0-9_.:-]+',host) or host.startswith('-') or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',user): raise ValueError('Invalid SSH configuration')
    SSH=['ssh','-T','-i',str(key),'-p',str(port),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ConnectionAttempts=1',user+'@'+host]
    iso=cpus(str(policy['isolated_cpus'])); hk=cpus(str(policy['housekeeping_cpus'])); online=cpus(str(policy['online_cpus'])); test=int(policy['test_cpu']); vm=str(policy['vm']['name']); n=workers(policy,'scheduling_workers'); gn=workers(policy,'guest_cpu_workers'); ENV.update(host=host,user=user,expected=policy,worker_counts=[1,n,n],durations=[3,5,10],guest_busy_threshold=.5)
    r,o=run('identity','hostname && whoami && uname -r'); lines=o.splitlines()
    if r!=0 or len(lines)!=3 or lines[1]!=user: raise RuntimeError('SSH identity verification failed')
    r,o=run('baseline','cat /sys/devices/system/cpu/online /sys/devices/system/cpu/isolated; grep Cpus_allowed_list /proc/self/status')
    lines=o.splitlines()
    if r!=0 or len(lines)!=3 or cpus(lines[0])!=online or cpus(lines[1])!=iso or hk&iso or hk|iso!=online or test not in iso: raise RuntimeError('CPU baseline mismatch')
    ENV['inherited_affinity']=lines[2]; ENV['script_version']='3'; ENV['script_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(); ENV['broad_probe_note']='Temporary explicit widening; observations do not prove scheduler domain isolation independently.'
    def argv(n,s,b): return ['python3','-c',PROBE,str(n),str(s),str(int(b))]
    def sample(cid,n,s,b,explicit=False,broad=False):
        expected={test} if explicit else hk; cmd=argv(n,s,b)
        if explicit: cmd=['taskset','-c',str(test)]+cmd
        elif broad: cmd=['taskset','-c',','.join(map(str,sorted(online)))]+cmd
        r,o=run(cid.lower(),shlex.join(cmd))
        try:
            if r!=0: raise ValueError('remote probe failed')
            rows=json.loads(o); counts,masks,ct=inspect_rows(rows,n,s,online,broad)
            bad=set(counts)-expected; valid=not explicit or all(set(m)==expected for m in masks)
            # Busy phase must actually consume CPU; no claim of full saturation.
            if b and ct<s*len(hk)*.8: raise ValueError('insufficient CPU activity for high-load phase')
            dump('evidence/'+cid.lower()+'_metrics.json',dict(group=cid,condition='explicit_pin' if explicit else 'broad_affinity' if broad else 'default_busy' if b else 'default',workers=n,planned_seconds=s,cpu_samples=counts,total_samples=sum(counts.values()),isolated_samples=sum(v for k,v in counts.items() if k in iso),expected_cpu_samples=sum(v for k,v in counts.items() if k in expected),cpu_seconds=ct,affinity_masks=masks,measurement='samples, not exhaustive migration events'))
            case(cid,'显式绑定对照' if explicit else '扩大亲和性探索采样' if broad else '默认环境实际调度采样','PASS' if not bad and valid else 'WARN' if broad else 'FAIL',f'CPU {sorted(expected)}; {n} workers; {s}s',f'counts={counts}; allowed={masks}; cpu_seconds={ct:.2f}')
            return counts
        except (ValueError,KeyError,TypeError) as e:
            case(cid,'实际调度采样','INCONCLUSIVE',f'{n} workers; {s}s',str(e)); return None
    batches=[sample('SCH01',1,3,False),sample('SCH02',n,5,False),sample('SCH03',n,10,True)]
    intrusion=sum(v for d in batches if d is not None for c,v in d.items() if c in iso)
    case('SCH04','隔离核心侵入统计','FAIL' if intrusion else 'INCONCLUSIVE' if any(d is None for d in batches) else 'PASS','0次采样',f'{intrusion}次；有效阶段={sum(d is not None for d in batches)}/3')
    sample('SCH05',1,3,False,True)
    sample('SCH07',1,3,False,broad=True)
    sample('SCH08',n,10,True,broad=True)
    try:
        inner=guest_ssh(run,policy)+[shlex.join(['python3','-c',GUEST,str(gn)])]
        r,o=run('sch06',shlex.join(['python3','-c',HOST_GUEST,json.dumps(inner),json.dumps(argv(n,10,True))]))
        if r!=0: raise ValueError('guest workload or host sampling failed; inspect stdout/stderr')
        d=json.loads(o); counts,masks,ct=inspect_rows(d['rows'],n,10,online,False); busy=float(d['guest']['busy_fraction'])
        if not 0.5<=busy<=1 or d['probe_elapsed']>17 or ct<5: raise ValueError(f'insufficient overlapping workload evidence: {d["guest"]}; elapsed={d["probe_elapsed"]}')
        dump('evidence/sch06_metrics.json',dict(group='SCH06',condition='host_guest',workers=n,planned_seconds=10,elapsed_s=d['probe_elapsed'],cpu_samples=counts,total_samples=sum(counts.values()),isolated_samples=sum(v for k,v in counts.items() if k in iso),cpu_seconds=ct,guest_busy=busy,affinity_masks=masks,measurement='samples, not exhaustive migration events'))
        case('SCH06','KVM负载下普通任务调度','PASS' if set(counts)<=hk else 'FAIL','普通任务仅在housekeeping CPU；guest busy >=50%',f'counts={counts}; guest_busy={busy:.1%}; host_cpu_seconds={ct:.2f}')
    except (ValueError,KeyError,TypeError) as e: case('SCH06','KVM负载下普通任务调度','INCONCLUSIVE','有效并发负载证据',str(e))
log('START CPU-05 scheduling isolation verification')
try: main()
except Exception as e: log('ERROR '+str(e))
finally:
    for i in range(1,9):
        cid=f'SCH{i:02d}'
        if not any(c['id']==cid for c in CASES): case(cid,'未执行项目','NOT_EXECUTED','完成检查','前置条件失败')
    overall='FAIL' if any(c['status']=='FAIL' for c in CASES) else 'INCONCLUSIVE' if any(c['status'] in ('INCONCLUSIVE','NOT_EXECUTED') for c in CASES) else 'WARN' if any(c['status']=='WARN' for c in CASES) else 'PASS'
    dump('environment.json',ENV); dump('result.json',dict(run_id=RID,stage='CPU-05',overall=overall,cases=CASES)); dump('test_cases.json',[{k:c[k] for k in ('id','name','expected')} for c in CASES])
    with (RUN/'result.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(CASES[0])); w.writeheader(); w.writerows(CASES)
    (RUN/'report.md').write_text(safe(f'# CPU-05 普通任务调度隔离验证\n\nRun: {RID}\n\nOverall: {overall}\n\n'+'\n'.join(f"- {c['id']} {c['name']}: {c['status']} — {c['reason']}" for c in CASES)+'\n\n虚拟机若由本任务启动，将保持运行供后续测试使用。SCH01–04及06验证默认环境；SCH07–08为临时扩大亲和性后的探索测试，观察到侵入记WARN，不等同于isolcpus失效。有限采样仅覆盖本次测试任务，不证明系统所有线程无侵入；不代表实时延迟达标。\n'))
    log(f'FINISH {overall}; evidence directory: {RUN}')
    (RUN/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(RUN)}\n' for p in sorted(RUN.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'))
    sys.exit(0 if overall=='PASS' else 2 if overall=='WARN' else 1)
