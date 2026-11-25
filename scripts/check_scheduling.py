#!/usr/bin/env python3
"""CPU-05 scheduling isolation; bounded sampling; policy-authorized VM start only."""
import csv, datetime as dt, hashlib, json, os, re, shlex, subprocess, sys, time, uuid
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml
BASE=Path(__file__).resolve().parent.parent
os.umask(0o077)
RID=dt.datetime.now(dt.timezone.utc).strftime('run-%Y%m%dT%H%M%SZ-')+uuid.uuid4().hex[:8]
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
def dump(name,obj): (RUN/name).write_text(safe(json.dumps(obj,ensure_ascii=False,indent=2))+'\n')
def case(i,name,status,expected,actual):
    CASES.append(dict(id=i,name=name,status=status,expected=str(expected),actual=str(actual),reason=f'expected={expected}; actual={actual}')); log(f'{i} {status}: {name}: {actual}')
def run(label,cmd,root=False):
    if root and (not SECRET or '\n' in SECRET or '\r' in SECRET): return None,''
    if root: cmd='sudo -k -S -p "" -- sh -c '+shlex.quote(cmd)
    argv=SSH+[cmd]; start=now(); t=time.monotonic(); rc=None; out=err=''; timed=False; log('START '+label)
    try:
        p=subprocess.run(argv,input=SECRET+'\n' if root else '',text=True,capture_output=True,timeout=65,env={k:v for k,v in os.environ.items() if k not in ('SUT_SUDO_PASSWORD','SUT_SSH_PASSWORD')}); rc,out,err=p.returncode,p.stdout,p.stderr
    except subprocess.TimeoutExpired as ex: timed=True; out=ex.stdout or ''; err=ex.stderr or ''
    except OSError as ex: err=str(ex)
    for ext,data in [('stdout',out),('stderr',err)]: (E/f'{label}.{ext}').write_text(safe(data))
    rec=dict(label=label,argv=argv,start=start,end=now(),elapsed_s=round(time.monotonic()-t,3),exit_code=rc,timeout=timed,stdout_file=f'evidence/{label}.stdout',stderr_file=f'evidence/{label}.stderr')
    with (RUN/'execution.jsonl').open('a') as f: f.write(safe(json.dumps(rec))+'\n')
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
import json, subprocess, time

def stat():
    with open('/proc/stat') as f:
        a=list(map(int,next(f).split()[1:9])); return sum(a),a[3]+a[4]
p=subprocess.Popen(['stress-ng','--cpu','4','--cpu-method','matrixprod','--cpu-load','100','--timeout','24s','--metrics-brief'])
try:
    time.sleep(3)
    if p.poll() is not None: raise RuntimeError('stress exited before ready')
    a,b=stat(); print('READY',flush=True); time.sleep(12); c,d=stat()
    if p.poll() is not None: raise RuntimeError('stress exited during window')
    print('GUEST_BUSY '+json.dumps({'busy_fraction':1-(d-b)/(c-a),'ticks':c-a}),flush=True)
    if p.wait(timeout=15)!=0: raise RuntimeError('stress failed')
finally:
    if p.poll() is None: p.terminate(); p.wait(timeout=5)
"""
HOST_GUEST = r"""
import json, select, subprocess, sys, time
ssh_cmd=json.loads(sys.argv[1]); probe=json.loads(sys.argv[2]); p=subprocess.Popen(ssh_cmd,stdout=subprocess.PIPE,stderr=None,text=True,bufsize=1)
try:
    ready,_,_=select.select([p.stdout],[],[],12)
    if not ready or p.stdout.readline().strip()!='READY': raise RuntimeError('guest not ready')
    started=time.monotonic(); q=subprocess.run(probe,capture_output=True,text=True,timeout=20)
    elapsed=time.monotonic()-started
    if q.returncode: raise RuntimeError(q.stderr)
    out,_=p.communicate(timeout=22)
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
    cfg=yaml.safe_load((BASE/'config.yaml').read_text()); policy=yaml.safe_load((BASE/'isolation_policy.yaml').read_text()); a=cfg.get('auth') or {}; host=str(cfg['host']); user=str(cfg['ssh_user']); port=int(cfg.get('ssh_port',22)); key=Path(a.get('ssh_key') or cfg.get('ssh_key') or '~/.ssh/id_ed25519').expanduser()
    if not key.is_file() or not re.fullmatch(r'[A-Za-z0-9_.:-]+',host) or host.startswith('-') or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',user): raise ValueError('Invalid SSH configuration')
    SSH=['ssh','-T','-i',str(key),'-p',str(port),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ConnectionAttempts=1',user+'@'+host]
    iso=cpus(str(policy['isolated_cpus'])); hk=cpus(str(policy['housekeeping_cpus'])); online=cpus(str(policy['online_cpus'])); test=int(policy['test_cpu']); vm=str(policy['vm']['name']); ENV.update(host=host,user=user,expected=policy,worker_counts=[1,8,8],durations=[3,5,10],guest_busy_threshold=.5)
    r,o=run('identity','hostname && whoami && uname -r'); lines=o.splitlines()
    if r!=0 or len(lines)!=3 or lines[1]!=user: raise RuntimeError('SSH identity verification failed')
    r,o=run('baseline','cat /sys/devices/system/cpu/online /sys/devices/system/cpu/isolated; grep Cpus_allowed_list /proc/self/status')
    lines=o.splitlines()
    if r!=0 or len(lines)!=3 or cpus(lines[0])!=online or cpus(lines[1])!=iso or hk&iso or hk|iso!=online or test not in iso: raise RuntimeError('CPU baseline mismatch')
    ENV['inherited_affinity']=lines[2]
    def argv(n,s,b): return ['python3','-c',PROBE,str(n),str(s),str(int(b))]
    def sample(cid,n,s,b,explicit=False):
        expected={test} if explicit else hk; cmd=argv(n,s,b)
        if explicit: cmd=['taskset','-c',str(test)]+cmd
        r,o=run(cid.lower(),shlex.join(cmd))
        try:
            if r!=0: raise ValueError('remote probe failed')
            rows=json.loads(o); counts,masks,ct=inspect_rows(rows,n,s,online,not explicit)
            bad=set(counts)-expected; valid=not explicit or all(set(m)==expected for m in masks)
            # Busy phase must actually consume CPU; no claim of full saturation.
            if b and ct<s*.5: raise ValueError('insufficient CPU activity')
            case(cid,'显式绑定对照' if explicit else '普通任务实际调度采样','PASS' if not bad and valid else 'FAIL',f'CPU {sorted(expected)}; {n} workers; {s}s',f'counts={counts}; allowed={masks}; cpu_seconds={ct:.2f}')
            return counts
        except (ValueError,KeyError,TypeError) as e:
            case(cid,'实际调度采样','INCONCLUSIVE',f'{n} workers; {s}s',str(e)); return None
    batches=[sample('SCH01',1,3,False),sample('SCH02',8,5,False),sample('SCH03',8,10,True)]
    intrusion=sum(v for d in batches if d is not None for c,v in d.items() if c in iso)
    case('SCH04','隔离核心侵入统计','FAIL' if intrusion else 'INCONCLUSIVE' if any(d is None for d in batches) else 'PASS','0次采样',f'{intrusion}次；有效阶段={sum(d is not None for d in batches)}/3')
    sample('SCH05',1,3,False,True)
    try:
        q=shlex.quote(vm); v='LC_ALL=C virsh -c qemu:///system '
        r,o=run('vm_state',v+'domstate '+q,True)
        if r!=0: raise ValueError('VM state unavailable')
        ENV['vm_initial_state']=o
        if o=='shut off':
            pp=BASE/'provision_policy.yaml'
            permitted=pp.exists() and (yaml.safe_load(pp.read_text()).get('provision') or {}).get('auto_start_vm') is True
            if not permitted: raise ValueError('VM stopped; auto_start_vm not authorized')
            r,o=run('vm_start',v+'start '+q,True)
            if r!=0: raise ValueError('VM start failed; inspect vm_start evidence')
            ENV['vm_started_by_test']=True
        elif o!='running': raise ValueError('unsupported VM state: '+o)
        r,o=run('vm_state_ready',v+'domstate '+q,True)
        if r!=0 or o!='running': raise ValueError('VM not running after start')
        r,o=run('vm_interfaces',v+'domiflist '+q,True)
        macs=set(re.findall(r'(?im)^\s*\S+\s+network\s+default\s+\S+\s+([0-9a-f:]{17})\s*$',o))
        if r!=0 or len(macs)!=1: raise ValueError('cannot identify default network MAC')
        import ipaddress
        guest='tester'; p=BASE/'provision_policy.yaml'
        if p.exists(): guest=str((yaml.safe_load(p.read_text()).get('virtualization') or {}).get('guest_user','tester'))
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',guest): raise ValueError('invalid guest user')
        # Poll for a MAC-matched lease, with bounded per-attempt runtime.
        lease_cmd=v+'domifaddr '+q+' --source lease'
        r,o=run('guest_ip', 'for i in $(seq 1 20); do out=$(timeout 2s sh -c '+shlex.quote(lease_cmd)+'); printf "%s\\n" "$out"; printf "%s\\n" "$out" | grep -iF '+shlex.quote(next(iter(macs)))+' | grep -q ipv4 && exit 0; sleep 1; done; exit 1',True)
        ips=[]
        for line in o.splitlines():
            parts=line.split()
            if len(parts)>=4 and parts[1].lower() in {m.lower() for m in macs} and parts[2]=='ipv4': ips.append(str(ipaddress.IPv4Interface(parts[3]).ip))
        if r!=0 or len(set(ips))!=1: raise ValueError('guest IPv4 unavailable or ambiguous')
        ready=shlex.join(['timeout','4s','ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=3',guest+'@'+ips[0],'true'])
        r,o=run('guest_ssh_ready','for i in $(seq 1 10); do '+ready+' && exit 0; sleep 1; done; exit 1')
        if r!=0: raise ValueError('guest SSH not ready; inspect guest_ssh_ready evidence')
        inner=['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',guest+'@'+ips[0],shlex.join(['python3','-c',GUEST])]
        r,o=run('sch06',shlex.join(['python3','-c',HOST_GUEST,json.dumps(inner),json.dumps(argv(8,10,True))]))
        if r!=0: raise ValueError('guest workload or host sampling failed; inspect stdout/stderr')
        d=json.loads(o); counts,masks,ct=inspect_rows(d['rows'],8,10,online,True); busy=float(d['guest']['busy_fraction'])
        if not 0.5<=busy<=1 or d['probe_elapsed']>12 or ct<5: raise ValueError(f'insufficient overlapping workload evidence: {d["guest"]}; elapsed={d["probe_elapsed"]}')
        case('SCH06','KVM负载下普通任务调度','PASS' if set(counts)<=hk else 'FAIL','普通任务仅在housekeeping CPU；guest busy >=50%',f'counts={counts}; guest_busy={busy:.1%}; host_cpu_seconds={ct:.2f}')
    except (ValueError,KeyError,TypeError) as e: case('SCH06','KVM负载下普通任务调度','INCONCLUSIVE','有效并发负载证据',str(e))
log('START CPU-05 scheduling isolation verification')
try: main()
except Exception as e: log('ERROR '+str(e))
finally:
    for i in range(1,7):
        cid=f'SCH{i:02d}'
        if not any(c['id']==cid for c in CASES): case(cid,'未执行项目','NOT_EXECUTED','完成检查','前置条件失败')
    overall='FAIL' if any(c['status']=='FAIL' for c in CASES) else 'INCONCLUSIVE' if any(c['status'] in ('INCONCLUSIVE','NOT_EXECUTED') for c in CASES) else 'WARN' if any(c['status']=='WARN' for c in CASES) else 'PASS'
    dump('environment.json',ENV); dump('result.json',dict(run_id=RID,stage='CPU-05',overall=overall,cases=CASES)); dump('test_cases.json',[{k:c[k] for k in ('id','name','expected')} for c in CASES])
    with (RUN/'result.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(CASES[0])); w.writeheader(); w.writerows(CASES)
    (RUN/'report.md').write_text(safe(f'# CPU-05 普通任务调度隔离验证\n\nRun: {RID}\n\nOverall: {overall}\n\n'+'\n'.join(f"- {c['id']} {c['name']}: {c['status']} — {c['reason']}" for c in CASES)+'\n\n虚拟机若由本任务启动，将保持运行供后续测试使用。有限采样仅覆盖本次测试任务，不证明系统所有线程无侵入；不代表实时延迟达标。\n'))
    log(f'FINISH {overall}; evidence directory: {RUN}')
    (RUN/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(RUN)}\n' for p in sorted(RUN.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'))
    sys.exit(0 if overall=='PASS' else 2 if overall=='WARN' else 1)
