#!/usr/bin/env python3
"""CPU-04 runtime affinity verification; bounded probe, no persistent changes."""
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
        p=subprocess.run(argv,input=SECRET+'\n' if root else '',text=True,capture_output=True,timeout=25,env={k:v for k,v in os.environ.items() if k not in ('SUT_SUDO_PASSWORD','SUT_SSH_PASSWORD')}); rc,out,err=p.returncode,p.stdout,p.stderr
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
def main():
    global SSH
    cfg=yaml.safe_load((BASE/'config.yaml').read_text()); policy=yaml.safe_load((BASE/'isolation_policy.yaml').read_text()); a=cfg.get('auth') or {}; host=str(cfg['host']); user=str(cfg['ssh_user']); port=int(cfg.get('ssh_port',22)); key=Path(a.get('ssh_key') or cfg.get('ssh_key') or '~/.ssh/id_ed25519').expanduser()
    if not key.is_file() or not re.fullmatch(r'[A-Za-z0-9_.:-]+',host) or host.startswith('-') or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',user): raise ValueError('Invalid SSH configuration')
    SSH=['ssh','-T','-i',str(key),'-p',str(port),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ConnectionAttempts=1',user+'@'+host]
    test=int(policy['test_cpu']); iso=cpus(str(policy['isolated_cpus'])); hk=cpus(str(policy['housekeeping_cpus'])); vm=policy['vm']; name=str(vm['name']); pins={int(k):cpus(str(v)) for k,v in vm['vcpu_pinning'].items()}; em=cpus(str(vm['emulator_cpus'])); ENV.update(host=host,user=user,expected=policy)
    r,o=run('identity','hostname && whoami && uname -r'); lines=o.splitlines()
    if r!=0 or len(lines)!=3 or lines[1]!=user: raise RuntimeError('SSH identity verification failed')
    r,on=run('online','cat /sys/devices/system/cpu/online'); rr,isol=run('isolated','cat /sys/devices/system/cpu/isolated')
    if r!=0 or rr!=0 or test not in cpus(on)&cpus(isol) or cpus(isol)!=iso or not hk or hk&iso: raise RuntimeError('CPU baseline mismatch')
    probe='import os,time,json,ctypes\nlibc=ctypes.CDLL(None); libc.sched_getcpu.restype=ctypes.c_int\nallowed=sorted(os.sched_getaffinity(0)); samples=[]\nfor i in range(100):\n    samples.append(libc.sched_getcpu()); time.sleep(.01)\nprint(json.dumps(dict(pid=os.getpid(),allowed=allowed,samples=samples)))'
    for cid,cpu in [('AFF01',test),('AFF02',min(hk))]:
        r,o=run(cid.lower(),f'taskset -c {cpu} python3 -c '+shlex.quote(probe))
        try:
            d=json.loads(o); valid=r==0 and len(d['samples'])==100 and all(isinstance(x,int) and x>=0 for x in d['samples']); ok=set(d['allowed'])=={cpu} and set(d['samples'])=={cpu}
            case(cid,'显式CPU绑定与运行采样','PASS' if valid and ok else 'FAIL' if valid else 'INCONCLUSIVE',f'CPU {cpu}; 100次采样',f'允许={d["allowed"]}; 实际={sorted(set(d["samples"]))}; 样本={len(d["samples"])}')
        except (ValueError,KeyError,TypeError): case(cid,'显式CPU绑定与运行采样','INCONCLUSIVE',cpu,'采集失败')
    q=shlex.quote(name); v='LC_ALL=C virsh -c qemu:///system '
    r,state=run('vm_state',v+'domstate '+q,True)
    if r!=0 or state!='running': raise RuntimeError('VM not running or unavailable; no automatic start in CPU-04')
    # QMP provides actual vCPU thread IDs; verify Linux /proc masks independently.
    r,o=run('qmp_vcpus',v+'qemu-monitor-command '+q+' '+shlex.quote('{"execute":"query-cpus-fast"}'),True)
    if r!=0: raise RuntimeError('QMP unavailable')
    rows=json.loads(o)['return']; tids={int(x['cpu-index']):int(x['thread-id']) for x in rows}
    if set(tids)!=set(pins) or len(set(tids.values()))!=len(tids) or any(t<=0 for t in tids.values()): raise RuntimeError('Unexpected QMP vCPU mapping')
    cmd='; '.join(f'printf "TID {t}\\n"; grep -E "^(Tgid|Cpus_allowed_list):" /proc/{t}/status || exit 1' for t in tids.values())
    r,o=run('vcpu_proc_status',cmd,True)
    entries=re.findall(r'TID (\d+)\s+Tgid:\s*(\d+)\s+Cpus_allowed_list:\s*([0-9,-]+)',o)
    masks={int(t):cpus(m) for t,g,m in entries}; groups={int(g) for t,g,m in entries}
    valid=r==0 and set(masks)==set(tids.values()) and len(groups)==1
    actual={i:sorted(masks[t]) for i,t in tids.items() if t in masks}
    case('AFF03','KVM vCPU实际线程亲和性','PASS' if valid and all(masks[t]==pins[i] for i,t in tids.items()) else 'FAIL' if valid else 'INCONCLUSIVE', {i:sorted(x) for i,x in pins.items()},actual)
    if not valid: raise RuntimeError('Cannot identify QEMU process')
    pid=next(iter(groups)); r,o=run('qemu_threads',f'for f in /proc/{pid}/task/*/status; do printf "TID %s\\n" "$(basename "$(dirname "$f")")"; grep -E "^(Name|Cpus_allowed_list):" "$f" || exit 1; done',True)
    entries=re.findall(r'TID (\d+)\s+Name:\s*([^\n]+)\s+Cpus_allowed_list:\s*([0-9,-]+)',o)
    other={int(t):(n,cpus(m)) for t,n,m in entries if int(t) not in tids.values()}; valid=r==0 and pid in other and bool(other)
    bad={t:(n,sorted(m)) for t,(n,m) in other.items() if not m or not m<=em}
    case('AFF04','QEMU非vCPU线程亲和性','PASS' if valid and not bad else 'WARN' if valid else 'INCONCLUSIVE',f'非vCPU线程允许范围属于{sorted(em)}',f'线程数={len(other)}; 超范围={bad}')
    r,o=run('qemu_thread_snapshot',f'ps -L -p {pid} -o pid,tid,psr,cls,rtprio,comm',True)
    case('AFF05','QEMU线程运行快照','PASS' if r==0 and o else 'INCONCLUSIVE','成功采集PSR快照','已采集（仅最近运行CPU，不证明持续绑定）' if r==0 and o else '采集失败')
log('START CPU-04 runtime affinity verification')
try: main()
except Exception as e: log('ERROR '+str(e))
finally:
    for i in range(1,6):
        cid=f'AFF{i:02d}'
        if not any(c['id']==cid for c in CASES): case(cid,'未执行项目','NOT_EXECUTED','完成检查','前置条件失败')
    overall='FAIL' if any(c['status']=='FAIL' for c in CASES) else 'INCONCLUSIVE' if any(c['status'] in ('INCONCLUSIVE','NOT_EXECUTED') for c in CASES) else 'WARN' if any(c['status']=='WARN' for c in CASES) else 'PASS'
    dump('environment.json',ENV); dump('result.json',dict(run_id=RID,stage='CPU-04',overall=overall,cases=CASES)); dump('test_cases.json',[{k:c[k] for k in ('id','name','expected')} for c in CASES])
    with (RUN/'result.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(CASES[0])); w.writeheader(); w.writerows(CASES)
    (RUN/'report.md').write_text(safe(f'# CPU-04 实际线程亲和性验证\n\nRun: {RID}\n\nOverall: {overall}\n\n'+'\n'.join(f"- {c['id']} {c['name']}: {c['status']} — {c['reason']}" for c in CASES)+'\n\n短时采样与实际线程允许掩码验证，不代表持续运行、调度隔离或延迟达标。\n'))
    log(f'FINISH {overall}; evidence directory: {RUN}')
    (RUN/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(RUN)}\n' for p in sorted(RUN.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'))
    sys.exit(0 if overall=='PASS' else 2 if overall=='WARN' else 1)
