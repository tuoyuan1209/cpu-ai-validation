#!/usr/bin/env python3
"""CPU-06 IRQ isolation; bounded workloads; policy-authorized VM start only."""
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

import tempfile
from collections import Counter

GUEST_IRQ=r"""
import json, subprocess, sys, time

def stat():
    a=list(map(int,open('/proc/stat').readline().split()[1:9])); return sum(a),a[3]+a[4]+a[7]
p=subprocess.Popen(['stress-ng','--cpu',sys.argv[1],'--cpu-method','matrixprod','--cpu-load','100','--timeout','28s','--metrics-brief'],stdout=sys.stderr,stderr=sys.stderr)
try:
    time.sleep(2)
    if p.poll() is not None: raise RuntimeError('stress exited before READY')
    a,b=stat(); print('READY',flush=True); time.sleep(17); c,d=stat()
    if p.poll() is not None or c<=a: raise RuntimeError('guest load invalid')
    print('METRIC '+json.dumps({'busy':1-(d-b)/(c-a)}),flush=True)
    if p.wait(timeout=12)!=0: raise RuntimeError('stress failed')
finally:
    if p.poll() is None: p.terminate(); p.wait(timeout=5)
"""
# Each snapshot is taken on SUT, not on the OpenHands controller.
REMOTE=r"""
import json, os, queue, shlex, subprocess, sys, tempfile, threading, time
mode=sys.argv[1]; hk=sys.argv[2]; guest=json.loads(sys.argv[3]); seconds=60 if mode=='baseline' else 10

def snap():
    with open('/proc/interrupts') as f: return f.read()
def stat():
    return open('/proc/stat').read()
def emit(k,v): print(k+' '+json.dumps(v),flush=True)
def window():
    a=time.monotonic(); emit('BEFORE',snap()); emit('STAT_BEFORE',stat()); time.sleep(seconds); emit('AFTER',snap()); emit('STAT_AFTER',stat()); emit('ELAPSED',time.monotonic()-a)
def diskstats(): return open('/proc/diskstats').read()
def netstats(): return open('/proc/net/dev').read()
def io():
    # Limit writes to a private temporary file, never a block device.
    # Direct I/O is required; unsupported filesystems yield insufficient evidence.
    with tempfile.TemporaryDirectory(prefix='cpu06-') as d:
        path=os.path.join(d,'io.bin'); stop=time.monotonic()+13; written=0
        while time.monotonic()<stop:
            p=subprocess.run(['dd','if=/dev/zero','of='+path,'bs=1M','count=16','oflag=direct','conv=fdatasync','status=none'],capture_output=True,timeout=8)
            if p.returncode: raise RuntimeError(p.stderr.decode(errors='replace'))
            written+=16*1024*1024; time.sleep(.1)
        emit('IO_WRITTEN',written)
if mode=='diskworker': io(); sys.exit(0)
if mode=='networkworker':
    # Read existing /dev/zero on the guest via the established SSH link.
    # Bounded total bytes; no external target or listening service.
    p=subprocess.run(guest+['dd if=/dev/zero bs=1M count=128 status=none'],stdout=subprocess.DEVNULL,timeout=18)
    sys.exit(p.returncode)
if mode=='baseline': window(); sys.exit(0)
if mode=='host':
    p=subprocess.Popen(['taskset','-c',hk,'stress-ng','--cpu',sys.argv[4],'--cpu-method','matrixprod','--cpu-load','100','--timeout','17s','--metrics-brief'],stdout=sys.stderr,stderr=sys.stderr)
    try:
        time.sleep(2)
        if p.poll() is not None: raise RuntimeError('host load exited early')
        window()
        if p.poll() is not None: raise RuntimeError('host load ended during window')
        if p.wait(timeout=10)!=0: raise RuntimeError('host load failed')
    finally:
        if p.poll() is None: p.terminate(); p.wait(timeout=5)
elif mode=='guest':
    p=subprocess.Popen(guest,stdout=subprocess.PIPE,stderr=sys.stderr,text=True,bufsize=1)
    q=queue.Queue()
    def reader():
        for l in p.stdout: q.put(l)
        q.put(None)
    threading.Thread(target=reader,daemon=True).start()
    try:
        deadline=time.monotonic()+18
        while True:
            l=q.get(timeout=max(0,deadline-time.monotonic()))
            if l is None: raise RuntimeError('guest closed before READY')
            print('guest: '+l.rstrip(),file=sys.stderr,flush=True)
            if l.strip()=='READY': break
            if time.monotonic()>=deadline: raise RuntimeError('READY timeout')
        window(); deadline=time.monotonic()+25; metric=None
        while True:
            l=q.get(timeout=max(0,deadline-time.monotonic()))
            if l is None: break
            if l.startswith('METRIC '): metric=json.loads(l[7:])
        if p.wait(timeout=5)!=0 or metric is None: raise RuntimeError('guest workload failed')
        emit('GUEST',metric)
    finally:
        if p.poll() is None: p.terminate(); p.wait(timeout=5)
elif mode=='io':
    # Run both bounded workloads concurrently with the observation window.
    # Network transfer uses repeated 8 MiB SSH transfers until the deadline.
    code='import subprocess,time,sys,json\na=json.loads(sys.argv[1]); end=time.monotonic()+13; total=0\nwhile time.monotonic()<end:\n p=subprocess.run(a+["dd if=/dev/zero bs=1M count=8 status=none"],stdout=subprocess.DEVNULL,timeout=8)\n if p.returncode: raise RuntimeError("network transfer failed")\n total+=8*1024*1024; time.sleep(.15)\nprint(total,flush=True)'
    # Separate process; bounded timeout and no persistent writes outside tmp.
    disk_code='import os,subprocess,tempfile,time\nwith tempfile.TemporaryDirectory(prefix="cpu06-") as d:\n end=time.monotonic()+13; total=0\n while time.monotonic()<end:\n  subprocess.run(["dd","if=/dev/zero","of="+os.path.join(d,"io.bin"),"bs=1M","count=16","oflag=direct","conv=fdatasync","status=none"],check=True,timeout=8)\n  total+=16*1024*1024; time.sleep(.1)\n print(total,flush=True)'
    emit('NET_BEFORE',netstats()); emit('DISK_BEFORE',diskstats())
    ps=[]
    try:
        for a in ([sys.executable,'-c',disk_code],[sys.executable,'-c',code,json.dumps(guest)]): ps.append(subprocess.Popen(a,stdout=subprocess.PIPE,stderr=sys.stderr,text=True))
        time.sleep(1)
        if any(p.poll() is not None for p in ps): raise RuntimeError('I/O load exited early')
        window(); emit('NET_AFTER',netstats()); emit('DISK_AFTER',diskstats())
        if any(p.poll() is not None for p in ps): raise RuntimeError('I/O load ended during window')
        vals=[]
        for p in ps:
            out,_=p.communicate(timeout=14)
            if p.returncode: raise RuntimeError('I/O worker failed')
            vals.append(int(out.strip()))
        emit('IO',{'written_bytes':vals[0],'transferred_bytes':vals[1]})
    finally:
        for p in ps:
            if p.poll() is None: p.terminate(); p.wait(timeout=5)
"""

def parse_irq(raw):
    lines=raw.splitlines(); header=lines[0].split()
    if not header or any(not re.fullmatch(r'CPU\d+',c) for c in header): raise ValueError('invalid interrupt header')
    ids=[int(c[3:]) for c in header]; result={}
    if len(ids)!=len(set(ids)): raise ValueError('duplicate CPU')
    for line in lines[1:]:
        key,sep,tail=line.partition(':'); key=key.strip(); parts=tail.split()
        if not sep: continue
        if len(parts)<len(ids) or not all(x.isdigit() for x in parts[:len(ids)]):
            if key.isdigit(): raise ValueError('invalid device IRQ row '+key)
            continue # e.g. global ERR/MIS, not per-CPU counters
        result[key]={'counts':dict(zip(ids,map(int,parts[:len(ids)]))),'description':' '.join(parts[len(ids):])}
    if not any(k.isdigit() for k in result): raise ValueError('no device IRQ rows')
    return ids,result

def delta(before,after,online):
    a,x=parse_irq(before); b,y=parse_irq(after)
    if set(a)!=online or a!=b or set(x)!=set(y): raise ValueError('CPU/IRQ rows changed during window')
    rows={}
    for k in x:
        if x[k]['description']!=y[k]['description']: raise ValueError('IRQ description changed: '+k)
        d={c:y[k]['counts'][c]-x[k]['counts'][c] for c in a}
        if min(d.values())<0: raise ValueError('counter decreased: '+k)
        rows[k]={'counts':d,'description':y[k]['description'],'category':'device' if k.isdigit() else 'local_or_ipi'}
    return rows

def cpu_busy(a,b,hk):
    def read(s):
        d={}
        for l in s.splitlines():
            p=l.split()
            if p and re.fullmatch(r'cpu\d+',p[0]): d[int(p[0][3:])]=list(map(int,p[1:9]))
        return d
    x,y=read(a),read(b); total=idle=0
    for c in hk:
        z=[j-i for i,j in zip(x[c],y[c])]
        if len(z)!=8 or min(z)<0: raise ValueError('invalid CPU counters')
        total+=sum(z); idle+=z[3]+z[4]
    if total<=0: raise ValueError('invalid CPU ticks')
    return 1-idle/total

def main():
    global SSH
    cfg=yaml.safe_load((BASE/'config.yaml').read_text()); policy=validate(yaml.safe_load((BASE/'isolation_policy.yaml').read_text()),load=True); verify_only(); a=cfg.get('auth') or {}; host=str(cfg['host']); user=str(cfg['ssh_user']); port=int(cfg.get('ssh_port',22)); key=Path(a.get('ssh_key') or cfg.get('ssh_key') or '~/.ssh/id_ed25519').expanduser()
    if not key.is_file() or not re.fullmatch(r'[A-Za-z0-9_.:-]+',host) or host.startswith('-') or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',user): raise ValueError('Invalid SSH configuration')
    SSH=['ssh','-T','-i',str(key),'-p',str(port),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',user+'@'+host]
    iso=cpus(str(policy['isolated_cpus'])); hk=cpus(str(policy['housekeeping_cpus'])); online=cpus(str(policy['online_cpus'])); test=int(policy['test_cpu']); vm=str(policy['vm']['name']); ENV.update(host=host,user=user,expected=policy,script_version='2.0',script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),window_seconds=10,baseline_window_seconds=60,host_busy_threshold=.8,guest_busy_threshold=.5)
    r,o=run('identity','hostname && whoami && uname -r'); lines=o.splitlines()
    if r!=0 or len(lines)!=3 or lines[1]!=user: raise RuntimeError('SSH identity verification failed')
    ENV.update(hostname=lines[0],kernel=lines[2]); r,o=run('baseline','cat /sys/devices/system/cpu/online /sys/devices/system/cpu/isolated')
    if r!=0 or len(o.splitlines())!=2 or cpus(o.splitlines()[0])!=online or cpus(o.splitlines()[1])!=iso or hk&iso or hk|iso!=online or test not in iso: raise RuntimeError('CPU baseline mismatch')
    r,o=run('irq_default','cat /proc/irq/default_smp_affinity'); compare('IRQ01','默认IRQ亲和性',r,o,format(sum(1<<i for i in hk),'x'),mask)
    r,o=run('irq_effective','for f in /proc/irq/[0-9]*/effective_affinity_list; do [ -e "$f" ] || continue; printf "%s " "$f"; cat "$f" || exit 1; done'); rr,s=run('irq_devices','cat /proc/interrupts')
    try:
        if r!=0 or rr!=0: raise ValueError('IRQ evidence unavailable')
        ids,devices=parse_irq(s); hits=[]; n=0; inactive=[]; unknown=[]; seen=set()
        if set(ids)!=online: raise ValueError('IRQ CPU topology mismatch')
        for l in o.splitlines():
            parts=l.split(None,1)
            if not parts: continue
            m=re.fullmatch(r'/proc/irq/(\d+)/effective_affinity_list',parts[0])
            if not m: unknown.append({'raw':l,'reason':'invalid path'}); continue
            irq=m[1]; n+=1; v=parts[1].strip() if len(parts)>1 else ''
            if irq in seen: unknown.append({'irq':irq,'reason':'duplicate'}); continue
            seen.add(irq)
            row={'irq':irq,'effective':v,'device':devices.get(irq,{}).get('description','未在快照中找到')}
            if not v:
                (unknown if irq in devices else inactive).append(row); continue
            try: affinity=cpus(v)
            except ValueError: unknown.append(row); continue
            if not affinity or not affinity<=online: unknown.append(row); continue
            if affinity&iso: hits.append(row)
        for irq in devices:
            if irq.isdigit() and irq not in seen: unknown.append({'irq':irq,'reason':'missing affinity record','device':devices[irq]['description']})
        if not n: raise ValueError('no affinity records')
        dump('evidence/irq_affinity_hits.json',hits)
        dump('evidence/irq_affinity_empty.json',{'inactive':inactive,'unknown':unknown})
        case('IRQ02','实际IRQ亲和性','INCONCLUSIVE' if unknown else 'WARN' if hits else 'PASS','无覆盖隔离核心的有效亲和性',f'{n}项; 覆盖={hits}; 非活动空字段={len(inactive)}; 未知={len(unknown)}')
    except (ValueError,KeyError,IndexError) as e: case('IRQ02','实际IRQ亲和性','INCONCLUSIVE','有效亲和性证据',str(e))
    phases={}; hks=','.join(map(str,sorted(hk)))
    def phase(cid,mode,guest=None):
        label=cid.lower(); r,o=run(label,shlex.join(['taskset','-c',hks,'python3','-c',REMOTE,mode,hks,json.dumps(guest or []),str(workers(policy,'host_cpu_workers'))]))
        try:
            if r!=0: raise ValueError('remote workload or capture failed; inspect stderr')
            d={}
            for l in o.splitlines():
                k,v=l.split(' ',1); d[k]=json.loads(v)
            if not (59.95 if mode=='baseline' else 9.95)<=d['ELAPSED']<=(70 if mode=='baseline' else 15): raise ValueError('invalid observation duration')
            rows=delta(d['BEFORE'],d['AFTER'],online); dump(f'evidence/{label}_delta.json',rows)
            totals={c:sum(z['counts'][c] for z in rows.values() if z['category']=='device') for c in sorted(iso)}
            busy=cpu_busy(d['STAT_BEFORE'],d['STAT_AFTER'],hk); metric={'host_busy':busy}
            valid=True
            if mode=='host': valid=busy>=.8
            if mode=='guest': metric.update(d['GUEST']); valid=.5<=d['GUEST']['busy']<=1
            if mode=='io':
                metric.update(d['IO']); valid=min(d['IO'].values())>=8*1024*1024
                # Prove counters changed inside the window, rather than only total worker output.
                def net(s):
                    return {l.split(':')[0].strip():int(l.split(':')[1].split()[0])+int(l.split(':')[1].split()[8]) for l in s.splitlines() if ':' in l}
                def disk(s):
                    return {p[2]:int(p[9]) for l in s.splitlines() if len(p:=l.split())>=14}
                # fields: major minor name reads merged sectors ... writes merged sectors (index 9)
                x,y=net(d['NET_BEFORE']),net(d['NET_AFTER']); nx=sum(y[k]-x[k] for k in x.keys()&y.keys() if k!='lo' and y[k]>=x[k]); x,y=disk(d['DISK_BEFORE']),disk(d['DISK_AFTER']); dx=sum(y[k]-x[k] for k in x.keys()&y.keys() if y[k]>=x[k]); metric.update(network_bytes_delta=nx,disk_write_sectors_delta=dx); valid=valid and nx>0 and dx>0
            dump(f'evidence/{label}_metrics.json',dict(group=cid,condition=mode,elapsed_s=d['ELAPSED'],isolated_irq_counts=totals,isolated_device_irq_total=sum(totals.values()),irq_per_second=sum(totals.values())/d['ELAPSED'],valid_load=valid,load_metrics=metric,measurement='device IRQ increments, excludes local/IPI'))
            phases[cid]={'totals':totals,'valid':valid,'rows':rows,'metric':metric}
            case(cid,{'baseline':'基线设备IRQ','host':'物理机CPU负载设备IRQ','guest':'KVM负载设备IRQ','io':'网络及磁盘I/O设备IRQ'}[mode],'FAIL' if any(totals.values()) else 'PASS' if valid else 'INCONCLUSIVE','隔离CPU设备IRQ增量=0且负载有效',f'{totals}; {metric}; valid={valid}')
        except (ValueError,KeyError,TypeError,IndexError) as e: case(cid,mode,'INCONCLUSIVE','完整中断及负载证据',str(e))
    phase('IRQ03','baseline'); phase('IRQ04','host')
    try:
        guest=guest_ssh(run,policy)
    except Exception as e:
        for cid in ('IRQ05','IRQ06'): case(cid,'虚拟机相关负载','INCONCLUSIVE','虚拟机就绪',str(e))
    else:
        phase('IRQ05','guest',guest+[shlex.join(['python3','-c',GUEST_IRQ,str(workers(policy,'guest_cpu_workers'))])]);
        if policy.get('allow_io_test') is True: phase('IRQ06','io',guest)
        else: case('IRQ06','网络及磁盘I/O设备IRQ','NOT_EXECUTED','explicit I/O authorization','allow_io_test not true')
    total=sum(p['totals'][test] for p in phases.values()); valid=sum(p['valid'] for p in phases.values())
    case('IRQ07',f'CPU {test}设备IRQ专项','FAIL' if total else 'PASS' if valid==4 else 'INCONCLUSIVE','四个有效阶段CPU设备IRQ增量=0',f'增量={total}; 有效阶段={valid}/4')
    nvme={cid:{k:v for k,v in p['rows'].items() if re.search(r'\bnvme\d+q\d+\b',v['description']) and v['category']=='device'} for cid,p in phases.items()}; dump('evidence/nvme_interrupts.json',nvme)
    local={cid:{k:{'description':v['description'],'counts':v['counts']} for k,v in p['rows'].items() if v['category']=='local_or_ipi'} for cid,p in phases.items()}; dump('evidence/local_interrupts.json',local)
    case('IRQ08','IPI及本地中断分类','PASS' if len(local)==4 and all(local.values()) else 'INCONCLUSIVE','四阶段分类统计完成（不要求为0）',f'阶段={len(local)}/4; 每阶段非数字IRQ行数={ {k:len(v) for k,v in local.items()} }')

log('START CPU-06 IRQ isolation verification')
try: main()
except Exception as e: log('ERROR '+str(e))
finally:
    for i in range(1,9):
        cid=f'IRQ{i:02d}'
        if not any(c['id']==cid for c in CASES): case(cid,'未执行项目','NOT_EXECUTED','完成检查','前置条件失败')
    overall='FAIL' if any(c['status']=='FAIL' for c in CASES) else 'INCONCLUSIVE' if any(c['status'] in ('INCONCLUSIVE','NOT_EXECUTED') for c in CASES) else 'WARN' if any(c['status']=='WARN' for c in CASES) else 'PASS'
    dump('environment.json',ENV); dump('result.json',dict(run_id=RID,stage='CPU-06',overall=overall,cases=CASES)); dump('test_cases.json',[{k:c[k] for k in ('id','name','expected')} for c in CASES])
    with (RUN/'result.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(CASES[0])); w.writeheader(); w.writerows(CASES)
    (RUN/'report.md').write_text(safe(f'# CPU-06 中断隔离验证\n\nRun: {RID}\n\nOverall: {overall}\n\n'+'\n'.join(f"- {c['id']} {c['name']}: {c['status']} — {c['reason']}" for c in CASES)+'\n\n虚拟机若由本任务启动，将保持运行供后续测试使用。数字IRQ按设备中断统计；非数字行单列，不要求为零。基线非保证空载；有限观测不证明全部设备或所有负载下无中断；I/O仅覆盖宿主临时文件及宿主到guest虚拟网络，不代表物理网卡专项测试。\n'))
    log(f'FINISH {overall}; evidence directory: {RUN}')
    (RUN/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(RUN)}\n' for p in sorted(RUN.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'))
    sys.exit(0 if overall=='PASS' else 2 if overall=='WARN' else 1)
