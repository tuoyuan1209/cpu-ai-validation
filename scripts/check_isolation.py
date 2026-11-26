#!/usr/bin/env python3
"""CPU-03 read-only configuration verification; no workload or configuration changes."""
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
        p=subprocess.run(argv,input=SECRET+'\n' if root and SECRET else '',text=True,capture_output=True,timeout=25,env={k:v for k,v in os.environ.items() if k not in ('SUT_SUDO_PASSWORD','SUT_SSH_PASSWORD')}); rc,out,err=p.returncode,p.stdout,p.stderr
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
def main():
    global SSH
    cfg=yaml.safe_load((BASE/'config.yaml').read_text()); policy=validate(yaml.safe_load((BASE/'isolation_policy.yaml').read_text()),load=False); verify_only(); a=cfg.get('auth') or {}; host=str(cfg['host']); user=str(cfg['ssh_user']); port=int(cfg.get('ssh_port',22)); key=Path(a.get('ssh_key') or cfg.get('ssh_key') or '~/.ssh/id_ed25519').expanduser()
    if not key.is_file() or not re.fullmatch(r'[A-Za-z0-9_.:-]+',host) or host.startswith('-') or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',user): raise ValueError('Invalid SSH configuration')
    SSH=['ssh','-T','-i',str(key),'-p',str(port),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ConnectionAttempts=1','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',user+'@'+host]
    online=str(policy['online_cpus']); iso=str(policy['isolated_cpus']); hk=str(policy['housekeeping_cpus']); kt=str(policy['kthread_cpus']); test=int(policy['test_cpu']); vm=policy['vm']; name=str(vm['name']); pins={int(k):cpus(str(v)) for k,v in vm['vcpu_pinning'].items()}; em=str(vm['emulator_cpus']); ENV.update(host=host,user=user,expected=policy)
    if cpus(iso)&cpus(hk) or cpus(iso)|cpus(hk)!=cpus(online): raise ValueError('Inconsistent CPU baseline')
    r,o=run('identity','hostname && whoami && uname -r'); lines=o.splitlines()
    if r!=0 or len(lines)!=3 or lines[1]!=user: raise RuntimeError('SSH identity verification failed')
    ENV.update(hostname=lines[0],kernel=lines[2]); r,o=run('realtime','cat /sys/kernel/realtime'); compare('ISO01','实时内核',r,o,'1')
    r,on=run('online','cat /sys/devices/system/cpu/online'); compare('ISO02','在线CPU',r,on,online,cpus); on_rc=r
    r,cmd=run('cmdline','cat /proc/cmdline'); args={x.split('=',1)[0]:x.split('=',1)[1] for x in cmd.split() if '=' in x}; cr=r
    # Bare isolcpus defaults to domain isolation. Explicit flags must include domain.
    raw=args.get('isolcpus',''); parts=raw.split(','); flags=[x for x in parts if x and not x[0].isdigit()]; nums=','.join(x for x in parts if x and x[0].isdigit()); compare('ISO03','isolcpus启动参数（domain）',cr,nums if not flags or 'domain' in flags else '',iso,cpus)
    r,actual_iso=run('isolated','cat /sys/devices/system/cpu/isolated'); iso_rc=r; compare('ISO04','实际隔离CPU',r,actual_iso,iso,cpus)
    r,o=run('nohz_full','cat /sys/devices/system/cpu/nohz_full'); compare('ISO05','NOHZ_FULL',r,o,iso,cpus)
    compare('ISO06','RCU卸载启动配置',cr,args.get('rcu_nocbs',''),iso,cpus)
    r,o=run('irq_default','cat /proc/irq/default_smp_affinity'); compare('ISO07','默认IRQ亲和性（运行时）',r,o,format(sum(1<<i for i in cpus(hk)),'x'),mask)
    compare('ISO08','内核线程启动参数',cr,args.get('kthread_cpus',''),kt,cpus)
    r,o=run('workqueue','cat /sys/devices/virtual/workqueue/cpumask')
    try: overlap=mask(o)&cpus(iso) if r==0 else None
    except ValueError: overlap=None
    case('ISO09','全局workqueue亲和性','INCONCLUSIVE' if overlap is None else 'WARN' if overlap else 'PASS','不覆盖隔离CPU',f'掩码={o}; 交集={sorted(overlap) if overlap is not None else "未知"}')
    r,o=run('irq_effective','for f in /proc/irq/[0-9]*/effective_affinity_list; do [ -e "$f" ] || continue; printf "%s " "$f"; cat "$f" || exit 1; done'); hits=[]; count=0; valid=r==0
    try:
        for line in o.splitlines():
            path,_,value=line.partition(' '); count+=1
            if cpus(value)&cpus(iso): hits.append(path.split('/')[3])
    except (ValueError,IndexError): valid=False
    case('ISO10','实际IRQ亲和性','INCONCLUSIVE' if not valid or not count else 'WARN' if hits else 'PASS','无IRQ有效亲和性覆盖隔离CPU',f'采集{count}项; 涉及隔离CPU的IRQ: {", ".join(hits) or "无"}')
    try: ok=on_rc==iso_rc==0 and test in cpus(on)&cpus(actual_iso)
    except ValueError: ok=False
    case('ISO11','实时测试核心','PASS' if ok else 'FAIL',f'CPU {test} 在线且隔离',f'在线={on}; 隔离={actual_iso}')
    prefix='LC_ALL=C virsh -c qemu:///system '; q=shlex.quote(name); r,x=run('vm_xml_config',prefix+'dumpxml --inactive '+q,True); rr,state=run('vm_state',prefix+'domstate '+q,True); live=None
    if rr==0 and state=='running': lr,live=run('vm_xml_live',prefix+'dumpxml '+q,True); live=live if lr==0 else None
    try:
        if r!=0 or rr!=0 or state not in ('running','shut off') or (state=='running' and live is None): raise ValueError('VM evidence unavailable')
        docs=[ET.fromstring(x)]+([ET.fromstring(live)] if live else []); ap=[{int(z.attrib['vcpu']):cpus(z.attrib['cpuset']) for z in d.findall('./cputune/vcpupin')} for d in docs]; ae=[cpus(d.find('./cputune/emulatorpin').attrib['cpuset']) for d in docs]; mode='持久+运行配置' if live else '仅持久配置（关机）'; case('ISO12','KVM vCPU绑定','PASS' if live and all(p==pins for p in ap) else 'INCONCLUSIVE' if all(p==pins for p in ap) else 'FAIL',pins,f'{mode}: {ap}'); case('ISO13','KVM模拟器绑定','PASS' if live and all(p==cpus(em) for p in ae) else 'INCONCLUSIVE' if all(p==cpus(em) for p in ae) else 'FAIL',em,f'{mode}: {ae}')
    except (ValueError,KeyError,AttributeError,ET.ParseError):
        for i,n in [('ISO12','KVM vCPU绑定'),('ISO13','KVM模拟器绑定')]: case(i,n,'INCONCLUSIVE','匹配基线','虚拟机证据不足')
    run('interrupts_snapshot','cat /proc/interrupts'); run('thread_snapshot','ps -eLo pid,tid,psr,cls,rtprio,comm --sort=psr')
log('START CPU-03 isolation verification (read-only)')
try: main()
except Exception as e: log('ERROR '+str(e))
finally:
    for i in range(1,14):
        cid=f'ISO{i:02d}'
        if not any(c['id']==cid for c in CASES): case(cid,'未执行项目','NOT_EXECUTED','完成检查','前置条件失败')
    overall='FAIL' if any(c['status']=='FAIL' for c in CASES) else 'INCONCLUSIVE' if any(c['status'] in ('INCONCLUSIVE','NOT_EXECUTED') for c in CASES) else 'WARN' if any(c['status']=='WARN' for c in CASES) else 'PASS'
    dump('environment.json',ENV); dump('result.json',dict(run_id=RID,stage='CPU-03',overall=overall,cases=CASES)); dump('test_cases.json',[{k:c[k] for k in ('id','name','expected')} for c in CASES])
    with (RUN/'result.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(CASES[0])); w.writeheader(); w.writerows(CASES)
    (RUN/'report.md').write_text(safe(f'# CPU-03 核心隔离配置验证\n\nRun: {RID}\n\nOverall: {overall}\n\n'+'\n'.join(f"- {c['id']} {c['name']}: {c['status']} — {c['reason']}" for c in CASES)+'\n\n仅验证配置与快照，不代表实际调度、中断或延迟达标。\n'))
    log(f'FINISH {overall}; evidence directory: {RUN}')
    (RUN/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(RUN)}\n' for p in sorted(RUN.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'))
    sys.exit(0 if overall=='PASS' else 2 if overall=='WARN' else 1)
