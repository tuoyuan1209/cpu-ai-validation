#!/usr/bin/env python3
"""Read-only vendor discovery and CPU-02 preflight. No automatic policy promotion."""
import sys, ipaddress, argparse, datetime as dt, hashlib, json, os, re, shlex, subprocess, time, uuid
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml
BASE=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(BASE))
from common.policy import structured, scrub, validate, verify_only
from common.transport import guest_ssh

def cpus(s):
    if not isinstance(s,str): raise ValueError('CPU list must be a string')
    out=set()
    for p in s.split(','):
        if not p: continue
        if not re.fullmatch(r'\d+(?:-\d+)?',p): raise ValueError('unsupported CPU list: '+p)
        a,b=int(p.split('-')[0]),int(p.split('-')[-1]);
        if b<a or b>1048575: raise ValueError('invalid range')
        out.update(range(a,b+1))
    return out

def fmt(s): return ','.join(map(str,sorted(s)))
def now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def parse_vm(xml):
    d=ET.fromstring(xml); c=d.find('cputune'); mem=d.find('memory'); v=d.find('vcpu'); em=d.find('./cputune/emulatorpin')
    return dict(name=d.findtext('name'),type=d.get('type'),vcpu_count=int(v.text),vcpu_current=int(v.get('current',v.text)),memory=mem.text,memory_unit=mem.get('unit','KiB'),vcpu_pinning={int(x.get('vcpu')):x.get('cpuset') for x in d.findall('./cputune/vcpupin')},emulator_cpus=em.get('cpuset') if em is not None else None,domain_cpuset=v.get('cpuset'),iothread_pinning=[x.attrib for x in d.findall('./cputune/iothreadpin')],interfaces=[dict(type=x.get('type'),source=x.find('source').attrib if x.find('source') is not None else {},mac=x.find('mac').get('address') if x.find('mac') is not None else None) for x in d.findall('./devices/interface')])

def main():
    p=argparse.ArgumentParser(); p.add_argument('--preflight',action='store_true'); p.add_argument('--vm'); a=p.parse_args(); stage='CPU-02' if a.preflight else 'CPU-00'
    os.umask(0o077); rid=os.environ.get('CPU_VALIDATION_RUN_ID') or ('run-' if a.preflight else 'discovery-')+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ-')+uuid.uuid4().hex[:8]; run=BASE/'runs'/rid; e=run/'evidence'; e.mkdir(parents=True); (BASE/'logs').mkdir(exist_ok=True)
    cfg=yaml.safe_load((BASE/'config.yaml').read_text()); host=str(cfg['host']); user=str(cfg['ssh_user']); key=Path((cfg.get('auth') or {}).get('ssh_key') or cfg.get('ssh_key') or '~/.ssh/id_ed25519').expanduser(); port=int(cfg.get('ssh_port',22))
    if not key.is_file() or not re.fullmatch(r'[A-Za-z0-9_.:-]+',host) or host.startswith('-') or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',user) or not 1<=port<=65535: raise ValueError('invalid SSH config')
    ssh=['ssh','-T','-i',str(key),'-p',str(port),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',user+'@'+host]
    secret=os.environ.get('SUT_SUDO_PASSWORD',''); secrets=[secret,os.environ.get('SUT_SSH_PASSWORD','')]; records={}; cases=[]
    def safe(s):
        if isinstance(s,bytes): s=s.decode(errors='replace')
        for x in sorted(filter(None,secrets),key=len,reverse=True): s=s.replace(x,'[REDACTED]')
        return s
    def log(s):
        line=safe(f'{now()} [{rid}] {s}'); print(line,flush=True)
        for path in (run/'progress.log',BASE/'logs/live.log'):
            with path.open('a') as f:f.write(line+'\n')
    def dump(name,x): (run/name).write_text(json.dumps(structured(x),ensure_ascii=False,indent=2)+'\n')
    def get(label,cmd,root=False):
        log('START '+label); start=now(); t=time.monotonic(); rc=None; out=err=''
        if root: cmd=('sudo -k -S -p ""' if secret else 'sudo -n')+' -- sh -c '+shlex.quote(cmd)
        try:
            z=subprocess.run(ssh+[cmd],input=secret+'\n' if root and secret else '',text=True,capture_output=True,timeout=25,env={k:v for k,v in os.environ.items() if k not in ('SUT_SUDO_PASSWORD','SUT_SSH_PASSWORD')}); rc,out,err=z.returncode,z.stdout,z.stderr
        except subprocess.TimeoutExpired as ex: out=ex.stdout or ''; err=ex.stderr or ''; err=safe(err)+'\nTIMEOUT'
        except OSError as ex: err=str(ex)
        raw_out=out; out,err=safe(out),safe(err); (e/(label+'.stdout')).write_text(out); (e/(label+'.stderr')).write_text(err)
        rec=dict(label=label,command=cmd,start=start,end=now(),elapsed_s=round(time.monotonic()-t,3),exit_code=rc,stdout_file='evidence/'+label+'.stdout',stderr_file='evidence/'+label+'.stderr'); records[label]=rec
        with (run/'execution.jsonl').open('a') as f:f.write(json.dumps(structured(rec),ensure_ascii=False)+'\n')
        log(f'END {label}: exit={rc}'); return raw_out.strip() if rc==0 else None
    def case(i,name,status,actual): cases.append(dict(id=i,name=name,status=status,actual=actual)); log(f'{i} {status}: {name}: {actual}')
    def verify(i,name,actual,expected): case(i,name,'INCONCLUSIVE' if actual is None or expected is None else 'PASS' if actual==expected else 'FAIL',dict(actual=actual,expected=expected))
    data={}; vms=[]; candidate={}; notes=[]
    try:
        identity=get('identity','hostname; id -un; uname -r');
        if not identity or identity.splitlines()[1:2]!=[user]: raise RuntimeError('SSH identity unavailable')
        data['identity']=identity.splitlines();
        probes={'topology':'LC_ALL=C lscpu -J','cpu_detail':'LC_ALL=C lscpu -e','os':'cat /etc/os-release','online':'cat /sys/devices/system/cpu/online','isolated':'cat /sys/devices/system/cpu/isolated','nohz_full':'cat /sys/devices/system/cpu/nohz_full','realtime':'cat /sys/kernel/realtime','cmdline':'cat /proc/cmdline','pid1_affinity':'grep Cpus_allowed_list /proc/1/status','ssh_affinity':'grep Cpus_allowed_list /proc/self/status','cgroup':'cat /proc/self/cgroup; findmnt -t cgroup,cgroup2','cpusets':'find /sys/fs/cgroup -maxdepth 6 -type f \\( -name cpuset.cpus -o -name cpuset.cpus.effective -o -name cpuset.cpus.partition \\) -print -exec cat {} \\;','irq_default':'cat /proc/irq/default_smp_affinity','workqueue':'cat /sys/devices/virtual/workqueue/cpumask','interrupts':'cat /proc/interrupts','irq_effective':'for f in /proc/irq/[0-9]*/effective_affinity_list; do [ -e "$f" ] || continue; printf "%s " "$f"; cat "$f"; done','threads':'ps -eLo pid,tid,psr,cls,rtprio,comm','virtualization':'systemd-detect-virt; ls -l /dev/kvm; lsmod | grep -E "^kvm"; command -v virsh; command -v qemu-system-x86_64; true','tools':'for t in python3 cyclictest stress-ng taskset chrt numactl virsh; do printf "%s " "$t"; command -v "$t" || echo MISSING; done','limits':'ulimit -r; ulimit -l; ls -l /dev/cpu_dma_latency','nvme_queues':'for f in /sys/block/nvme*/mq/*/cpu_list; do [ -e "$f" ] || continue; printf "%s " "$f"; cat "$f"; done','network':'ip -br addr; ip route'}
        for k,cmd in probes.items(): data[k]=get(k,cmd)
        vir='LC_ALL=C virsh -r -c qemu:///system '
        names=get('vm_list',vir+'list --all --name',True); data['vm_inventory_complete']=names is not None
        if names is None: notes.append('libvirt read-only query unavailable; non-libvirt deployment not automatically interpreted')
        else:
            for i,n in enumerate(names.splitlines()):
                if not n.strip(): continue
                q=shlex.quote(n); prefix=f'vm_{i}'; state=get(prefix+'_state',vir+'domstate '+q,True); xml=get(prefix+'_xml',vir+'dumpxml '+q+' --inactive',True); live=get(prefix+'_live_xml',vir+'dumpxml '+q,True) if state=='running' else None
                item={'name':n,'state':state,'persistent':parse_vm(xml) if xml else None,'live':parse_vm(live) if live else None}; vms.append(item)
                if state=='running': get(prefix+'_vcpupin',vir+'vcpupin '+q,True); get(prefix+'_emulatorpin',vir+'emulatorpin '+q,True); get(prefix+'_leases',vir+'domifaddr '+q+' --source lease',True)
        args=dict(x.split('=',1) for x in shlex.split(data['cmdline'] or '') if '=' in x); iso=cpus(data['isolated']) if data['isolated'] is not None else None; online=cpus(data['online']) if data['online'] else None
        policy=validate(yaml.safe_load((BASE/'isolation_policy.yaml').read_text())) if a.preflight else None
        if a.preflight: verify_only()
        target=a.vm or (policy['vm']['name'] if policy else None)
        selected=next((x for x in vms if x['name']==target),None) if target else vms[0] if len(vms)==1 else None
        candidate=dict(online_cpus=data['online'],isolated_cpus=data['isolated'],housekeeping_cpus=fmt(online-iso) if online is not None and iso is not None else None,kthread_cpus=args.get('kthread_cpus'),test_cpu=None,vm=None)
        if selected and selected['persistent']:
            v=selected['persistent']; candidate['vm']={k:v[k] for k in ('name','vcpu_count','vcpu_pinning','emulator_cpus','iothread_pinning')}
            candidate['vm'].update(guest_user=None,guest_mac=None,guest_ip=None)
        candidate.update(isolation_mechanism='isolcpus-domain' if iso else None,allow_load_tests=False,allow_io_test=False,realtime={'priority':80,'interval_us':1000,'short_duration_s':60,'long_duration_s':3600,'max_latency_us':None})
        notes.extend(['Detected values are observations, NOT approved acceptance criteria. test_cpu deliberately unset.','Any [REDACTED] value is not usable as a policy value; confirm from supplier independently.','Housekeeping is inferred as online minus sysfs isolated; cpuset-only isolation needs separate review.','Guest account, SSH trust, workload thresholds and vendor guarantees must be confirmed independently.','Read-only libvirt queries do not collect QMP thread IDs; CPU-04 does this with an authorized running VM.'])
        case('DISC01','SSH identity','PASS',data['identity']); case('DISC02','CPU evidence','PASS' if online and iso is not None and data['cmdline'] is not None else 'INCONCLUSIVE',candidate); case('DISC03','VM inventory','PASS' if names is not None and all(x['persistent'] is not None for x in vms) else 'INCONCLUSIVE',len(vms)); case('DISC04','candidate selection','PASS' if candidate['vm'] and iso and candidate['vm']['vcpu_pinning'] and candidate['vm']['emulator_cpus'] else 'INCONCLUSIVE','candidate only; approval required')
        if a.preflight:
            dump('acceptance_policy.json',policy)
            vm=policy['vm']; expected_vm=next((x for x in vms if x['name']==vm['name']),None)
            verify('TP01','online CPUs',sorted(online) if online is not None else None,sorted(cpus(str(policy['online_cpus'])))); verify('TP02','isolated CPUs',sorted(iso) if iso is not None else None,sorted(cpus(str(policy['isolated_cpus'])))); verify('TP03','RT kernel',data['realtime'],'1')
            tools=data['tools']; case('TP04','host tools','INCONCLUSIVE' if tools is None else 'FAIL' if 'MISSING' in tools else 'PASS',tools)
            case('TP05','test CPU membership','PASS' if iso and int(policy['test_cpu']) in iso else 'FAIL',policy['test_cpu']); case('TP06','VM exists','PASS' if expected_vm else 'INCONCLUSIVE' if names is None else 'FAIL',vm['name'])
            for label,src in [('TP07','persistent'),('TP08','live')]:
                val=expected_vm.get(src) if expected_vm else None
                if val is None: case(label,'VM '+src+' affinity','INCONCLUSIVE','XML unavailable or VM not running'); continue
                actual={int(k):sorted(cpus(s)) for k,s in val['vcpu_pinning'].items()}; expected={int(k):sorted(cpus(str(s))) for k,s in vm['vcpu_pinning'].items()}; ok=actual==expected and val['emulator_cpus'] is not None and cpus(val['emulator_cpus'])==cpus(str(vm['emulator_cpus'])); case(label,'VM '+src+' affinity','PASS' if ok else 'FAIL',dict(actual=actual,expected=expected,emulator=val['emulator_cpus']))
            pp=yaml.safe_load((BASE/'provision_policy.yaml').read_text()); guest=vm.get('guest_user')
            def adapter(label,cmd,root=False):
                out=get(label,cmd,root); return (0,out) if out is not None else (1,'')
            try:
                guest_ssh(adapter,policy)
                case('TP09','guest readiness','PASS','MAC-matched IP, guest user, vCPU count and tools verified')
            except Exception as exc: case('TP09','guest readiness','INCONCLUSIVE',str(exc))
            case('TP10','host limits evidence capture','INCONCLUSIVE' if data['limits'] is None else 'PASS',{'observed':data['limits'],'scope':'read-only limits capture; actual FIFO scheduling tested later'})
    except Exception as ex: case('ERROR','collection error','INCONCLUSIVE',str(ex))
    env_record = structured(dict(host=host,ssh_user=user,ssh_port=port,stage=stage,script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
    env_record['target_sha256'] = hashlib.sha256(json.dumps([host,user,port],separators=(',',':')).encode()).hexdigest()
    (run/'environment.json').write_text(json.dumps(env_record,ensure_ascii=False,indent=2)+'\n')
    dump('observed.json',data); dump('vm_config.json',vms); dump('notes.json',notes)
    (run/'isolation_policy.detected.yaml').write_text(yaml.safe_dump(scrub(candidate),allow_unicode=True,sort_keys=False))
    (run/'provision_policy.detected.yaml').write_text(yaml.safe_dump({'validation_mode':'verify','provision':{k:False for k in ['auto_install_tools','auto_fix_permissions','auto_fix_dma','auto_install_kvm','auto_load_modules','auto_start_libvirt','auto_start_network','auto_create_vm','auto_start_vm','auto_fix_irq_affinity','auto_download_image']},'virtualization':{'auto_download_image':False,'name':scrub((candidate.get('vm') or {}).get('name')),'guest_user':None}},sort_keys=False))
    overall='FAIL' if any(c['status']=='FAIL' for c in cases) else 'INCONCLUSIVE' if any(c['status']=='INCONCLUSIVE' for c in cases) else 'PASS'; dump('result.json',dict(run_id=rid,stage=stage,overall=overall,cases=cases)); (run/'report.md').write_text(safe('# '+stage+' '+overall+'\n\n'+'\n'.join(f"- {c['id']} {c['status']} {c['name']}: {c['actual']}" for c in cases)+'\n\n'+'\n'.join(notes)+'\n')); log(f'FINISH {overall}; evidence directory: {run}'); (run/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(run)}\n' for f in sorted(run.rglob('*')) if f.is_file() and f.name!='SHA256SUMS')); return 0 if overall=='PASS' else 1
if __name__=='__main__': raise SystemExit(main())
