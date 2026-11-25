#!/usr/bin/env python3
"""Read-only CPU test environment preflight. Requires PyYAML and OpenSSH."""
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

BASE = Path(__file__).resolve().parent.parent
os.umask(0o077)
RUN_ID = dt.datetime.now(dt.timezone.utc).strftime('run-%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8]
RUN = BASE / 'runs' / RUN_ID
EVIDENCE = RUN / 'evidence'
EVIDENCE.mkdir(parents=True)
(BASE / 'logs').mkdir(exist_ok=True)
secrets = [os.environ.get(k, '') for k in ('SUT_SSH_PASSWORD', 'SUT_SUDO_PASSWORD')]

def safe(value):
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    for s in sorted(filter(None, secrets), key=len, reverse=True):
        value = value.replace(s, '[REDACTED]')
    return value

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def log(msg):
    line = safe(f'{now()} [{RUN_ID}] {msg}')
    print(line, flush=True)
    for p in (RUN / 'progress.log', BASE / 'logs/live.log'):
        with p.open('a') as f:
            f.write(line + '\n')
            f.flush()

def dump(path, obj):
    # Redact string values without modifying structural keys or numeric values.
    def scrub(v):
        if isinstance(v, str): return safe(v)
        if isinstance(v, list): return [scrub(x) for x in v]
        if isinstance(v, dict): return {k: scrub(x) for k,x in v.items()}
        return v
    path.write_text(json.dumps(scrub(obj), ensure_ascii=False, indent=2)+'\n')

cases = []
environment = {}
commands = []
def case(cid, name, status, reason):
    cases.append({'id': cid, 'name': name, 'status': status, 'reason': reason})
    log(f'{cid} {status}: {reason}')

def execute(label, argv, stdin=None):
    log(f'START {label}')
    started = now(); t = time.monotonic()
    rc = None; timed_out = False; out = err = ''
    try:
        # Do not pass password-bearing environment variables to SSH.
        env = {k:v for k,v in os.environ.items() if k not in ('SUT_SSH_PASSWORD','SUT_SUDO_PASSWORD')}
        p = subprocess.run(argv, input=stdin, text=True, capture_output=True, timeout=20, env=env)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True; out = e.stdout or ''; err = e.stderr or ''
    except OSError as e:
        err = str(e)
    for suffix, data in [('stdout', out), ('stderr', err)]:
        (EVIDENCE / f'{label}.{suffix}').write_text(safe(data))
    record = {'label': label, 'argv': argv, 'start': started, 'end': now(), 'elapsed_s': round(time.monotonic()-t,3), 'exit_code': rc, 'timeout': timed_out, 'stdout_file': f'evidence/{label}.stdout', 'stderr_file': f'evidence/{label}.stderr'}
    commands.append(record)
    with (RUN/'execution.jsonl').open('a') as f:
        f.write(json.dumps({k: ([safe(x) for x in v] if isinstance(v,list) else safe(v) if isinstance(v,str) else v) for k,v in record.items()}, ensure_ascii=False)+'\n')
    log(f'END {label}: exit={rc}, timeout={timed_out}')
    return rc, out, timed_out

log('START provision preflight (read-only)')
checks = [
 ('TP01','OS release','os_release','cat /etc/os-release', 'output'),
 ('TP02','CPU topology','cpu_topology','LC_ALL=C lscpu', 'output'),
 ('TP03','Kernel version','kernel','uname -r','output'),
 ('TP04','cyclictest','cyclictest','command -v cyclictest && cyclictest --help >/dev/null 2>&1','exit'),
 ('TP05','stress-ng','stress_ng','command -v stress-ng && stress-ng --version','exit'),
 ('TP06','taskset','taskset','taskset --version','exit'),
 ('TP07','chrt','chrt','chrt --version','exit'),
 ('TP08','numactl','numactl','numactl --show','exit'),
 ('TP09','FIFO priority 80 as SSH user','realtime','chrt -f 80 true','exit'),
 ('TP10','memlock soft limit','memlock','ulimit -l','memlock'),
 ('TP11','DMA latency device access as SSH user','dma_latency','test -c /dev/cpu_dma_latency && test -w /dev/cpu_dma_latency && printf "writable\\n"','exit'),
 ('TP12','Isolation configuration capture','isolation', 'cat /proc/cmdline && for f in isolated nohz_full online; do printf "%s: " "$f"; if test -r /sys/devices/system/cpu/$f; then cat /sys/devices/system/cpu/$f || exit 1; else printf "unavailable\\n"; fi; done','output'),
]
try:
    import yaml
    cfg = yaml.safe_load((BASE/'config.yaml').read_text())
    host,user=str(cfg['host']),str(cfg['ssh_user']); port=int(cfg.get('ssh_port',22))
    auth=cfg.get('auth') or {}
    key=Path(auth.get('ssh_key') or cfg.get('ssh_key') or '~/.ssh/id_ed25519').expanduser()
    if not key.is_file(): raise ValueError('SSH private key missing')
    if not host or not user or host.startswith('-') or user.startswith('-') or any(c.isspace() for c in host+user): raise ValueError('Invalid target')
    ssh=['ssh','-T','-i',str(key),'-p',str(port),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ConnectionAttempts=1','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',f'{user}@{host}']
    rc,out,timed=execute('identity',ssh+['hostname && whoami && uname -r'],'')
    lines=out.strip().splitlines() if isinstance(out,str) else []
    if rc!=0 or len(lines)!=3 or lines[1]!=user: raise RuntimeError('Remote identity not confirmed')
    environment.update(host=host,ssh_user=user,ssh_port=port,hostname=lines[0],kernel=lines[2],stage='provision-preflight')
    for cid,name,label,cmd,rule in checks:
        rc,out,timed=execute(label,ssh+[cmd],'')
        value=out.strip() if isinstance(out,str) else ''
        ok=rc==0
        reason='Command completed successfully' if ok else 'Command failed; see evidence'
        if rule=='output' and ok:
            ok=bool(value); reason='Nonempty output captured' if ok else 'Empty output'
        if rule=='memlock' and ok:
            # Conservative readiness gate for cyclictest -m; finite limits require workload-specific validation.
            ok=value=='unlimited'; reason='Unlimited soft memlock' if ok else 'Finite or unknown soft memlock; requires workload-specific validation: '+value
            if not ok:
                case(cid,name,'INCONCLUSIVE',reason); continue
        case(cid,name,'PASS' if ok else 'TIMEOUT' if timed else 'FAIL',reason)
except Exception as e:
    log('ERROR '+str(e))
finally:
    for cid,name,*_ in checks:
        if not any(c['id']==cid for c in cases): case(cid,name,'NOT_EXECUTED','Prerequisite or earlier execution failed')
    (RUN/'execution.jsonl').touch(exist_ok=True)
    dump(RUN/'environment.json',environment)
    dump(RUN/'test_cases.json',[{'id':cid,'name':name,'command':cmd,'rule':rule} for cid,name,label,cmd,rule in checks])
    evidence_ok=bool(commands) and all((RUN/c[k]).is_file() for c in commands for k in ('stdout_file','stderr_file'))
    overall='PASS' if evidence_ok and all(c['status']=='PASS' for c in cases) else 'FAIL'
    dump(RUN/'result.json',{'run_id':RUN_ID,'stage':'provision-preflight','overall':overall,'evidence_present':evidence_ok,'cases':cases})
    with (RUN/'result.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['id','name','status','reason']); writer.writeheader()
        for c in cases: writer.writerow({k:safe(v) for k,v in c.items()})
    (RUN/'report.md').write_text(safe('# Provision preflight (read-only)\n\nRun: '+RUN_ID+'\n\nOverall: '+overall+'\n\n'+'\n'.join(f"- {c['id']} {c['name']}: {c['status']} — {c['reason']}" for c in cases)+'\n'))
    log(f'FINISH {overall}; evidence directory: {RUN}')
    with (RUN/'SHA256SUMS').open('w') as f:
        for p in sorted(RUN.rglob('*')):
            if p.is_file() and p.name!='SHA256SUMS': f.write(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(RUN)}\n')
    sys.exit(0 if overall=='PASS' else 1)
