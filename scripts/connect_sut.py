#!/usr/bin/env python3
"""Read-only connection smoke test. Requires PyYAML and OpenSSH."""
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
        f.write(safe(json.dumps(record, ensure_ascii=False))+'\n')
    log(f'END {label}: exit={rc}, timeout={timed_out}')
    return rc, out, timed_out

log('START connection test')
try:
    import yaml
    cfg = yaml.safe_load((BASE/'config.yaml').read_text())
    host, user = str(cfg['host']), str(cfg['ssh_user'])
    port = int(cfg.get('ssh_port', 22))
    auth = cfg.get('auth') or {}
    key = Path(auth.get('ssh_key') or cfg.get('ssh_key') or '~/.ssh/id_ed25519').expanduser()
    if not key.is_file(): raise ValueError('SSH private key missing')
    if not host or not user or host.startswith('-') or user.startswith('-') or any(c.isspace() for c in host+user): raise ValueError('Invalid target')
    environment.update(host=host, ssh_user=user, ssh_port=port)
    ssh = ['ssh','-T','-i',str(key),'-p',str(port),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ConnectionAttempts=1','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',f'{user}@{host}']
    rc, out, timed = execute('identity', ssh+['hostname; whoami; uname -r'], '')
    lines = out.strip().splitlines() if isinstance(out,str) else []
    ok = rc == 0
    case('TC01','SSH connection','PASS' if ok else ('TIMEOUT' if timed else 'FAIL'),'SSH exit code 0' if ok else 'SSH failed; see evidence')
    case('TC02','Trusted SSH host','PASS' if ok else 'INCONCLUSIVE','StrictHostKeyChecking=yes; trusted known_hosts entry' if ok else 'Connection not verified')
    identity_ok = ok and len(lines)==3 and lines[1]==user
    case('TC03','Remote user','PASS' if identity_ok else ('FAIL' if ok else 'NOT_EXECUTED'),'Remote user matches configuration' if identity_ok else 'Remote user not confirmed')
    kernel_ok = ok and len(lines)==3 and bool(lines[2])
    case('TC04','Kernel version','PASS' if kernel_ok else ('FAIL' if ok else 'NOT_EXECUTED'),'Kernel output captured' if kernel_ok else 'Kernel output not confirmed')
    if ok and len(lines)==3: environment.update(hostname=lines[0], remote_user=lines[1], kernel=lines[2])
    password = os.environ.get('SUT_SUDO_PASSWORD')
    if not identity_ok:
        case('TC05','sudo','NOT_EXECUTED','Remote identity not confirmed')
    elif not password or '\n' in password or '\r' in password:
        case('TC05','sudo','INCONCLUSIVE','Usable SUT_SUDO_PASSWORD not injected into process')
    else:
        rc, out, timed = execute('sudo',ssh+['sudo -k -S -p "" -- id -u'],password+'\n')
        ok = rc==0 and isinstance(out,str) and out.strip()=='0'
        case('TC05','sudo','PASS' if ok else ('TIMEOUT' if timed else 'FAIL'),'sudo returned UID 0' if ok else 'sudo verification failed; see evidence')
except Exception as e:
    log('ERROR '+str(e))
finally:
    for i,name in enumerate(['SSH connection','Trusted SSH host','Remote user','Kernel version','sudo'],1):
        cid=f'TC{i:02d}'
        if not any(c['id']==cid for c in cases): case(cid,name,'NOT_EXECUTED','Earlier prerequisite failed')
    (RUN/'execution.jsonl').touch(exist_ok=True)
    dump(RUN/'environment.json',environment)
    dump(RUN/'test_cases.json',[{'id':c['id'],'name':c['name']} for c in cases]+[{'id':'TC06','name':'Evidence presence'}])
    required=[RUN/'progress.log',RUN/'execution.jsonl',RUN/'environment.json',RUN/'test_cases.json']
    for cmd in commands:
        required.extend(RUN/cmd[k] for k in ('stdout_file','stderr_file'))
    complete=bool(commands) and all(p.is_file() for p in required)
    case('TC06','Evidence presence','PASS' if complete else 'FAIL','Recorded command evidence exists' if complete else 'Missing execution evidence')
    overall='PASS' if all(c['status']=='PASS' for c in cases) else 'FAIL'
    dump(RUN/'result.json',{'run_id':RUN_ID,'overall':overall,'cases':cases})
    with (RUN/'result.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['id','name','status','reason']); writer.writeheader()
        for c in cases: writer.writerow({k:safe(v) for k,v in c.items()})
    (RUN/'report.md').write_text(safe('# Connection test\n\nRun: '+RUN_ID+'\n\nOverall: '+overall+'\n\n'+'\n'.join(f"- {c['id']} {c['name']}: {c['status']} — {c['reason']}" for c in cases)+'\n'))
    log(f'FINISH {overall}; evidence directory: {RUN}')
    with (RUN/'SHA256SUMS').open('w') as f:
        for p in sorted(RUN.rglob('*')):
            if p.is_file() and p.name!='SHA256SUMS': f.write(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(RUN)}\n')
    sys.exit(0 if overall=='PASS' else 1)
