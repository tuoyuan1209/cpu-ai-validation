#!/usr/bin/env python3
"""Local overlay installer. Never contacts SUT/GitHub. Preserve existing source and evidence."""
import argparse, datetime, fcntl, shutil, sys, os
from pathlib import Path
import yaml
SOURCE=Path(__file__).resolve().parent
DEFAULT='/home/teemo/project/teemo_project/cpu_ai_validation'

def main():
    p=argparse.ArgumentParser(); p.add_argument('--target',default=DEFAULT); p.add_argument('--apply',action='store_true'); a=p.parse_args(); target=Path(a.target).resolve()
    if target==SOURCE or not (target/'config.yaml').is_file() or not (target/'.git').exists(): raise SystemExit('Specify the EXISTING test Git repository; do not install into the extraction folder.')
    allowed_dirs={'scripts','common','tests','workflows'}; allowed_files={'README.md','requirements.txt','run_all.sh','install_upgrade.py','isolation_policy.example.yaml','provision_policy.verify_only.yaml','config.yaml.example','VALIDATION.md'}
    files=[f for f in SOURCE.rglob('*') if f.is_file() and '__pycache__' not in f.parts and not f.name.endswith(('.pyc','.bak')) and (f.relative_to(SOURCE).parts[0] in allowed_dirs or f.relative_to(SOURCE).as_posix() in allowed_files)]
    print(f'Target: {target}; overlay files: {len(files)}; config.yaml, logs/, runs/, .git unchanged.')
    if not a.apply: print('Dry run; add --apply after pausing old automations.'); return
    os.umask(0o077); state=target/'.validation'; state.mkdir(exist_ok=True)
    with (state/'run.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        backup=state/'backups'/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'); backup.mkdir(parents=True)
        def save(path):
            if path.is_file():
                q=backup/path.relative_to(target); q.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(path,q)
        for f in files:
            dst=target/f.relative_to(SOURCE); save(dst); dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(f,dst)
        old=target/'provision_policy.yaml'; save(old); policy=yaml.safe_load(old.read_text()) or {} if old.exists() else {}; policy['validation_mode']='verify'; defaults=yaml.safe_load((SOURCE/'provision_policy.verify_only.yaml').read_text())
        for section in ('provision','virtualization'):
            d=policy.setdefault(section,{})
            for k in list(d):
                if k.startswith('auto_'): d[k]=False
            d.update(defaults[section])
        old.write_text(yaml.safe_dump(policy,allow_unicode=True,sort_keys=False))
        # Preserve existing acceptance ranges. Add only missing schema fields; approval is still manual.
        iso=target/'isolation_policy.yaml'; save(iso); sample=yaml.safe_load((SOURCE/'isolation_policy.example.yaml').read_text()); current=yaml.safe_load(iso.read_text()) if iso.exists() else None
        if current is None: current=sample
        else:
            for k in ('isolation_mechanism','workload','realtime'): current.setdefault(k,sample[k])
            vm=current.setdefault('vm',{}); vm.setdefault('vcpu_count',len(vm.get('vcpu_pinning',{}))); vm.setdefault('guest_user',(policy.get('virtualization') or {}).get('guest_user')); vm.setdefault('guest_mac',None); vm.setdefault('guest_ip',None); vm.setdefault('iothread_pinning',{})
        current['allow_load_tests']=False; current['allow_io_test']=False; iso.write_text(yaml.safe_dump(current,allow_unicode=True,sort_keys=False))
        gi=target/'.gitignore'; save(gi); previous=gi.read_text() if gi.exists() else ''; new=(SOURCE/'.gitignore.example').read_text().splitlines(); missing=[x for x in new if x and x not in previous.splitlines()]; gi.write_text(previous.rstrip()+'\n'+'\n'.join(missing)+'\n')
        # Old approvals must not be reused after upgrading.
        active=state/'active.json'; save(active)
        if active.exists(): active.unlink()
        print('UPGRADED: '+str(target)); print('Local backup: '+str(backup)); print('No remote deployment, no Git commit/push. Run discovery, review policy, approve.')
if __name__=='__main__': main()
