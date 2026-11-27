#!/usr/bin/env python3
"""Single entry point for independently approved vendor validation; no deployment."""
import argparse, fcntl, hashlib, json, os, re, subprocess, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common.policy import BASE, read, validate, verify_only, policy_hashes, digest, clean_text
from common.transport import fingerprint
from common.evidence import new_id, now, verify, Run
STATE=BASE/'.validation'; STATE.mkdir(mode=0o700,exist_ok=True)
LOCK_FD=None
WEB_REQUEST=None
STAGES={'00':'discover_sut.py','01':'connect_sut.py','02':'check_vendor_preflight.py','03':'check_isolation.py','04':'check_affinity.py','05':'check_scheduling.py','06':'check_irq.py','07':'check_latency.py','08':'check_stability.py'}

def code_hash():
    files=[BASE/'scripts'/f for f in STAGES.values()]+[Path(__file__)]+sorted((BASE/'common').glob('*.py'))
    return hashlib.sha256(''.join(str(f.relative_to(BASE))+':'+digest(f)+'\n' for f in files).encode()).hexdigest()
def atomic(p,obj):
    tmp=p.with_suffix('.tmp'); tmp.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n'); tmp.chmod(0o600); tmp.replace(p)
def claim_web_request(action):
    """Bind a fixed runner invocation to one web request, if present, under engine lock."""
    global WEB_REQUEST
    path=STATE/'web-stage-request.json'
    if not path.is_file(): return
    q=json.loads(path.read_text())
    if q.get('state')!='READY' or q.get('stage')!=action or action not in (*STAGES,'09','13','14','15'):
        raise ValueError('a web stage request is pending/consumed; no unrelated or duplicate invocation')
    if not re.fullmatch(r'flow-[0-9a-f]{32}',q.get('flow_id','')) or not re.fullmatch(r'[0-9a-f]{32}',q.get('request_id','')) or not re.fullmatch(r'(run|discovery)-\d{8}T\d{6}Z-[0-9a-f]{8}',q.get('run_id','')):
        raise ValueError('invalid web request IDs')
    if q['run_id'].startswith('discovery-')!=(action=='00') or (BASE/'runs'/q['run_id']).exists(): raise ValueError('invalid or used requested run ID')
    if q.get('policy_hashes')!=policy_hashes() or q.get('code_sha256')!=code_hash(): raise ValueError('web stage request code/policy changed')
    active_id=None
    if (STATE/'active.json').is_file(): active_id=json.loads((STATE/'active.json').read_text()).get('session_id')
    if q.get('session_id')!=active_id: raise ValueError('web stage request session changed')
    q.update(state='STARTED',started=now()); atomic(path,q); WEB_REQUEST=q

def receipt(rid,n,status,valid,h,rc,hashes,code,sid):
    d=STATE/'receipts'; d.mkdir(mode=0o700,exist_ok=True)
    binding={k:WEB_REQUEST[k] for k in ('request_id','flow_id')} if WEB_REQUEST else {}
    atomic(d/(rid+'.json'),dict(run_id=rid,stage=n,overall=status,valid=valid,manifest_sha256=h,exit_code=rc,policy_hashes=hashes,code_sha256=code,session_id=sid,**binding))

def load_session(check_target=True):
    p=validate(read('isolation_policy.yaml')); verify_only()
    if not (STATE/'active.json').is_file(): raise ValueError('no approved session: review candidate/vendor spec, then run approve --reviewed')
    sid=json.loads((STATE/'active.json').read_text())['session_id']
    if not re.fullmatch(r'session-\d{8}T\d{6}Z-[0-9a-f]{8}',sid): raise ValueError('invalid session id')
    d=STATE/'sessions'/sid; s=json.loads((d/'approval.json').read_text())
    if s['policy_hashes']!=policy_hashes() or s['code_sha256']!=code_hash(): raise ValueError('policy/config/code changed; approve a NEW session and rerun tests')
    if check_target and s['target_fingerprint']!=fingerprint(): raise ValueError('target boot/config fingerprint changed; rediscover and reapprove')
    return p,d,s

def approve():
    p=validate(read('isolation_policy.yaml')); verify_only()
    if '[REDACTED]' in (BASE/'isolation_policy.yaml').read_text(): raise ValueError('policy contains redacted values')
    sid=new_id('session-'); d=STATE/'sessions'/sid; d.mkdir(parents=True)
    atomic(d/'approval.json',{'session_id':sid,'approved_at':now(),'policy_hashes':policy_hashes(),'code_sha256':code_hash(),'target_fingerprint':fingerprint(),'scope':'human-reviewed vendor contract; not automatically derived from observations'})
    atomic(STATE/'active.json',{'session_id':sid}); print('APPROVED SESSION: '+sid+'; all stages must be run for this session')

def entries(d):
    return json.loads((d/'runs.json').read_text()) if (d/'runs.json').exists() else []
def latest(d,stage): return next((x for x in reversed(entries(d)) if x['stage']==stage),None)
def validate_entry(rec):
    if not rec: raise ValueError('no run in active session')
    rid=rec['run_id']; path=BASE/'runs'/rid
    if not re.fullmatch(r'(run|discovery)-\d{8}T\d{6}Z-[0-9a-f]{8}',rid): raise ValueError('invalid recorded run ID')
    if not rec['valid'] or verify(path)!=rec['manifest_sha256']: raise ValueError('run invalid or evidence changed')
    x=json.loads((path/'result.json').read_text())
    if x['run_id']!=rid or x.get('stage')!='CPU-'+rec['stage'] or x['overall']!=rec['overall']: raise ValueError('result mismatch')
    return x

def stage(n,allow_long=False):
    sess=None
    if n=='08' and not allow_long: raise ValueError('CPU-08 needs persistent terminal and --allow-long, not a 1800s automation')
    if n not in ('00','01') or (STATE/'active.json').exists():
        try: sess=load_session()
        except Exception:
            if n not in ('00','01'): raise
            # Discovery/connection remain available after config drift but are not attached to stale sessions.
    if n in ('04','05','06','07','08'):
        p,d,s=sess; validate(p,load=True)
        if WEB_REQUEST and WEB_REQUEST.get('full_measurement') is True:
            from common.stage_gates import allows_active
            for gate in ('02','03')+(('04',) if n!='04' else ()):
                if not allows_active(gate,validate_entry(latest(d,gate))): raise ValueError('CPU-'+gate+' safety prerequisites not verified')
        else:
            if validate_entry(latest(d,'02'))['overall']!='PASS': raise ValueError('CPU-02 must PASS before active load tests')
            if validate_entry(latest(d,'03'))['overall'] not in ('PASS','WARN'): raise ValueError('CPU-03 must PASS/WARN before active load tests')
            if n in ('05','06','07','08') and validate_entry(latest(d,'04'))['overall']!='PASS': raise ValueError('CPU-04 must PASS before VM load tests')
    rid=WEB_REQUEST['run_id'] if WEB_REQUEST else new_id('discovery-' if n=='00' else 'run-'); env=dict(os.environ,CPU_VALIDATION_RUN_ID=rid)
    command=[sys.executable,'-u',str(BASE/'scripts'/STAGES[n])]+(['--continuous-60min'] if n=='08' else [])
    if n=='00':
        # Select the supplier-declared VM; never infer from an unrelated inventory entry.
        v=read('isolation_policy.yaml').get('vm',{}).get('name')
        if v: command += ['--vm',v]
    before=policy_hashes(); before_code=code_hash()
    rc=subprocess.call(command,cwd=BASE,env=env,pass_fds=(LOCK_FD,) if LOCK_FD is not None else ()); path=BASE/'runs'/rid
    status='INCONCLUSIVE'; valid=False; h=None; reason=''
    try:
        h=verify(path); result=json.loads((path/'result.json').read_text()); status=result['overall']
        if result.get('run_id')!=rid or result.get('stage')!='CPU-'+n or status not in ('PASS','WARN','FAIL','INCONCLUSIVE') or not result.get('cases'): raise ValueError('invalid or incomplete stage result')
        if (rc==0)!=(status=='PASS'): raise ValueError('exit/result mismatch')
        if sess:
            _,d,s=sess
            if s['policy_hashes']!=policy_hashes() or s['code_sha256']!=code_hash() or s['target_fingerprint']!=fingerprint(): raise ValueError('configuration/boot changed during test')
        if before!=policy_hashes() or before_code!=code_hash(): raise ValueError('configuration/code changed during stage')
        valid=True
    except Exception as e: reason=clean_text(str(e)); status='INCONCLUSIVE'
    if sess:
        _,d,s=sess; rows=entries(d); rows.append(dict(stage=n,run_id=rid,overall=status,valid=valid,manifest_sha256=h,exit_code=rc,finished=now(),reason=reason)); atomic(d/'runs.json',rows)
    receipt(rid,n,status,valid,h,rc,before,before_code,sess[2]['session_id'] if sess else None)
    print(f'CPU-{n} {status} | exit={rc} | evidence={path} | verified={valid}',flush=True)
    if reason: print('Evidence issue: '+reason)
    return 0 if valid and status=='PASS' else 2 if valid and status=='WARN' else 1

def report():
    p,d,s=load_session(); before=policy_hashes(); before_code=code_hash()
    if WEB_REQUEST: os.environ['CPU_VALIDATION_RUN_ID']=WEB_REQUEST['run_id']
    run=Run('CPU-09'); refs=[]
    for n in STAGES:
        rec=latest(d,n)
        try:
            x=validate_entry(rec); state=x['overall']; run.case('SUM'+n,'CPU-'+n,state,'verified stage evidence',{'run_id':rec['run_id'],'status':state}); refs.append(rec)
        except Exception as e: run.case('SUM'+n,'CPU-'+n,'INCONCLUSIVE','verified stage evidence',str(e))
    run.dump('evidence/session_runs.json',refs); run.dump('environment.json',s); rc=run.finish()
    h=verify(run.path); x=json.loads((run.path/'result.json').read_text()); valid=before==policy_hashes() and before_code==code_hash() and s['target_fingerprint']==fingerprint()
    receipt(run.rid,'09',x['overall'] if valid else 'INCONCLUSIVE',valid,h,rc,before,before_code,s['session_id'])
    return rc if valid else 1
def status08():
    _,d,s=load_session(False); rec=latest(d,'08')
    if rec:
        x=validate_entry(rec); print('CPU-08 '+x['overall']+'; evidence='+str(BASE/'runs'/rec['run_id'])); return 0 if x['overall']=='PASS' else 1
    print('CPU-08 NOT_EXECUTED. Use the persistent controller terminal with: python scripts/run_stage.py 08 --allow-long'); return 1

def workflow(allow_long=False):
    load_session(); result=0
    # Discovery and identity are captured again after explicit approval, under the same session.
    for n in ('01','00','02','03','04','05','06','07')+ (('08',) if allow_long else ()):
        rc=stage(n,allow_long)
        if rc!=0:
            result=rc; print('Workflow stopped at CPU-'+n+'; generating partial report'); break
    rr=report(); return 1 if 1 in (result,rr) else 2 if 2 in (result,rr) else 0

def main():
    global LOCK_FD
    a=argparse.ArgumentParser(); a.add_argument('action',choices=list(STAGES)+['approve','09','13','14','15','workflow','status08']); a.add_argument('--reviewed',action='store_true'); a.add_argument('--allow-long',action='store_true'); x=a.parse_args()
    os.umask(0o077)
    try:
        with (STATE/'run.lock').open('a') as lock:
            try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: raise ValueError('another validation stage is running')
            LOCK_FD=lock.fileno()
            claim_web_request(x.action)
            if x.action=='approve':
                if not x.reviewed: raise ValueError('explicit --reviewed required; compare candidate with supplier contract first')
                approve(); return 0
            if x.action in ('13','14','15'):
                if not WEB_REQUEST or WEB_REQUEST.get('session_id') is not None: raise ValueError('CPU-13 requires web authorization before approval')
                from common.preparation import prepare
                os.environ['CPU_VALIDATION_RUN_ID']=WEB_REQUEST['run_id']
                before=policy_hashes(); code=code_hash(); rc=prepare(WEB_REQUEST)
                rid=WEB_REQUEST['run_id']; path=BASE/'runs'/rid; h=verify(path); result=json.loads((path/'result.json').read_text())
                valid=before==policy_hashes() and code==code_hash() and result.get('stage')=='CPU-'+x.action and result.get('run_id')==rid and (rc==0)==(result.get('overall')=='PASS')
                receipt(rid,x.action,result['overall'],valid,h,rc,before,code,None)
                return rc if valid else 1
            if x.action=='09': return report()
            if x.action=='status08': return status08()
            if x.action=='workflow': return workflow(x.allow_long)
            return stage(x.action,x.allow_long)
    except Exception as e: print('INCONCLUSIVE: '+clean_text(str(e)),file=sys.stderr); return 1
if __name__=='__main__': raise SystemExit(main())
