#!/usr/bin/env python3
"""Single operator, private-network controller for CPU validation V2."""
import os, sys, json, hashlib, hmac, base64, secrets, threading, subprocess, re, fcntl, time, uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError
from urllib.parse import urlsplit, quote, parse_qs
from functools import lru_cache
import yaml
from spec_compare import compare, summary, check_comparison, cpu_set
ROOT=Path(__file__).resolve().parent
ENGINE=Path(os.getenv('CPU_ENGINE',str(ROOT.parent if (ROOT.parent/'scripts/run_stage.py').is_file() else ROOT.parent/'cpu_ai_validation'))).resolve()
AUTO=Path(os.getenv('CPU_AUTOMATIONS',str(ENGINE.parent/'openhands-automations'))).resolve()
PY=os.getenv('CPU_PYTHON',sys.executable)
STATE=ENGINE/'.validation'; WEB=ROOT/'.web-state'; WEB.mkdir(mode=0o700,exist_ok=True)
BASEURL=os.getenv('OH_AUTOMATION_URL','http://127.0.0.1:18001/api/automation/v1').rstrip('/')
KEY=os.getenv('OH_SESSION_KEY',''); PASSWORD=os.getenv('WEB_PASSWORD','')
NO_AUTH=os.getenv('WEB_NO_AUTH','0')=='1'
SUDO=os.getenv('SUT_SUDO_PASSWORD',''); GUARD=threading.RLock(); JOB=None; PENDING=None
NAMES={'00':'CPU-00-Discovery','01':'CPU-01-Connection','02':'CPU-02-Provision','03':'CPU-03-Isolation','04':'CPU-04-Affinity','05':'CPU-05-Scheduling','06':'CPU-06-IRQ','07':'CPU-07-Latency','09':'CPU-09-Report','workflow':'CPU-Isolation-AutoTest','10':'CPU-10-EvidenceAnalysis','11':'CPU-11-FailureAnalysis','12':'CPU-12-FinalReport','13':'CPU-13-EnvironmentPrepare','14':'CPU-14-FaultRecovery','15':'CPU-15-ReadinessCheck'}
ACTIONS=set(NAMES)|{'08','full','approve'}
class RedirectOff(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw): return None
OPENER=build_opener(RedirectOff())
def oh(path='',method='GET'):
    u=urlsplit(BASEURL)
    if u.scheme not in ('http','https') or not u.hostname or u.username or u.password: raise ValueError('invalid configured OpenHands URL')
    headers={'Accept':'application/json'}
    if KEY: headers['X-Session-API-Key']=KEY
    req=Request(BASEURL+path,headers=headers,method=method)
    try:
        with OPENER.open(req,timeout=12) as r:
            b=r.read(2_000_001)
            if len(b)>2_000_000: raise ValueError('OpenHands response too large')
            return json.loads(b) if b else {}
    except HTTPError as e: raise ValueError(f'OpenHands HTTP {e.code}; check endpoint/auth/activation; do not retry dispatch blindly') from None
    except Exception as e: raise ValueError('OpenHands API unavailable or unexpected response: '+type(e).__name__) from None
def rows(x):
    if isinstance(x,list): return x
    if isinstance(x,dict):
        for k in ('items','automations','runs','data','results'):
            if isinstance(x.get(k),list): return x[k]
    raise ValueError('Unknown OpenHands list response; inspect installed API')
def aid(x):
    v=x.get('id') or x.get('automation_id')
    if not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',v): raise ValueError('Invalid automation ID')
    return v
def match(action):
    name=NAMES[action]; listing=rows(oh('?limit=100')); matches=[x for x in listing if isinstance(x,dict) and str(x.get('name','')).casefold()==name.casefold()]
    # Existing exported name can differ for discovery; only accept known alias.
    if action=='00':
        matches=[x for x in listing if isinstance(x,dict) and str(x.get('name','')).casefold() in ('cpu-00-discovery','cpu-00-discovery-automation')]
    if len(matches)>1:
        active_matches=[x for x in matches if (x.get('enabled') is True or str(x.get('state','')).upper()=='ACTIVE') and x.get('enabled') is not False and str(x.get('state','')).upper()!='INACTIVE']
        if len(active_matches)==1: matches=active_matches
    if len(matches)!=1: raise ValueError(f'{name}: expected exactly one active task, found {len(matches)}')
    return matches[0]
def local_prompt(action):
    slug=NAMES[action].lower(); d=AUTO/'automations'/slug/'tarball'/'prompt.txt'
    if action=='00' and not d.exists(): d=AUTO/'automations/cpu-00-discovery-automation/tarball/prompt.txt'
    return d.read_text()
def norm(s): return ' '.join(s.split())
def checked_task(action):
    a=match(action); i=aid(a); d=oh('/'+i)
    if isinstance(d.get('automation'),dict): d=d['automation']
    p=d.get('prompt') or (d.get('preset_metadata') or {}).get('prompt')
    if not isinstance(p,str) or norm(p)!=norm(local_prompt(action)): raise ValueError('Server prompt differs from local reviewed V2 template; sync/review in Canvas first')
    if d.get('enabled') is False or str(d.get('state','')).upper()=='INACTIVE': raise ValueError('Task inactive; activate manually in official Canvas, verify schedule')
    return i
def jsonfile(p,default=None):
    try: return json.loads(p.read_text())
    except (OSError,ValueError): return default
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():
    paths=[ENGINE/'config.yaml',ENGINE/'isolation_policy.yaml',ENGINE/'provision_policy.yaml',ENGINE/'scripts/run_stage.py']+sorted((ENGINE/'scripts').glob('*.py'))+sorted((ENGINE/'common').glob('*.py'))
    candidate=latest_discovery()
    for name in ('supplier.json','target-change.json'):
        if (WEB/name).is_file(): paths.append(WEB/name)
    if candidate:
        d=ENGINE/'runs'/candidate['id']; paths.extend([d/'isolation_policy.detected.yaml',d/'result.json',d/'SHA256SUMS'])
    return hashlib.sha256(''.join(str(p.relative_to(ENGINE) if p.is_relative_to(ENGINE) else p.name)+':'+sha(p)+'\n' for p in paths).encode()).hexdigest()
def policy(): return yaml.safe_load((ENGINE/'isolation_policy.yaml').read_text())
def active():
    a=jsonfile(STATE/'active.json',{}) or {}; sid=a.get('session_id','')
    if not re.fullmatch(r'session-\d{8}T\d{6}Z-[0-9a-f]{8}',sid): return None,[]
    d=STATE/'sessions'/sid; s=jsonfile(d/'approval.json')
    if not s: return None,[]
    try: current=all(sha(ENGINE/k)==v for k,v in s['policy_hashes'].items() if k in ('config.yaml','isolation_policy.yaml','provision_policy.yaml')) and set(s['policy_hashes'])=={'config.yaml','isolation_policy.yaml','provision_policy.yaml'}
    except Exception: current=False
    # Match the V2 engine code hash, not the broader review digest.
    files=['discover_sut.py','connect_sut.py','check_vendor_preflight.py','check_isolation.py','check_affinity.py','check_scheduling.py','check_irq.py','check_latency.py','check_stability.py']
    try:
        paths=[ENGINE/'scripts'/f for f in files]+[ENGINE/'scripts/run_stage.py']+sorted((ENGINE/'common').glob('*.py'))
        current=current and hashlib.sha256(''.join(str(p.relative_to(ENGINE))+':'+sha(p)+'\n' for p in paths).encode()).hexdigest()==s['code_sha256']
    except Exception: current=False
    return {'session_id':sid,'approved_at':s.get('approved_at'),'local_current':current},jsonfile(d/'runs.json',[]) or []
def latest_discovery():
    for d in sorted((ENGINE/'runs').glob('discovery-*'),key=lambda p:(p.stat().st_mtime_ns,p.name),reverse=True):
        p=d/'isolation_policy.detected.yaml'; r=jsonfile(d/'result.json',{}) or {}
        if p.is_file() and r.get('overall')=='PASS' and r.get('stage')=='CPU-00' and r.get('run_id')==d.name and (d/'SHA256SUMS').is_file():
            try:
                value=yaml.safe_load(p.read_text())
                if isinstance(value,dict): return {'id':d.name,'policy':value}
            except (OSError,yaml.YAMLError): pass
    return None
def comparison(p=None,candidate=None):
    p=policy() if p is None else p
    candidate=latest_discovery() if candidate is None else candidate
    if not candidate: return {'rows':compare(p,{},None),'verified':False,'error':'暂无 PASS 探测，请先运行 CPU-00'}
    try:
        verify_candidate(candidate)
        # Do not allow an earlier successful scan to conceal a later unsuccessful attempt.
        latest=next(iter(sorted((ENGINE/'runs').glob('discovery-*'),key=lambda p:(p.stat().st_mtime_ns,p.name),reverse=True)),None)
        if latest is None or latest.name!=candidate['id']: raise ValueError('最新一次探测未通过，请重新探测')
        marker=jsonfile(WEB/'target-change.json',{}) or {}
        if marker.get('changed_ns') and (ENGINE/'runs'/candidate['id']/'result.json').stat().st_mtime_ns<=marker['changed_ns']: raise ValueError('连接参数已变化，请重新运行 CPU-00')
        if not marker.get('changed_ns') and candidate['id']==marker.get('previous'): raise ValueError('连接参数已变化，请重新运行 CPU-00')
        folder=ENGINE/'runs'/candidate['id']
        environment=jsonfile(folder/'environment.json',{}) or {}
        target=yaml.safe_load((ENGINE/'config.yaml').read_text()) or {}
        if not target.get('host') or not target.get('ssh_user'):
            raise ValueError('当前连接配置不完整')
        target_hash = hashlib.sha256(json.dumps([str(target['host']),str(target['ssh_user']),int(target.get('ssh_port',22))],separators=(',',':')).encode()).hexdigest()
        if environment.get('target_sha256') != target_hash:
            raise ValueError('探测目标校验失败或缺少新版连接校验证据，请重新探测')
        observed=jsonfile(folder/'observed.json',{}) or {}
        result=compare(p,candidate['policy'],observed.get('realtime'))
        for row in result:
            if row['path']=='isolated_cpus' and observed.get('isolated')=='': row.update(actual='',status='MISMATCH')
        # Candidate VM fields are persistent XML, not runtime thread affinity.
        inventory=jsonfile(folder/'vm_config.json',[]) or []
        selected=next((x for x in inventory if x.get('name')==p['vm']['name']),None)
        if selected and selected.get('state')=='running':
            live=selected.get('live') or {}
            for row in compare(p,{'vm':live},observed.get('realtime')):
                if row['path'].startswith('vm.'):
                    result.append({**row,'path':'live.'+row['path'],'label':'运行配置 / '+row['label']})
        if not selected or selected.get('state')!='running':
            result.append({'path':'vm.running','label':'KVM 运行状态','expected':'running','actual':selected.get('state') if selected else None,'status':'MISMATCH' if (selected and selected.get('state')) or (not selected and observed.get('vm_inventory_complete') is True) else 'UNKNOWN'})
        return {'rows':result,'summary':summary(result),'verified':True,'candidate_id':candidate['id']}
    except Exception as e:
        return {'rows':compare(p,{},None),'verified':False,'error':redact(str(e))}

def device():
    cfg=yaml.safe_load((ENGINE/'config.yaml').read_text()) or {}
    return {k:cfg.get(k,22 if k=='ssh_port' else '') for k in ('host','ssh_user','ssh_port')}

def validate_device(changes):
    if not isinstance(changes,dict) or set(changes)!={'host','ssh_user','ssh_port'}: raise ValueError('Invalid connection fields')
    host,user,port=(changes[k] for k in ('host','ssh_user','ssh_port'))
    if not isinstance(host,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}',host) or host.startswith('-'): raise ValueError('无效主机地址')
    if not isinstance(user,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',user): raise ValueError('无效 SSH 用户')
    if type(port) is not int or not 1<=port<=65535: raise ValueError('无效 SSH 端口')
    return changes

def update_device(d):
    if d.get('review_hash')!=snapshot() or d.get('confirmed') is not True: raise ValueError('请确认当前连接配置后再保存')
    changes=validate_device(d.get('device'))
    if changes==device(): return {'saved':True,'changed':False}
    STATE.mkdir(mode=0o700,exist_ok=True)
    with (STATE/'run.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if d['review_hash']!=snapshot(): raise ValueError('Configuration changed')
        cfg=yaml.safe_load((ENGINE/'config.yaml').read_text()); cfg.update(changes)
        previous=next(iter(sorted((ENGINE/'runs').glob('discovery-*'),key=lambda p:(p.stat().st_mtime_ns,p.name),reverse=True)),None)
        marker=WEB/'target-change.tmp';marker.write_text(json.dumps({'previous':previous.name if previous else '', 'changed_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'changed_ns':time.time_ns()}));marker.chmod(0o600);marker.replace(WEB/'target-change.json')
        tmp=ENGINE/'config.web.tmp';tmp.write_text(yaml.safe_dump(cfg,sort_keys=False,allow_unicode=True));tmp.chmod(0o600);tmp.replace(ENGINE/'config.yaml')
        (STATE/'active.json').unlink(missing_ok=True)
    audit('device_changed');return {'saved':True,'changed':True}

def supplier():
    s=jsonfile(WEB/'supplier.json',{}) or {}
    return {**s,'current':bool(s.get('policy_sha256')==sha(ENGINE/'isolation_policy.yaml'))}

def verify_candidate(candidate):
    sys.path.insert(0,str(ENGINE)); from common.evidence import verify
    return verify(ENGINE/'runs'/candidate['id'])
def tail(p,n=40000):
    if not p.is_file(): return ''
    with p.open('rb') as f: f.seek(max(0,p.stat().st_size-n)); return f.read().decode(errors='replace')
def redact(s):
    for k in (SUDO,KEY,PASSWORD):
        if k: s=s.replace(k,'[REDACTED]')
    return s
def audit(event,**kw):
    with (WEB/'audit.jsonl').open('a') as f: f.write(json.dumps({'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'operator':'operator','event':event,**kw},ensure_ascii=False)+'\n')
def engine_busy():
    STATE.mkdir(mode=0o700,exist_ok=True)
    with (STATE/'run.lock').open('a') as f:
        try: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB); return False
        except BlockingIOError: return True
        finally: fcntl.flock(f,fcntl.LOCK_UN)
def pending_status():
    global PENDING
    if not PENDING: return None
    p=dict(PENDING)
    if p.get('run_id'):
        try:
            rs=rows(oh('/'+p['automation_id']+'/runs?limit=100')); found=next((r for r in rs if str(r.get('id') or r.get('run_id'))==p['run_id']),None)
            if found:
                p['status']=str(found.get('status') or found.get('state') or 'UNKNOWN').upper()
                if p['status'] in ('COMPLETED','FAILED','CANCELLED','CANCELED','TIMED_OUT','TIMEOUT','SUCCESS','ERROR'):
                    audit('openhands_run_terminal',action=p['action'],run_id=p['run_id'],status=p['status']); PENDING=None; (WEB/'pending.json').unlink(missing_ok=True)
        except Exception: p['status']='UNKNOWN (API unavailable)'
    return p
def guard_idle():
    if (STATE/'web-stage-request.json').is_file(): raise ValueError('上次阶段请求尚未核销；请确认 Canvas 无排队/运行任务后人工解除')
    if JOB and JOB['process'].poll() is None: raise ValueError('Local task already running')
    p=pending_status()
    if PENDING: raise ValueError('OpenHands dispatch pending/unknown; reconcile in official Canvas before another task')
    if engine_busy(): raise ValueError('Test engine busy')
def ensure_approval(action):
    if action not in ('00','01','approve'):
        s,_=active()
        if not s or not s['local_current'] or not supplier()['current']: raise ValueError('No current human-approved session / supplier specification')
        if action!='09':
            c=comparison()
            if not c['verified']: raise ValueError(c.get('error','探测证据未验证'))
            check_comparison(c['rows'])
        if action in ('04','05','06','07','08','workflow','full') and policy().get('allow_load_tests') is not True: raise ValueError('CPU/KVM load not authorized')
def start_local(action):
    global JOB
    args=[PY,'-u',str(ENGINE/'scripts/run_stage.py'), 'workflow' if action=='full' else action]
    if action=='approve': args+=['--reviewed']
    if action in ('08','full'): args+=['--allow-long']
    jid=uuid.uuid4().hex; logfile=WEB/(jid+'.log'); env={k:v for k,v in os.environ.items() if k not in ('WEB_PASSWORD','OH_SESSION_KEY','SUT_SSH_PASSWORD')}; env['SUT_SUDO_PASSWORD']=SUDO
    with logfile.open('wb') as f: proc=subprocess.Popen(args,cwd=ENGINE,env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
    JOB={'id':jid,'action':action,'process':proc,'log':logfile}; audit('local_start',action=action,job=jid)
    def finish():
        rc=proc.wait()
        with GUARD:
            sess,_=active() if action=='approve' and rc==0 else (None,[])
            audit('local_exit',action=action,job=jid,exit_code=rc,session_id=sess['session_id'] if sess else None)
    threading.Thread(target=finish,daemon=True).start()
    return {'job':jid,'action':action,'state':'RUNNING'}
def dispatch(action):
    global PENDING
    i=checked_task(action); PENDING={'automation_id':i,'action':action,'status':'DISPATCHING','run_id':None}; (WEB/'pending.json').write_text(json.dumps(PENDING))
    # Persist before request; ambiguous transport errors never cause automatic retry.
    result=oh('/'+i+'/dispatch','POST'); r=result.get('run',result) if isinstance(result,dict) else {}; rid=r.get('run_id') or r.get('id')
    PENDING.update(status='ACCEPTED' if rid else 'UNKNOWN (inspect Canvas)',run_id=str(rid) if rid else None); (WEB/'pending.json').write_text(json.dumps(PENDING)); audit('openhands_dispatch',action=action,automation_id=i,run_id=PENDING['run_id']); return dict(PENDING)
def build_policy(d):
    p=policy(); allowed={'test_cpu','guest_user','guest_mac','guest_ip','max_latency_us','allow_load_tests','allow_io_test','online_cpus','housekeeping_cpus','isolated_cpus','kthread_cpus','vm_name','vcpu_count','vcpu_pinning','emulator_cpus','priority','interval_us','short_duration_s','long_duration_s','compare_isolated_cores','isolation_mechanism'}
    ref=d.get('reference','')
    if not isinstance(ref,str) or not ref.strip() or len(ref)>200: raise ValueError('请填写供应商正式规格版本或编号')
    if d.get('supplier_confirmed') is not True: raise ValueError('请确认预期值来自供应商正式规格，而非自动探测')
    if set(d.get('changes',{}))-allowed: raise ValueError('Unsupported policy fields')
    for k,v in d['changes'].items():
        if k in ('online_cpus','housekeeping_cpus','isolated_cpus','kthread_cpus','emulator_cpus') and isinstance(v,str): v=','.join(x.strip() for x in v.split(','))
        if k=='vcpu_pinning' and isinstance(v,dict): v={int(i):','.join(x.strip() for x in c.split(',')) if isinstance(c,str) else c for i,c in v.items()}
        if k.startswith('guest_') or k in ('vcpu_count','vcpu_pinning','emulator_cpus'): p['vm'][k]=v
        elif k=='vm_name': p['vm']['name']=v
        elif k in ('max_latency_us','priority','interval_us','short_duration_s','long_duration_s','compare_isolated_cores'): p['realtime'][k]=v
        else: p[k]=v
    if type(p.get('allow_load_tests')) is not bool or type(p.get('allow_io_test')) is not bool or (p['allow_io_test'] and not p['allow_load_tests']): raise ValueError('Invalid load authorization')
    sys.path.insert(0,str(ENGINE)); from common.policy import validate
    if type(p['realtime'].get('compare_isolated_cores',False)) is not bool: raise ValueError('invalid compare_isolated_cores')
    validate(p)
    return p,ref

def update_policy(d):
    if d.get('review_hash')!=snapshot(): raise ValueError('Configuration changed; reload before saving')
    p,ref=build_policy(d)
    STATE.mkdir(mode=0o700,exist_ok=True)
    with (STATE/'run.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if d['review_hash']!=snapshot(): raise ValueError('Configuration changed')
        tmp=ENGINE/'isolation_policy.web.tmp'; tmp.write_text(yaml.safe_dump(p,sort_keys=False,allow_unicode=True)); tmp.chmod(0o600); tmp.replace(ENGINE/'isolation_policy.yaml')
        meta={'reference':redact(ref.strip()),'version':uuid.uuid4().hex,'saved_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'policy_sha256':sha(ENGINE/'isolation_policy.yaml')}
        versions=WEB/'supplier-versions'; versions.mkdir(mode=0o700,exist_ok=True)
        versionfile=versions/(meta['version']+'.json'); versionfile.write_text(json.dumps({'metadata':meta,'policy':p},ensure_ascii=False,indent=2)); versionfile.chmod(0o600)
        tmp=WEB/'supplier.tmp'; tmp.write_text(json.dumps(meta,ensure_ascii=False)); tmp.chmod(0o600); tmp.replace(WEB/'supplier.json')
        # Explicitly invalidate even when values stayed unchanged but supplier evidence changed.
        (STATE/'active.json').unlink(missing_ok=True)
    audit('policy_saved',review_hash=snapshot()); return {'saved':True,'review_hash':snapshot()}
def flow_module():
    sys.path.insert(0,str(ENGINE))
    import flow
    return flow

def status():
    fl=flow_module(); f=fl.get(); j=None
    if JOB:
        rc=JOB['process'].poll(); j={'id':JOB['id'],'action':JOB['action'],'exit_code':rc,'state':'RUNNING' if rc is None else 'EXITED','log':redact(tail(JOB['log']))}
    # Polling the browser must never consume an OpenHands terminal state while the workflow is waiting.
    return {'device':device(),'policy':policy(),'supplier':supplier(),'review_hash':snapshot(),'flow':fl.public(f) if f else None,'job':j,'openhands_run':dict(PENDING) if PENDING else None,'engine_busy':engine_busy(),'workflow_busy':fl.running(),'unreconciled_request':(STATE/'web-stage-request.json').is_file() and not fl.running(),'live_log':redact(tail(ENGINE/'logs/live.log'))}
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def reply(self,status,obj,ctype='application/json; charset=utf-8',download=None):
        b=json.dumps(obj,ensure_ascii=False).encode() if ctype.startswith('application/json') else obj
        self.send_response(status); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(b)));
        if download: self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+quote(download,safe=''))
        self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'"); self.end_headers(); self.wfile.write(b)
    def auth(self):
        if NO_AUTH:
            # Only the local host bridge or a local browser may access this mode.
            if self.client_address[0]=='127.0.0.1' and self.headers.get('Host','') in (f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'):
                return True
            self.reply(403,{'error':'Passwordless mode is loopback only'}); return False
        expected='Basic '+base64.b64encode(('operator:'+PASSWORD).encode()).decode()
        if hmac.compare_digest(self.headers.get('Authorization',''),expected): return True
        self.send_response(401); self.send_header('WWW-Authenticate','Basic realm="CPU Validation"'); self.send_header('Content-Length','0'); self.end_headers(); return False
    def do_GET(self):
        if not self.auth(): return
        try:
            path=urlsplit(self.path).path
            if path in ('/','/app.js','/style.css'):
                f={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}[path]; self.reply(200,(ROOT/'static'/f).read_bytes(),{'index.html':'text/html; charset=utf-8','app.js':'application/javascript; charset=utf-8','style.css':'text/css; charset=utf-8'}[f]); return
            with GUARD:
                if path=='/api/status': self.reply(200,status()); return
                if path=='/api/openhands': self.reply(200,[{k:x.get(k) for k in ('id','automation_id','name','enabled','state','model')} for x in rows(oh('?limit=100')) if isinstance(x,dict)]); return
                if path=='/api/audit': self.reply(200,{'text':redact(tail(WEB/'audit.jsonl'))}); return
                if path=='/api/history': self.reply(200,flow_module().history()); return
                if path.startswith('/api/flow-report/'):
                    self.reply(200,flow_module().scrub_values(flow_module().report(flow_module().archived(path.split('/')[-1])))); return
                if path in ('/api/evidence','/api/evidence-zip'):
                    q=parse_qs(urlsplit(self.path).query); fl=flow_module(); fid=q.get('flow',[''])[0]; rid=q.get('run',[''])[0]; f=fl.archived(fid)
                    fl.authorize_run(f,rid)
                    if path=='/api/evidence-zip':
                        self.reply(200,fl.evidence_zip(rid),'application/zip',download=rid+'.zip'); return
                    name=q.get('file',[''])[0]
                    if q.get('download')==['1']:
                        self.reply(200,fl.evidence(rid,name,raw=True),'application/octet-stream',download=Path(name).name); return
                    self.reply(200,{'text':fl.evidence(rid,name)}); return
                if path.startswith('/api/report/'):
                    rid=path.split('/')[-1]
                    if not re.fullmatch(r'(run|discovery)-\d{8}T\d{6}Z-[0-9a-f]{8}',rid): raise ValueError('Invalid run ID')
                    p=ENGINE/'runs'/rid
                    if not (p/'report.md').is_file(): raise ValueError('Report unavailable')
                    self.reply(200,{'text':redact((p/'report.md').read_text())}); return
            self.reply(404,{'error':'Not found'})
        except Exception as e: self.reply(400,{'error':redact(str(e))})
    def do_POST(self):
        global PENDING
        if not self.auth(): return
        try:
            if self.headers.get('X-CPU-Request')!='1' or self.headers.get('Content-Type','').split(';')[0]!='application/json': raise ValueError('Invalid request protection header')
            origin=self.headers.get('Origin'); host=self.headers.get('Host')
            if origin and urlsplit(origin).netloc!=host: raise ValueError('Cross-origin request blocked')
            n=int(self.headers.get('Content-Length','0'))
            if not 0<n<=32768: raise ValueError('Invalid body size')
            d=json.loads(self.rfile.read(n)); path=urlsplit(self.path).path
            with GUARD:
                fl=flow_module(); current=fl.get()
                if path=='/api/reconcile':
                    if fl.running() or d.get('confirmed') is not True or engine_busy(): raise ValueError('请先在 Canvas 确认无运行或排队任务')
                    PENDING=None; (WEB/'pending.json').unlink(missing_ok=True); (STATE/'web-stage-request.json').unlink(missing_ok=True); audit('manual_reconcile'); out={'cleared':True}
                elif path=='/api/flow/approve': out=fl.public(fl.approve(d))
                elif path=='/api/flow/cancel': out=fl.public(fl.cancel(d))
                elif path=='/api/flow/final-review': out=fl.final_review(d)
                else:
                    if fl.running(): raise ValueError('当前验收流程正在执行')
                    if current and current['state']=='WAITING_APPROVAL': raise ValueError('请先审批或放弃当前流程')
                    guard_idle()
                    if path=='/api/flow/start':
                        if d.get('review_hash')!=snapshot() or d.get('confirmed') is not True or d.get('mode') not in ('local','openhands'): raise ValueError('请确认当前供应商规格及执行模式')
                        validate_device(d.get('device')); build_policy(d)
                        update_device({'review_hash':snapshot(),'device':d['device'],'confirmed':True})
                        update_policy({**d,'review_hash':snapshot()})
                        out=fl.public(fl.begin({**d,'review_hash':snapshot()}))
                    elif path in ('/api/device','/api/policy','/api/approve','/api/run'):
                        raise ValueError('V3.2 仅允许通过顺序验收流程执行，请刷新页面')
                    else: raise ValueError('Unknown operation')
            self.reply(200,out)
        except Exception as e: self.reply(400,{'error':redact(str(e))})
if __name__=='__main__':
    sys.modules['server']=sys.modules[__name__]
    os.umask(0o077)
    bind=os.getenv('WEB_BIND','127.0.0.1'); port=int(os.getenv('WEB_PORT','8080'))
    if NO_AUTH and bind!='127.0.0.1': sys.exit('Passwordless mode requires WEB_BIND=127.0.0.1')
    if not NO_AUTH and len(PASSWORD)<12: sys.exit('WEB_PASSWORD must contain at least 12 characters')
    if not (ENGINE/'scripts/run_stage.py').is_file(): sys.exit('V2 engine not found: '+str(ENGINE))
    lock=(WEB/'server.lock').open('a'); fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    PENDING=jsonfile(WEB/'pending.json')
    flow_module().recover()
    bind=os.getenv('WEB_BIND','127.0.0.1'); port=int(os.getenv('WEB_PORT','8080'))
    print(f'CPU Validation Web listening on {bind}:{port}',flush=True); ThreadingHTTPServer((bind,port),Handler).serve_forever()
