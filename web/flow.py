"""Sequential, single-operator acceptance controller. All decisions use sealed engine evidence."""
import json, os, re, time, uuid, threading, hashlib, subprocess, sys, fcntl, zipfile, io
from pathlib import Path
from spec_compare import check_comparison
from common.evidence import verify, new_id
from common.policy import policy_hashes
import server as s
# server is imported as a module by the entrypoint below, not a second __main__ instance.
STAGES=['01','00','02','03','04','05','06','07','08']
TERMINAL={'PASS','FAIL','INCONCLUSIVE'}
PLANS={
'14':('故障诊断与恢复','初次准备证据及单独重启授权','虚拟机状态、资源、SSH超时证据','复核Guest；仅在已授权且实际SSH超时时正常重启一次，不强制断电。'),
'15':('环境就绪复核','Guest身份、CPU及工具要求','最新只读就绪证据','不改变VM状态；重新验证Guest连接和实际绑定。'),
'13':('环境准备','指定VM及明确启动授权','初始状态、启动命令、Guest就绪记录','只在关机且持久绑定及CPU范围一致时启动一次；最多三次只读Guest检查；不自动重启、安装或改配置。'),
'01':('连接认证','预期主机、用户及可信主机密钥','实际 SSH、sudo UID','严格主机密钥校验；采集 hostname、登录身份、内核和 sudo 身份；核对返回码。'),
'00':('环境探测','供应商独立填写的 CPU、RT、KVM 规格','sysfs、启动参数、libvirt XML','只读采集 CPU 拓扑、隔离集合、内核参数、中断、虚拟机持久及运行配置；自动比对。'),
'02':('环境预检','正式策略、工具及 Guest 可用性要求','实际工具、VM 配置、Guest SSH','只读检查宿主机工具、RT 内核、KVM 绑定、Guest 连接；不安装或启动服务。'),
'03':('核心隔离','批准的隔离范围及绑定要求','sysfs、IRQ、workqueue、VM XML','检查隔离集合、启动参数、内核线程、IRQ 和虚拟机配置；不改变隔离设置。'),
'04':('线程亲和性','预期 CPU 集合','实际任务及 QEMU 线程亲和性','运行受限临时任务，采样实际 CPU；核对 QMP vCPU 线程与亲和性。'),
'05':('调度隔离','普通任务基线与默认亲和性','扩展亲和性、宿主机及 Guest 负载','在不同调度及负载条件采集 CPU 样本和繁忙度，比较普通任务进入隔离区的次数。'),
'06':('设备中断隔离','空闲对照窗口','宿主机、KVM、经授权的 I/O 压力窗口','记录每组前后 /proc/interrupts 与负载证据；比较隔离核心设备 IRQ 增量；本地中断/IPI 单列。'),
'07':('实时延迟','无主动压力 cyclictest','宿主机、Guest、两者联合压力 cyclictest','相同实时核心、FIFO 优先级、周期和时长；验证负载、线程亲和性及周期数；比较最小、平均、最大延迟。'),
'08':('连续稳定性','CPU-07 Guest 压力短测','Guest 压力下连续3600秒 cyclictest','连续运行，验证负载覆盖、周期数、FIFO 亲和性及最大延迟；保留全程原始记录。'),
'09':('综合验收','全部必需阶段及已批准阈值','已封存的本会话证据','核验各阶段证据哈希；任何失败优先于未完成；不得将报告生成等同验收通过。')}
AGENTS=['10','11','12']
AGENT_NAMES={'10':'CPU-10-EvidenceAnalysis','11':'CPU-11-FailureAnalysis','12':'CPU-12-FinalReport'}
THREAD=None

def atomic(p,x):
    p.parent.mkdir(mode=0o700,parents=True,exist_ok=True); t=p.with_name(p.name+'.tmp'); t.write_text(json.dumps(x,ensure_ascii=False,indent=2)); t.chmod(0o600); t.replace(p)
def get(): return s.jsonfile(s.WEB/'flow.json')
def save(f): atomic(s.WEB/'flow.json',f); atomic(folder(f)/'state.json',f)
def folder(f): return s.WEB/'flows'/f['id']
def now(): return time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
def running(): return THREAD is not None and THREAD.is_alive()
def code_digest():
    paths=sorted((s.ENGINE/'scripts').glob('*.py'))+sorted((s.ENGINE/'common').glob('*.py'))+sorted(s.ROOT.glob('*.py'))
    return hashlib.sha256(''.join(str(p)+':'+s.sha(p)+'\n' for p in paths).encode()).hexdigest()

def engine_hash():
    files=['discover_sut.py','connect_sut.py','check_vendor_preflight.py','check_isolation.py','check_affinity.py','check_scheduling.py','check_irq.py','check_latency.py','check_stability.py']
    paths=[s.ENGINE/'scripts'/f for f in files]+[s.ENGINE/'scripts/run_stage.py']+sorted((s.ENGINE/'common').glob('*.py'))
    return hashlib.sha256(''.join(str(p.relative_to(s.ENGINE))+':'+s.sha(p)+'\n' for p in paths).encode()).hexdigest()

def assert_unchanged(f):
    if f['code_digest']!=code_digest(): raise ValueError('验收执行代码已变化，须重新开始')
    if f['config']!={k:s.sha(s.ENGINE/k) for k in ('config.yaml','isolation_policy.yaml','provision_policy.yaml')}: raise ValueError('正式规格或目标配置已变化，必须重新开始验收')
    if f['supplier_version']!=s.supplier().get('version'): raise ValueError('供应商规格版本已变化')
def paths(): return {p.name for p in (s.ENGINE/'runs').glob('*') if p.is_dir()}
def sealed(rid,stage=None):
    if not re.fullmatch(r'(run|discovery)-\d{8}T\d{6}Z-[0-9a-f]{8}',rid): raise ValueError('invalid run ID')
    p=s.ENGINE/'runs'/rid; h=verify(p); r=json.loads((p/'result.json').read_text())
    if r.get('run_id')!=rid or (stage and r.get('stage')!='CPU-'+stage) or r.get('overall') not in ('PASS','WARN','FAIL','INCONCLUSIVE') or not r.get('cases'): raise ValueError('invalid result schema')
    return p,h,r

def fresh(before,stage):
    found=[]
    for rid in paths()-before:
        p=s.ENGINE/'runs'/rid; r=s.jsonfile(p/'result.json',{}) or {}
        if r.get('stage')=='CPU-'+stage: found.append(rid)
    if len(found)!=1: raise ValueError(f'CPU-{stage}: expected exactly one fresh result, found {len(found)}')
    p,h,r=sealed(found[0],stage); return dict(stage=stage,run_id=found[0],manifest=h,status=r['overall'])

def local(action):
    with s.GUARD:
        j=s.start_local(action); proc=s.JOB['process']
    return proc.wait()
def remote(action):
    with s.GUARD: s.dispatch(action)
    deadline=time.monotonic()+1900
    while time.monotonic()<deadline:
        with s.GUARD:
            p=s.pending_status(); pending=s.PENDING
        if not pending:
            if not p or p.get('status') not in ('COMPLETED','SUCCESS'): raise ValueError('OpenHands execution did not complete: '+str(p))
            return
        time.sleep(3)
    raise ValueError('OpenHands run unresolved; inspect official Canvas, do not retry blindly')

def stage(f,n):
    assert_unchanged(f); f['current']=n; save(f)
    rid=new_id('discovery-' if n=='00' else 'run-'); token=uuid.uuid4().hex
    request={'state':'READY','flow_id':f['id'],'request_id':token,'stage':n,'run_id':rid,'policy_hashes':f['config'],'code_sha256':engine_hash(),'session_id':f.get('session_id'),'created':now()}
    if f.get('full_measurement'): request['full_measurement']=True
    if n=='13': request['allow_vm_start']=f.get('allow_vm_start') is True
    if n=='14':
        request['allow_vm_reboot']=f.get('allow_vm_reboot') is True
        request['prior_preparation']=next((dict(run_id=x['run_id'],manifest=x['manifest']) for x in reversed(f['runs']) if x['stage']=='13'),None)
    reqpath=s.STATE/'web-stage-request.json'
    with s.GUARD:
        s.guard_idle()
        with (s.STATE/'run.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            atomic(reqpath,request)
    error=None; rc=None
    try:
        try:
            if f['mode']=='openhands' and n not in ('08','09'): remote(n)
            else: rc=local(n)
        except Exception as e: error=str(e)
        try:
            p,h,r=sealed(rid,n)
            rec=dict(stage=n,run_id=rid,manifest=h,status=r['overall'],request_id=token)
        except Exception as e:
            f['stage_error']={'stage':n,'run_id':rid,'reason':s.redact(error or str(e))}; save(f)
            raise ValueError(error or '阶段未产生完整可校验证据: '+str(e))
        receipt=s.jsonfile(s.STATE/'receipts'/(rid+'.json'),{}) or {}
        checks={'stage':n,'run_id':rid,'manifest_sha256':h,'overall':rec['status'],'policy_hashes':f['config'],'session_id':f.get('session_id'),'request_id':token,'flow_id':f['id'],'code_sha256':request['code_sha256']}
        if not receipt.get('valid') or any(receipt.get(k)!=v for k,v in checks.items()):
            error=error or 'runner receipt missing, invalid or not bound to this request'
        if rc is not None and (rc==0)!=(rec['status']=='PASS'):
            error=error or 'process exit and sealed result disagree'
        if f.get('session_id') and n!='09':
            a,rs=s.active(); rr=[x for x in rs if x.get('run_id')==rid and x.get('stage')==n]
            if not a or a['session_id']!=f['session_id'] or len(rr)!=1 or not rr[0].get('valid') or rr[0].get('manifest_sha256')!=h or rr[0].get('overall')!=rec['status']:
                error=error or 'result not bound to current approved session'
        if error: rec['controller_error']=s.redact(error)
        f['runs'].append(rec); save(f)
        if error: raise Stop('FAIL' if rec['status']=='FAIL' else 'INCONCLUSIVE',error)
        assert_unchanged(f); return rec
    finally:
        # Do not clear a request if a transport failure may have left a queued/running action.
        with s.GUARD:
            if not s.PENDING and not s.engine_busy():
                q=s.jsonfile(reqpath,{}) or {}
                if q.get('request_id')==token: reqpath.unlink(missing_ok=True)

def require_pass(rec):
    if rec['status']!='PASS': raise Stop(rec['status'],f"CPU-{rec['stage']} {rec['status']}")
class Stop(Exception):
    def __init__(self,status,message): self.status=status if status in TERMINAL else 'INCONCLUSIVE'; super().__init__(message)

def begin(d):
    global THREAD
    s.guard_idle()
    if running(): raise ValueError('已有流程正在执行')
    if d.get('confirmed') is not True or d.get('review_hash')!=s.snapshot() or not s.supplier().get('current'): raise ValueError('请先保存并确认独立供应商规格')
    if d.get('mode') not in ('local','openhands'): raise ValueError('invalid execution mode')
    p=s.policy(); from common.policy import validate,verify_only
    validate(p); verify_only()
    if d['mode']=='openhands':
        rt=p['realtime']; extra=len(s.cpu_set(p['isolated_cpus']))-1 if rt.get('compare_isolated_cores') else 0
        if (4+extra)*(rt.get('short_duration_s',60)+130)+180>1800: raise ValueError('CPU-07 计划可能超过 Automation 1800 秒上限；缩短经确认的短测时长、取消额外核心比较或选择固定 Python 模式')
    # Never reuse approval/evidence from previous run. Preserve previous session archive.
    s.STATE.mkdir(mode=0o700,exist_ok=True)
    with (s.STATE/'run.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        (s.STATE/'active.json').unlink(missing_ok=True)
    f=dict(id='flow-'+uuid.uuid4().hex,created=now(),state='DISCOVERING',current='01',mode=d['mode'],supplier_version=s.supplier()['version'],reference=s.supplier()['reference'],device=s.device(),policy=p,code_digest=code_digest(),config={k:s.sha(s.ENGINE/k) for k in ('config.yaml','isolation_policy.yaml','provision_policy.yaml')},runs=[],agents=[],comparison=None,session_id=None)
    f['allow_vm_start']=d.get('allow_vm_start') is True; f['allow_vm_reboot']=d.get('allow_vm_reboot') is True; f['full_measurement']=True
    save(f); s.audit('flow_environment_authorization',flow=f['id'],allow_vm_start=f['allow_vm_start'],allow_vm_reboot=f['allow_vm_reboot'],vm=s.redact(p['vm']['name'])); THREAD=threading.Thread(target=discover,args=(f,),daemon=True); THREAD.start(); return f

def candidate_for_run(rid):
    import yaml
    p,_,_=sealed(rid,'00'); value=yaml.safe_load((p/'isolation_policy.detected.yaml').read_text())
    if not isinstance(value,dict): raise ValueError('invalid discovery candidate')
    return {'id':rid,'policy':value}

def discover(f):
    try:
        require_pass(stage(f,'01')); rec=stage(f,'00')
        assert_unchanged(f)
        c=s.comparison(candidate=candidate_for_run(rec['run_id'])); f['comparison']=c; save(f)
        if not c.get('verified'): raise Stop('INCONCLUSIVE',c.get('error','未验证探测证据'))
        if f.get('full_measurement'):
            require_pass(rec)
            f['initial_comparison']=c; save(f)
            # Preparation has independent authorization. Even if readiness fails, keep evidence and permit safe diagnostics.
            try:
                prep=stage(f,'13')
                f['preparation_status']=prep['status']; save(f)
                if prep['status']!='PASS': stage(f,'14')
                ready=stage(f,'15'); f['readiness_status']=ready['status']; save(f)
                rec=stage(f,'00'); require_pass(rec)
                c=s.comparison(candidate=candidate_for_run(rec['run_id'])); f['comparison']=c; save(f)
            except Exception as e:
                raise Stop('INCONCLUSIVE','环境准备/复探测未取得有效证据: '+str(e))
            if not c.get('verified'): raise Stop('INCONCLUSIVE',c.get('error','未验证探测证据'))
        else:
            if any(x['status']=='MISMATCH' for x in c['rows']): raise Stop('FAIL','供应商规格与实测配置不一致')
            require_pass(rec); check_comparison(c['rows'])
        f['review_hash']=s.snapshot(); f['state']='WAITING_APPROVAL'; f['current']=None; save(f)
    except Exception as e: conclude(f,getattr(e,'status','INCONCLUSIVE'),str(e))

def approve(d):
    global THREAD
    f=get(); s.guard_idle()
    if running() or not f or f['state']!='WAITING_APPROVAL' or d.get('flow_id')!=f['id']: raise ValueError('当前没有等待审批的流程')
    if d.get('reviewed') is not True or d.get('permissions_reviewed') is not True or not isinstance(d.get('operator'),str) or not d['operator'].strip() or not isinstance(d.get('opinion'),str) or not d['opinion'].strip(): raise ValueError('请填写审批人、审批意见并明确确认')
    assert_unchanged(f)
    if d.get('review_hash')!=f['review_hash'] or s.snapshot()!=f['review_hash']: raise ValueError('审批证据或策略已变化，请重新探测')
    c=s.comparison()
    if not f.get('full_measurement'): check_comparison(c['rows'])
    if not c['verified'] or c['candidate_id']!=f['runs'][-1]['run_id']: raise ValueError('探测证据已变化')
    p=s.policy()
    if not f.get('full_measurement') and (p.get('allow_load_tests') is not True or p.get('allow_io_test') is not True): raise ValueError('完整测量仍需要明确 CPU/KVM 与 I/O 授权；不得自动授权')
    f['acceptance_mode']='measurement_only' if p['realtime'].get('max_latency_us') is None else 'formal'
    f['human_approval']={'operator':s.redact(d['operator'][:120]),'opinion':s.redact(d['opinion'][:1000]),'at':now(),'review_hash':f['review_hash'],'acceptance_mode':f['acceptance_mode']}; f['state']='APPROVING'; save(f); s.audit('flow_human_approval',flow=f['id'],**f['human_approval']); THREAD=threading.Thread(target=validate_flow,args=(f,),daemon=True); THREAD.start(); return f

def threshold_only(f,rec):
    """Allow continuation only for complete, sealed latency measurements with no threshold.
    Never waive transport, receipt, runtime or other acceptance failures.
    """
    n=rec['stage']; p=f['policy']; rt=p['realtime']
    if f.get('acceptance_mode')!='measurement_only' or rt.get('max_latency_us') is not None or n not in ('07','08') or rec['status']!='INCONCLUSIVE' or rec.get('controller_error'): return False
    try:
        path,h,r=sealed(rec['run_id'],n)
        if h!=rec['manifest'] or r['overall']!='INCONCLUSIVE': return False
        cpu=p['test_cpu']; seconds=rt.get('short_duration_s',60) if n=='07' else rt.get('long_duration_s',3600)
        groups={'LAT01':(cpu,'baseline'),'LAT02':(cpu,'host'),'LAT03':(cpu,'guest'),'LAT04':(cpu,'joint')} if n=='07' else {'STAB01':(cpu,'guest')}
        if n=='07' and rt.get('compare_isolated_cores') is True:
            groups.update({f'LAT_CPU{c}':(c,'baseline') for c in s.cpu_set(p['isolated_cpus']) if c!=cpu})
        cases=r['cases']
        if len(cases)!=len(groups) or {c['id'] for c in cases}!=set(groups): return False
        for c in cases:
            cid=c['id']; expected=c['expected']; m=c['actual']; target,mode=groups[cid]
            if c['status']!='INCONCLUSIVE' or expected!={'max_latency_us':None,'seconds':seconds,'measurement_valid':True,'decision_basis':'threshold_missing'}: return False
            if not isinstance(m,dict) or m!=json.loads((path/'evidence'/(cid.lower()+'_metrics.json')).read_text()): return False
            if m.get('group')!=cid or m.get('condition')!=mode or m.get('cpu')!=target or m.get('planned_seconds')!=seconds or m.get('threshold_us','missing') is not None: return False
            interval=rt.get('interval_us',1000); priority=rt.get('priority',80)
            if m.get('interval_us')!=interval or m.get('priority')!=priority: return False
            if not 0<=m['min_us']<=m['avg_us']<=m['max_us'] or not .98*seconds*1e6/interval<=m['cycles']<=1.02*seconds*1e6/interval or not .98*seconds<=m['elapsed_s']<=seconds+15 or m['fifo_thread_samples']<2: return False
            if mode in ('host','joint') and not .8<=m['host_busy']<=1: return False
            if mode in ('guest','joint') and not .5<=m['guest']['busy']<=1: return False
        return True
    except (ValueError,KeyError,TypeError,OSError,AttributeError): return False

def deferred_irq_warning(rec):
    """Only the known static IRQ affinity warning may proceed to dynamic tests."""
    if rec.get('stage')!='03' or rec.get('status')!='WARN' or rec.get('controller_error'): return False
    try:
        _,h,r=sealed(rec['run_id'],'03')
        if h!=rec['manifest'] or r['overall']!='WARN': return False
        cases=r['cases']; ids={f'ISO{i:02d}' for i in range(1,14)}
        if len(cases)!=len(ids) or {c['id'] for c in cases}!=ids: return False
        return all(c['status']==('WARN' if c['id']=='ISO10' else 'PASS') for c in cases)
    except (ValueError,KeyError,TypeError,OSError): return False

def completed_summary(f,rec):
    if rec['status'] not in ('WARN','INCONCLUSIVE') or rec.get('controller_error'): return False
    try:
        path,h,r=sealed(rec['run_id'],'09')
        if h!=rec['manifest'] or r['overall']!=rec['status']: return False
        rows={x['id']:x for x in r['cases']}
        if len(r['cases'])!=len(STAGES) or set(rows)!={'SUM'+n for n in STAGES}: return False
        for n in STAGES:
            prev=next(x for x in reversed(f['runs']) if x['stage']==n)
            status='INCONCLUSIVE' if n in ('07','08') and f.get('acceptance_mode')=='measurement_only' else 'WARN' if n=='03' and deferred_irq_warning(prev) else 'PASS'
            if prev.get('controller_error') or prev['status']!=status or rows['SUM'+n]['status']!=status or rows['SUM'+n]['actual']!={'run_id':prev['run_id'],'status':status}: return False
            if status=='INCONCLUSIVE' and not threshold_only(f,prev): return False
            if sealed(prev['run_id'],n)[1]!=prev['manifest']: return False
        expected_overall='INCONCLUSIVE' if any(x['status']=='INCONCLUSIVE' for x in rows.values()) else 'WARN' if any(x['status']=='WARN' for x in rows.values()) else 'PASS'
        return rec['status']==expected_overall
    except (ValueError,KeyError,TypeError,OSError,StopIteration): return False

def validate_flow_legacy(f):
    status='PASS'; reason='全部必需阶段通过'; measurement_complete=False; execution_complete=False
    try:
        assert_unchanged(f)
        if local('approve')!=0: raise ValueError('engine approval failed')
        a,_=s.active()
        if not a or not a['local_current']: raise ValueError('approval missing')
        f['session_id']=a['session_id']; f['state']='VALIDATING'; save(f)
        # Engine report requires 01/00 captured within approved session; repeat once and recompare.
        for n in STAGES:
            rec=stage(f,n)
            if n=='00':
                c=s.comparison(candidate=candidate_for_run(rec['run_id'])); f['post_approval_comparison']=c; save(f)
                if c.get('verified') and any(x['status']=='MISMATCH' for x in c['rows']): raise Stop('FAIL','审批后复核发现配置差异')
                check_comparison(c['rows'])
                if not c['verified'] or c['candidate_id']!=f['runs'][-1]['run_id']: raise ValueError('复核探测证据无效')
                f['post_approval_comparison']=c; save(f)
            if threshold_only(f,rec):
                rec['measurement_status']='COMPLETE'; rec['decision_basis']='threshold_missing'; save(f)
            elif deferred_irq_warning(rec):
                rec['decision_basis']='irq_affinity_deferred'; rec['warning_detail']='ISO10：IRQ有效亲和性覆盖隔离核心；保留WARN，继续动态中断验证（CPU-06）'; save(f)
                s.audit('flow_warning_deferred',flow=f['id'],run_id=rec['run_id'],case='ISO10')
            else: require_pass(rec)
    except Exception as e: status=getattr(e,'status','INCONCLUSIVE'); reason=str(e)
    if f.get('session_id') and not s.PENDING:
        try:
            rec=stage(f,'09')
            if rec['status']=='FAIL': status='FAIL'; reason='CPU-09 发现失败项'
            elif status=='PASS' and completed_summary(f,rec):
                status='INCONCLUSIVE'; execution_complete=True
                measurement_complete=f.get('acceptance_mode')=='measurement_only'
                warned=any(x.get('decision_basis')=='irq_affinity_deferred' for x in f['runs'])
                reason='全部计划测试已完成；'+('ISO10 静态IRQ警告仍保留，需供应商复核；' if warned else '')+('供应商未提供延迟验收阈值；' if measurement_complete else '')+'不构成验收通过'
            elif status=='PASS' and (rec['status']!='PASS' or any(x.get('decision_basis')=='irq_affinity_deferred' for x in f['runs'])): status='INCONCLUSIVE'; reason='CPU-09 汇总未通过或与已归档警告不一致'
        except Exception as e:
            if status=='PASS': status='INCONCLUSIVE'; reason='CPU-09: '+str(e)
    if status=='PASS' and f['policy']['realtime'].get('max_latency_us') is None:
        status='INCONCLUSIVE'; reason='缺少正式延迟阈值；未取得完整的仅测量汇总证据'
    f['measurement_complete']=measurement_complete; f['execution_complete']=execution_complete or status=='PASS'
    conclude(f,status,reason)

def validate_flow(f):
    if not f.get('full_measurement'): return validate_flow_legacy(f)
    status='INCONCLUSIVE'; reason='测试尚未完成'; f['skipped']={}; f['stage_errors']={}; f['execution_complete']=False
    records={}; fatal=None
    try:
        assert_unchanged(f)
        if local('approve')!=0: raise ValueError('engine approval failed; inspect local approval log')
        a,_=s.active()
        if not a or not a['local_current']: raise ValueError('approval missing')
        f['session_id']=a['session_id']; f['state']='VALIDATING'; save(f)
        for n in STAGES:
            # Do not weaken engine placement/identity/load gates. Performance outcomes never block unrelated later tests.
            blocked=dependency_reason(n,records,f)
            if blocked:
                f['skipped'][n]=blocked; save(f); continue
            try:
                rec=stage(f,n); records[n]=rec
                if n=='00':
                    c=s.comparison(candidate=candidate_for_run(rec['run_id'])); f['post_approval_comparison']=c; save(f)
                    if not c.get('verified'): raise ValueError('复核探测证据无效')
                if threshold_only(f,rec): rec['measurement_status']='COMPLETE'; rec['decision_basis']='threshold_missing'; save(f)
                elif deferred_irq_warning(rec): rec['decision_basis']='irq_affinity_deferred'; rec['warning_detail']='ISO10：静态IRQ警告保留，继续动态验证'; save(f)
            except Exception as e:
                f['stage_errors'][n]=s.redact(str(e)); save(f)
                # Unknown dispatch/session/code changes must not lead to concurrent or unbound testing.
                if s.PENDING or (s.STATE/'web-stage-request.json').is_file() or s.engine_busy(): raise
                assert_unchanged(f)
                a,_=s.active()
                if not a or not a['local_current'] or a['session_id']!=f['session_id']: raise
                if n in ('01','00'): raise
        if f.get('session_id') and not s.PENDING:
            try: records['09']=stage(f,'09')
            except Exception as e: f['stage_errors']['09']=s.redact(str(e)); save(f)
    except Exception as e:
        fatal=s.redact(str(e))
    if fatal:
        for n in STAGES:
            if n not in records and n not in f['stage_errors']: f['skipped'].setdefault(n,'控制器中断：'+fatal)
    actual=[x for n,x in records.items() if n in STAGES]
    failures=any(x['status']=='FAIL' for x in actual) or records.get('09',{}).get('status')=='FAIL' or any(x['status']=='MISMATCH' for c in (f.get('comparison'),f.get('post_approval_comparison')) if c for x in c.get('rows',[]))
    def complete(n,rec):
        if not rec or rec.get('controller_error') or n in f['stage_errors']: return False
        if rec['status']=='INCONCLUSIVE': return threshold_only(f,rec)
        try:
            cases=sealed(rec['run_id'],n)[2]['cases']
            expected={'01':{f'TC{i:02d}' for i in range(1,7)},'00':{f'DISC{i:02d}' for i in range(1,5)},'02':{f'DISC{i:02d}' for i in range(1,5)}|{f'TP{i:02d}' for i in range(1,11)},'03':{f'ISO{i:02d}' for i in range(1,14)},'04':{f'AFF{i:02d}' for i in range(1,6)},'05':{f'SCH{i:02d}' for i in range(1,9)},'06':{f'IRQ{i:02d}' for i in range(1,9)},'07':{'LAT01','LAT02','LAT03','LAT04'},'08':{'STAB01'}}[n]
            if n=='07' and f['policy']['realtime'].get('compare_isolated_cores') is True: expected|={f'LAT_CPU{c}' for c in s.cpu_set(f['policy']['isolated_cpus']) if c!=f['policy']['test_cpu']}
            if len(cases)!=len(expected) or {x['id'] for x in cases}!=expected: return False
            if n=='06':
                path=sealed(rec['run_id'],n)[0]
                for cid in ('irq03','irq04','irq05','irq06'):
                    m=s.jsonfile(path/'evidence'/(cid+'_metrics.json'),{}) or {}
                    if m.get('valid_load') is not True: return False
            return bool(cases) and all(x['status'] in ('PASS','WARN','FAIL') for x in cases)
        except Exception: return False
    f['execution_complete']=not fatal and all(complete(n,records.get(n)) for n in STAGES) and bool(records.get('09')) and not records['09'].get('controller_error')
    f['measurement_complete']=f['execution_complete'] and f.get('acceptance_mode')=='measurement_only'
    status='FAIL' if failures else 'PASS' if f['execution_complete'] and all(x['status']=='PASS' for x in actual) and records['09']['status']=='PASS' and f.get('acceptance_mode')=='formal' else 'INCONCLUSIVE'
    reason=('全部计划测试已完成；客观指标与最终人工验收分离' if f['execution_complete'] else '已尽可能执行；部分项目前置条件不足或证据不完整')+('；'+fatal if fatal else '')
    conclude(f,status,reason)

def dependency_reason(n,records,f):
    if n in ('01','00'): return ''
    if any(records.get(x,{}).get('status')!='PASS' for x in ('01','00')): return '连接或探测未有效完成'
    if n in ('02','03'): return ''
    if not f['policy'].get('allow_load_tests'): return '未授权计算负载'
    from common.stage_gates import allows_active
    for g in ('02','03')+(('04',) if n!='04' else ()):
        rec=records.get(g)
        try:
            if not rec or rec.get('controller_error') or sealed(rec['run_id'],g)[1]!=rec['manifest'] or not allows_active(g,sealed(rec['run_id'],g)[2]): return 'CPU-'+g+' 安全执行前置条件不足；跳过受影响的主动负载'
        except Exception: return 'CPU-'+g+' 前置证据不可验证'
    return ''

def _report(f):
    out=[]
    for n in ([n for n in ('13','14','15') if any(x['stage']==n for x in f['runs'])] if f.get('full_measurement') else [])+STAGES+['09']:
        rec=next((r for r in reversed(f['runs']) if r['stage']==n),None); item={'stage':n,'plan':PLANS[n],'status':'NOT_EXECUTED','cases':[],'files':[],'metrics':[]}
        if rec:
            item.update(rec)
            try:
                p,h,r=sealed(rec['run_id'],n)
                if h!=rec['manifest']: raise ValueError('manifest changed')
                item['cases']=r['cases']; item['files']=[str(x.relative_to(p)) for x in sorted(p.rglob('*')) if x.is_file() and not x.is_symlink()]; item['commands']=[]
                if (p/'execution.jsonl').is_file():
                    for line in (p/'execution.jsonl').read_text().splitlines():
                        z=json.loads(line); item['commands'].append({k:z.get(k) for k in ('label','command','argv','start','end','elapsed_s','exit_code','stdout_file','stderr_file')})
                for x in sorted((p/'evidence').glob('*_metrics.json')):
                    m=s.jsonfile(x)
                    if isinstance(m,dict): item['metrics'].append({'label':x.stem,'file':str(x.relative_to(p)),**m})
                if n=='08': item['trend']=s.jsonfile(p/'evidence/stab01_trend.json',{})
                if rec.get('controller_error') and item['status']!='FAIL': item['status']='INCONCLUSIVE'; item['error']=rec['controller_error']
            except Exception as e: item['status']='INCONCLUSIVE'; item['error']=str(e); item['files']=[]; item['metrics']=[]; item['cases']=[]
        if n in f.get('skipped',{}): item['error']=f['skipped'][n]
        if n in f.get('stage_errors',{}): item['error']=f['stage_errors'][n]
        out.append(item)
    overall=f.get('result','INCONCLUSIVE')
    if any(x['status']=='FAIL' for x in out) or any(x['status']=='MISMATCH' for x in (f.get('comparison') or {}).get('rows',[])+(f.get('post_approval_comparison') or {}).get('rows',[])): overall='FAIL'
    elif overall=='PASS' and (f['policy']['realtime'].get('max_latency_us') is None or any(x['status']!='PASS' for x in out)): overall='INCONCLUSIVE'
    return {'flow_id':f['id'],'overall':overall,'acceptance_mode':f.get('acceptance_mode'),'measurement_complete':bool(f.get('measurement_complete')) and overall=='INCONCLUSIVE' and all(x['status']==('INCONCLUSIVE' if x['stage'] in ('07','08','09') else 'WARN' if x['stage']=='03' and deferred_irq_warning(x) else 'PASS') and not x.get('error') and not x.get('controller_error') for x in out),'execution_complete':bool(f.get('execution_complete')) and all(x['status']!='NOT_EXECUTED' and not x.get('error') and not x.get('controller_error') for x in out),'state':f['state'],'run_history':f['runs'],'reason':f.get('reason'),'stage_error':f.get('stage_error'),'created':f['created'],'finished':f.get('finished'),'reference':f['reference'],'device':f['device'],'policy':f['policy'],'approval':f.get('human_approval'),'comparison':f.get('comparison'),'post_approval_comparison':f.get('post_approval_comparison'),'stages':out,'agents':f.get('agents',[])}

def report(f):
    r=_report(f)
    r['final_review']=s.jsonfile(folder(f)/'final-review.json')
    if f.get('full_measurement'):
        formal=[x for x in r['stages'] if x['stage'] in STAGES+['09']]
        valid=all(x.get('run_id') and not x.get('error') and not x.get('controller_error') for x in formal)
        overall=f.get('result','INCONCLUSIVE')
        if any(x['status']=='FAIL' for x in formal) or any(x['status']=='MISMATCH' for c in (f.get('comparison'),f.get('post_approval_comparison')) if c for x in c.get('rows',[])): overall='FAIL'
        elif overall=='PASS' and (not valid or any(x['status']!='PASS' for x in formal) or f['policy']['realtime'].get('max_latency_us') is None): overall='INCONCLUSIVE'
        r.update(overall=overall,execution_complete=bool(f.get('execution_complete')) and valid,measurement_complete=bool(f.get('measurement_complete')) and valid,skipped=f.get('skipped',{}),stage_errors=f.get('stage_errors',{}),initial_comparison=f.get('initial_comparison'),final_review=s.jsonfile(folder(f)/'final-review.json'),full_measurement=True)
    return r

def final_review(d):
    f=archived(d.get('flow_id',''))
    if f['state'] not in ('COMPLETED','STOPPED') or d.get('reviewed') is not True: raise ValueError('仅可审阅已结束流程')
    if d.get('decision') not in ('pass','conditional','fail','retest'): raise ValueError('invalid human decision')
    operator=d.get('operator'); opinion=d.get('opinion')
    if not isinstance(operator,str) or not operator.strip() or not isinstance(opinion,str) or not opinion.strip(): raise ValueError('填写验收人及依据')
    r=report(f); r.pop('final_review',None)
    if d['decision']=='pass' and (r['overall']!='PASS' or not r['execution_complete']): raise ValueError('客观不达标/证据不足不得直接标为无条件合格；可记录有条件接受及依据')
    v={'decision':d['decision'],'operator':s.redact(operator[:120]),'opinion':s.redact(opinion[:2000]),'at':now(),'objective':r['overall'],'report_sha256':hashlib.sha256(json.dumps(r,sort_keys=True,ensure_ascii=False).encode()).hexdigest()}
    path=folder(f)/'final-review.json'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as h: json.dump(v,h,ensure_ascii=False,indent=2)
    s.audit('human_final_review',flow=f['id'],**v); return v

def conclude(f,status,reason):
    f.update(result=status,reason=s.redact(reason),state='ANALYZING',current=None,finished=now()); save(f)
    has_warning=any(x.get('status')=='WARN' for x in f['runs'])
    try:
        if f['mode']=='openhands' and not s.PENDING and not (s.STATE/'web-stage-request.json').is_file() and f['runs']:
            # Immutable facts packet; agent outputs separate from sealed evidence.
            packet=report(f); packet['agents']=[]
            # Commands are large embedded remote programs: retain references, not full source in Agent context.
            for item in packet['stages']:
                for cmd in item.get('commands',[]): cmd.pop('command',None); cmd.pop('argv',None)
            atomic(folder(f)/'facts.json',scrub_values(packet))
            for role in ('10','11','12'):
                if role=='11' and status=='PASS' and not has_warning: continue
                try:
                    f['current']=role; save(f); token=uuid.uuid4().hex; atomic(s.WEB/'analysis_request.json',{'flow_id':f['id'],'role':role,'token':token,'facts_sha256':s.sha(folder(f)/'facts.json')}); remote(role)
                    a=s.jsonfile(folder(f)/('agent-'+role+'.json'))
                    if not a or a.get('token')!=token or a.get('facts_sha256')!=s.sha(folder(f)/'facts.json'): raise ValueError('agent did not submit correlated analysis')
                    from agent_exchange import validate_analysis
                    a['analysis']=validate_analysis(a['analysis'],s.jsonfile(folder(f)/'facts.json'))
                    f['agents'].append({'role':role,'status':'AVAILABLE','analysis':a['analysis']})
                except Exception as e:
                    f['agents'].append({'role':role,'status':'UNAVAILABLE','reason':s.redact(str(e))})
                    if s.PENDING: break
                finally: (s.WEB/'analysis_request.json').unlink(missing_ok=True)
                save(f)
    finally:
        if f['mode']=='openhands':
            present={a['role'] for a in f['agents']}
            for role in AGENTS:
                if role not in present: f['agents'].append({'role':role,'status':'SKIPPED' if role=='11' and status=='PASS' and not has_warning else 'UNAVAILABLE','reason':'无失败需要分析' if role=='11' and status=='PASS' and not has_warning else '无可用证据或派发状态未确认'})
        else: f['agents']=[{'role':role,'status':'SKIPPED','reason':'固定 Python 模式不调用 Agent'} for role in AGENTS]
        f['state']='COMPLETED' if status=='PASS' or f.get('measurement_complete') or f.get('execution_complete') else 'STOPPED'; f['current']=None; save(f)

def scrub_values(x):
    if isinstance(x,str): return s.redact(x)
    if isinstance(x,list): return [scrub_values(v) for v in x]
    if isinstance(x,dict): return {k:(v if k in ('id','run_id','flow_id','stage','status','manifest','file','files','label','source_line','state','current','mode','review_hash','request_id','path','overall','result','stdout_file','stderr_file','condition','group','role') else scrub_values(v)) for k,v in x.items()}
    return x

def archived(fid):
    if not re.fullmatch(r'flow-[0-9a-f]{32}',fid): raise ValueError('invalid flow ID')
    f=s.jsonfile(s.WEB/'flows'/fid/'state.json')
    if not f or f.get('id')!=fid: raise ValueError('flow not found')
    return f

def history():
    result=[]
    for p in (s.WEB/'flows').glob('flow-*/state.json'):
        f=s.jsonfile(p)
        if f: result.append({k:f.get(k) for k in ('id','created','finished','state','result','reference','device')})
    return sorted(result,key=lambda f:f['created'],reverse=True)[:200]

def evidence_zip(rid):
    p,h,r=sealed(rid); files=[x for x in p.rglob('*') if x.is_file()]
    if any(x.is_symlink() or not x.resolve().is_relative_to(p.resolve()) for x in files) or sum(x.stat().st_size for x in files)>100_000_000: raise ValueError('证据包过大或路径异常，请本地归档')
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:
        for x in files: z.write(x,arcname=rid+'/'+str(x.relative_to(p)))
    if verify(p)!=h: raise ValueError('归档时证据发生变化')
    return b.getvalue()

def evidence(rid,name,raw=False):
    p,h,r=sealed(rid); rel=Path(name)
    if rel.is_absolute() or '..' in rel.parts or name not in [str(x.relative_to(p)) for x in p.rglob('*') if x.is_file() and not x.is_symlink()]: raise ValueError('invalid evidence path')
    target=p/rel
    if not target.resolve().is_relative_to(p.resolve()) or target.stat().st_size>8_000_000: raise ValueError('file unavailable or too large; use local archive')
    return target.read_bytes() if raw else s.redact(target.read_text(errors='replace'))


def public(f):
    if not f: return None
    return scrub_values({k:f.get(k) for k in ('id','created','finished','state','current','mode','reference','runs','agents','comparison','post_approval_comparison','review_hash','result','reason','human_approval','stage_error','acceptance_mode','measurement_complete','execution_complete','allow_vm_start','allow_vm_reboot','preparation_status','readiness_status','initial_comparison','skipped','stage_errors','full_measurement')})

def cancel(d):
    f=get()
    if running() or not f or f['state']!='WAITING_APPROVAL' or f['id']!=d.get('flow_id') or d.get('confirmed') is not True: raise ValueError('仅能放弃等待审批的流程')
    f.update(state='STOPPED',result='INCONCLUSIVE',reason='人工放弃审批',current=None,finished=now()); save(f); s.audit('flow_cancelled',flow=f['id']); return f

def recover():
    f=get()
    if f and f['state'] in ('DISCOVERING','APPROVING','VALIDATING','ANALYZING'):
        f.update(state='STOPPED',result='FAIL' if f.get('result')=='FAIL' else 'INCONCLUSIVE',reason='网页服务中断，禁止自动续跑；请核对原任务与证据后重新开始',current=None,finished=now()); save(f)
        (s.WEB/'analysis_request.json').unlink(missing_ok=True)

def authorize_run(f,rid):
    rec=next((r for r in f['runs'] if r.get('run_id')==rid),None)
    if not rec: raise ValueError('证据不属于选定流程')
    p,h,r=sealed(rid,rec['stage'])
    if h!=rec.get('manifest'): raise ValueError('证据与流程记录的哈希不一致')
    return p
