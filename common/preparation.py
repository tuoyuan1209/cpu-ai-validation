"""Bounded, explicitly authorized preparation; never alters supplier configuration."""
import json, shlex, time, re
from pathlib import Path
from xml.etree import ElementTree as ET
from .policy import BASE, read, validate, verify_only, cpus, policy_hashes
from .evidence import Run, verify
from .transport import guest_ssh


def prepare(request):
    if not request or request.get('stage') not in ('13','14','15') or request.get('session_id') is not None or request.get('state')!='STARTED':
        raise ValueError('preparation requires a fresh web request before approval')
    p=validate(read('isolation_policy.yaml')); verify_only()
    if request['policy_hashes']!=policy_hashes(): raise ValueError('preparation policy changed')
    role=request['stage']; run=Run('CPU-'+role); v=p['vm']; q=shlex.quote(v['name']); vir='LC_ALL=C virsh -c qemu:///system '
    def call(label,cmd,root=False):
        rc,o=run.run(label,cmd,root)
        if rc!=0: raise ValueError(label+' failed; see command evidence')
        return o
    try:
        state=call('before_state',vir+'domstate '+q,True)
        run.case('PRE01','初始VM状态','PASS','记录实际初始状态',state)
        def placement_guard(live=False):
            online=call('before_online','cat /sys/devices/system/cpu/online')
            isolated=call('before_isolated','cat /sys/devices/system/cpu/isolated')
            if cpus(online)!=cpus(p['online_cpus']) or cpus(isolated)!=cpus(p['isolated_cpus']): raise ValueError('实际CPU范围与批准规格不同；禁止自动改变VM状态')
            for suffix,label in [(' --inactive','before_xml')]+([('','before_live_xml')] if live else []):
                xml=ET.fromstring(call(label,vir+'dumpxml '+q+suffix,True))
                pins={int(x.get('vcpu')):cpus(x.get('cpuset')) for x in xml.findall('./cputune/vcpupin')}; em=xml.find('./cputune/emulatorpin'); vc=xml.find('vcpu')
                if xml.get('type')!='kvm' or xml.findtext('name')!=v['name'] or vc is None or int(vc.text)!=v['vcpu_count'] or int(vc.get('current',vc.text))!=v['vcpu_count'] or pins!={int(k):cpus(x) for k,x in v['vcpu_pinning'].items()} or em is None or cpus(em.get('cpuset'))!=cpus(v['emulator_cpus']) or xml.findall('./cputune/iothreadpin') or int(xml.findtext('iothreads','0')): raise ValueError('VM绑定与规格不同；禁止自动改变VM状态')
        if role=='14':
            # Preserve pre-recovery diagnostic evidence; never reboot just because a tool or key is missing.
            for label,cmd in [('fault_dominfo','dominfo '),('fault_domstats','domstats '),('fault_memstat','dommemstat ')]: run.run(label,vir+cmd+q,True)
            if state!='running': raise ValueError('VM不在运行；无需重启；保留诊断')
            prior=request.get('prior_preparation') or {}
            rid=prior.get('run_id','')
            if not re.fullmatch(r'run-\d{8}T\d{6}Z-[0-9a-f]{8}',rid): raise ValueError('缺少相关准备证据')
            path=BASE/'runs'/rid
            if verify(path)!=prior.get('manifest'): raise ValueError('准备证据哈希不一致')
            receipt=json.loads((BASE/'.validation/receipts'/(rid+'.json')).read_text())
            if not receipt.get('valid') or receipt.get('flow_id')!=request.get('flow_id') or receipt.get('manifest_sha256')!=prior.get('manifest') or receipt.get('policy_hashes')!=request['policy_hashes'] or receipt.get('code_sha256')!=request['code_sha256']: raise ValueError('准备证据未绑定当前流程')
            result=json.loads((path/'result.json').read_text())
            if result.get('stage')!='CPU-13' or result.get('run_id')!=rid or result.get('overall')!='INCONCLUSIVE': raise ValueError('不适用恢复')
            # Recheck now before considering any reboot: an already-ready guest needs no change.
            timeout_seen=False
            def fault_probe(label,cmd,root=False):
                nonlocal timeout_seen
                rc,o=run.run('diagnose_'+label,cmd,root)
                if label=='guest_ssh_ready':
                    err=(run.e/('diagnose_'+label+'.stderr')).read_text(errors='replace')
                    timeout_seen=(rc is None and '\nTIMEOUT' in err) or (rc==255 and ('Connection timed out' in err or 'Operation timed out' in err))
                return rc,o
            try:
                guest_ssh(fault_probe,p)
            except Exception as e:
                if request.get('allow_vm_reboot') is not True or not timeout_seen: raise ValueError('仅诊断，未授权正常重启或不是SSH超时: '+str(e))
                placement_guard(True)
                if request['policy_hashes']!=policy_hashes(): raise ValueError('policy changed')
                call('authorized_graceful_reboot',vir+'reboot '+q,True)
                run.case('PRE02','授权正常重启请求','PASS','最多发出一次正常重启请求；不强制关机','libvirt accepted reboot request; actual reboot not independently proven')
                time.sleep(15)
            else:
                run.case('PRE02','故障复核','PASS','已就绪，不改变状态','guest ready without reboot')
        elif role=='13' and state=='shut off':
            if request.get('allow_vm_start') is not True: raise ValueError('VM关闭；未授权自动启动')
            placement_guard()
            if request['policy_hashes']!=policy_hashes(): raise ValueError('policy changed')
            call('authorized_start',vir+'start '+q,True)
            run.case('PRE02','授权启动VM','PASS','最多启动一次','start returned 0')
        elif state=='running': run.case('PRE02','VM状态','PASS','不改变已运行VM','already running')
        else: raise ValueError('VM未就绪；本阶段不改变状态: '+state)
        # Retry read-only readiness checks only; never restart or disable SSH verification.
        last=''
        for i in range(1,4):
            try:
                guest_ssh(lambda label,cmd,root=False:run.run(f'try{i}_{label}',cmd,root),p)
                run.case('PRE03','Guest就绪','PASS','SSH身份、CPU数量、工具及实时绑定','verified'); break
            except Exception as e:
                last=str(e); run.log(f'readiness attempt {i}: {last}')
                if i<3: time.sleep(5)
        else: raise ValueError('Guest readiness failed after bounded retries: '+last)
    except Exception as e:
        run.case('PRE_ERROR','环境准备未完成','INCONCLUSIVE','授权范围内准备及只读验证',str(e))
    return run.finish()
