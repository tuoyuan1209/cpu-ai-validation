import ast, copy, json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import yaml
from common.policy import BASE, cpus, validate, workers, structured
from common.evidence import seal, verify, overall
from common.latency import parse_result
from common.transport import guest_ssh

class PolicyTests(unittest.TestCase):
    def setUp(self): self.p=yaml.safe_load((BASE/'isolation_policy.example.yaml').read_text())
    def test_old_layout(self): self.assertEqual(workers(validate(self.p),'scheduling_workers'),8)
    def test_noncontiguous_layout(self):
        self.p.update(housekeeping_cpus='0,2,4,6',isolated_cpus='1,3,5,7',test_cpu=5)
        self.p['vm'].update(vcpu_count=3,vcpu_pinning={0:'0',1:'2',2:'4'},emulator_cpus='0,2,4,6')
        self.assertEqual(workers(validate(self.p),'guest_cpu_workers'),3)
    def test_reject_overlap(self):
        self.p['vm']['vcpu_pinning'][0]='6'
        with self.assertRaises(ValueError): validate(self.p)
    def test_reject_null_guest(self):
        self.p['vm']['guest_user']=None
        with self.assertRaises(ValueError): validate(self.p)
    def test_reject_unapproved_load(self):
        with self.assertRaises(ValueError): validate(self.p,load=True)
    def test_cpu_sets(self):
        self.assertEqual(cpus('0,3-5,7'),{0,3,4,5,7})
        for value in ('','3-1','0-7,^3',None):
            with self.assertRaises(ValueError): cpus(value)
    def test_secret_collision_preserves_keys(self):
        with patch.dict(os.environ,{'SUT_SUDO_PASSWORD':'test'}):
            d=structured({'test_cpu':6,'status':'PASS','actual':'test','run_id':'test-run'}); self.assertEqual(d,{'test_cpu':6,'status':'PASS','actual':'[REDACTED]','run_id':'test-run'})
    def test_guest_no_start(self):
        calls=[]
        def run(label,cmd,root=False): calls.append(cmd); return 0,'shut off'
        with self.assertRaises(ValueError): guest_ssh(run,self.p)
        self.assertEqual(len(calls),1); self.assertNotIn(' start ',calls[0])
    def test_guest_lease_agent_mac(self):
        vm=self.p['vm']; vm['guest_mac']='52:54:00:11:22:33'
        xml='<domain type="kvm"><cputune>'+''.join(f'<vcpupin vcpu="{i}" cpuset="{s}"/>' for i,s in vm['vcpu_pinning'].items())+'<emulatorpin cpuset="0-3"/></cputune></domain>'
        def run(label,cmd,root=False):
            return {'vm_state':(0,'running'),'vm_interfaces':(0,'vnet0 bridge br0 virtio 52:54:00:11:22:33\nvnet1 bridge br1 virtio 52:54:00:aa:bb:cc'),'guest_ip_lease':(1,''),'guest_ip_agent':(0,'eth0 52:54:00:11:22:33 ipv4 192.0.2.3/24'),'guest_ssh_ready':(0,'tester\n4\n/usr/bin/stress-ng\n/usr/bin/python3'),'vm_live_load_guard':(0,xml)}[label]
        self.assertEqual(guest_ssh(run,self.p)[-1],'tester@192.0.2.3')

class EvidenceTests(unittest.TestCase):
    def test_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); (p/'x').write_text('abc'); seal(p); self.assertEqual(len(verify(p)),64); (p/'x').write_text('changed')
            with self.assertRaises(ValueError): verify(p)
    def test_status(self):
        self.assertEqual(overall([{'status':'FAIL'},{'status':'WARN'}]),'FAIL'); self.assertEqual(overall([{'status':'NOT_EXECUTED'}]),'INCONCLUSIVE'); self.assertEqual(overall([{'status':'WARN'},{'status':'PASS'}]),'WARN')
    def test_latency_parser(self):
        # Synthetic fixture, not test data from a real SUT.
        d={'rc':0,'stdout':'T: 0 ( 1234) P:80 I:1000 C:60000 Min: 1 Act: 2 Avg: 2 Max: 19','elapsed':60.1,'thread_samples':[{'elapsed':x,'threads':[{'tid':1234,'allowed':[6],'scheduler':1,'priority':80}]} for x in [1,55]],'host_busy':.99,'guest':{'busy':.8}}
        self.assertEqual(parse_result(d,6,60,80,1000,'guest')['max_us'],19)
        with self.assertRaises(ValueError): parse_result(d,7,60,80,1000,'guest')
        d['guest']['busy']=.1
        with self.assertRaises(ValueError): parse_result(d,6,60,80,1000,'guest')
    def test_remote_programs_compile(self):
        targets={'scripts/check_scheduling.py':{'PROBE','GUEST','HOST_GUEST'},'scripts/check_irq.py':{'REMOTE','GUEST_IRQ'},'common/latency.py':{'GUEST','REMOTE'}}
        for name,required in targets.items():
            seen=set()
            for node in ast.parse((BASE/name).read_text()).body:
                if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in required:
                    compile(ast.literal_eval(node.value),name+':'+node.targets[0].id,'exec'); seen.add(node.targets[0].id)
            self.assertEqual(seen,required)
if __name__=='__main__': unittest.main()
