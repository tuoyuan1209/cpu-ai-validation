"""Offline V3.3 checks. All SSH and Automation behavior is mocked."""
import copy, json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import test_flow as fixture
from common import preparation as prep
from common.stage_gates import allows_active
from common.evidence import seal,verify
f,s=fixture.f,fixture.s

CASES={'01':[f'TC{i:02d}' for i in range(1,7)],'00':[f'DISC{i:02d}' for i in range(1,5)],'02':[f'DISC{i:02d}' for i in range(1,5)]+[f'TP{i:02d}' for i in range(1,11)],'03':[f'ISO{i:02d}' for i in range(1,14)],'04':[f'AFF{i:02d}' for i in range(1,6)],'05':[f'SCH{i:02d}' for i in range(1,9)],'06':[f'IRQ{i:02d}' for i in range(1,9)],'07':['LAT01','LAT02','LAT03','LAT04'],'08':['STAB01']}

def result(n, bad=None, status='FAIL'):
    return {'cases':[{'id':cid,'status':status if cid==bad else 'PASS','name':cid,'actual':'offline fixture'} for cid in CASES[n]]}

class GateTests(unittest.TestCase):
    def test_guest_only_failure_not_placement_failure(self):
        self.assertTrue(allows_active('02',result('02','TP09','INCONCLUSIVE')))
        self.assertFalse(allows_active('02',result('02','TP08','INCONCLUSIVE')))
    def test_noncritical_config_deviation(self):
        self.assertTrue(allows_active('03',result('03','ISO07')))
        self.assertFalse(allows_active('03',result('03','ISO12')))
    def test_live_masks_are_required(self):
        self.assertFalse(allows_active('04',result('04','AFF03')))
        self.assertTrue(allows_active('04',result('04','AFF05','INCONCLUSIVE')))
    def test_missing_or_duplicate_cases_rejected(self):
        x=result('03'); x['cases'].pop();self.assertFalse(allows_active('03',x)); x['cases'].append(x['cases'][0]);self.assertFalse(allows_active('03',x))

class FlowTests(unittest.TestCase):
    # Borrow the original fixture's isolated temporary repository without inheriting its legacy tests.
    setUp=fixture.FlowTests.setUp
    tearDown=fixture.FlowTests.tearDown
    discover=fixture.FlowTests.discover
    approve=fixture.FlowTests.approve
    def fake(self,n):
        rc=fixture.FlowTests.fake(self,n)
        if n=='approve':return rc
        q=s.jsonfile(s.STATE/'web-stage-request.json');rid=q['run_id'];d=s.ENGINE/'runs'/rid;r=s.jsonfile(d/'result.json')
        if n in CASES:
            bad=getattr(self,'badcases',{}).get(n)
            r['cases']=result(n,bad,r['overall'])['cases']
        if n=='06':
            for k in ('irq03','irq04','irq05','irq06'): f.atomic(d/'evidence'/(k+'_metrics.json'),{'valid_load':True})
        if n=='09':
            rows=[]
            for code in f.STAGES:
                rr=next((x for x in reversed(self.journal) if x['stage']==code),None)
                rows.append({'id':'SUM'+code,'status':rr['overall'] if rr else 'INCONCLUSIVE','actual':{'run_id':rr['run_id'],'status':rr['overall']} if rr else 'missing'})
            r['cases']=rows;r['overall']='FAIL' if any(x['status']=='FAIL' for x in rows) else 'INCONCLUSIVE' if any(x['status']=='INCONCLUSIVE' for x in rows) else 'WARN' if any(x['status']=='WARN' for x in rows) else 'PASS'
        f.atomic(d/'result.json',r);seal(d);rec=s.jsonfile(s.STATE/'receipts'/(rid+'.json'));rec.update(overall=r['overall'],manifest_sha256=verify(d));f.atomic(s.STATE/'receipts'/(rid+'.json'),rec)
        if self.session:self.journal[-1].update(rec)
        return 0 if r['overall']=='PASS' else 1
    def start(self):
        self.flow.update(full_measurement=True,allow_vm_start=True,allow_vm_reboot=False);f.save(self.flow);return self.discover()
    def test_full_preparation_sequence(self):
        self.assertEqual(self.start()['state'],'WAITING_APPROVAL');self.assertEqual(self.calls,['01','00','13','15','00']);self.assertTrue(f.get()['initial_comparison']['verified'])
    def test_recovery_after_preparation_failure(self):
        self.fail['13']='INCONCLUSIVE';self.assertEqual(self.start()['state'],'WAITING_APPROVAL');self.assertEqual(self.calls,['01','00','13','14','15','00'])
    def test_performance_failures_do_not_stop(self):
        self.start();self.fail.update({'05':'FAIL','06':'FAIL','07':'FAIL'});self.badcases={'05':'SCH04','06':'IRQ05','07':'LAT03'};q=self.approve();self.assertEqual(q['state'],'COMPLETED',q.get('reason'));self.assertEqual(q['result'],'FAIL');self.assertTrue(q['execution_complete']);self.assertIn('08',self.calls);self.assertIn('09',self.calls);self.assertEqual(f.report(q)['overall'],'FAIL')
    def test_guest_readiness_only_allows_other_stages(self):
        self.start();self.fail['02']='INCONCLUSIVE';self.badcases={'02':'TP09'};q=self.approve();self.assertIn('07',self.calls);self.assertFalse(q['execution_complete']);self.assertEqual(q['result'],'INCONCLUSIVE')
    def test_unsafe_placement_blocks_only_active(self):
        self.start();self.fail['03']='FAIL';self.badcases={'03':'ISO12'};q=self.approve();self.assertNotIn('04',self.calls);self.assertNotIn('08',self.calls);self.assertIn('09',self.calls);self.assertIn('04',q['skipped']);self.assertEqual(q['result'],'FAIL')
    def test_mismatch_waits_for_human_not_auto_approve(self):
        self.mismatch=True;q=self.start();self.assertEqual(q['state'],'WAITING_APPROVAL');self.assertNotIn('approve',self.calls);self.assertTrue(any(x['status']=='MISMATCH' for x in q['comparison']['rows']))
    def test_final_review_keeps_objective_result_and_is_write_once(self):
        self.start();self.fail['06']='FAIL';self.badcases={'06':'IRQ05'};q=self.approve();d={'flow_id':q['id'],'reviewed':True,'decision':'conditional','operator':'reviewer','opinion':'documented acceptance of deviation'};r=f.final_review(d);self.assertEqual(r['objective'],'FAIL');self.assertEqual(f.report(f.archived(q['id']))['overall'],'FAIL');self.assertEqual(f.report(q)['final_review']['decision'],'conditional');self.assertRaises(FileExistsError,f.final_review,d)

class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.calls=[]
        self.p={'online_cpus':'0-3','isolated_cpus':'2-3','housekeeping_cpus':'0-1','vm':{'name':'vm','vcpu_count':2,'vcpu_pinning':{0:'0',1:'1'},'emulator_cpus':'0-1'}}
        self.state='shut off';self.mismatch=False;self.ready=True;self.guest_timeout=False
        outer=self
        class MockRun:
            def __init__(self,stage):self.stage=stage;self.cases=[];self.e=outer.root/'evidence';self.e.mkdir(exist_ok=True)
            def run(self,label,cmd,root=False):
                outer.calls.append(cmd); rc,o=0,''
                if 'domstate' in cmd:o=outer.state
                elif 'cpu/online' in cmd:o='0-3'
                elif 'cpu/isolated' in cmd:o='3' if outer.mismatch else '2-3'
                elif 'dumpxml' in cmd:o='<domain type="kvm"><name>vm</name><vcpu>2</vcpu><cputune><vcpupin vcpu="0" cpuset="0"/><vcpupin vcpu="1" cpuset="1"/><emulatorpin cpuset="0-1"/></cputune></domain>'
                elif ' start ' in cmd:outer.state='running'
                elif ' reboot ' in cmd:outer.ready=True
                elif label.endswith('guest_ssh_ready') and not outer.ready:rc=None if outer.guest_timeout else 255
                (self.e/(label+'.stderr')).write_text('\nTIMEOUT' if rc is None else 'Permission denied' if rc else '')
                return rc,o
            def case(self,id,name,status,expected,actual):self.cases.append(status)
            def log(self,x):pass
            def finish(self):return 1 if 'INCONCLUSIVE' in self.cases else 0
        def guest(cb,p):
            rc,_=cb('guest_ssh_ready','mock guest probe')
            if not outer.ready:raise ValueError('guest unavailable')
        self.patches=[patch.object(prep,'BASE',self.root),patch.object(prep,'Run',MockRun),patch.object(prep,'read',return_value=self.p),patch.object(prep,'validate',side_effect=lambda p:p),patch.object(prep,'verify_only'),patch.object(prep,'policy_hashes',return_value={'x':'y'}),patch.object(prep,'guest_ssh',side_effect=guest),patch.object(prep.time,'sleep')];[p.start() for p in self.patches]
        self.req={'stage':'13','session_id':None,'state':'STARTED','policy_hashes':{'x':'y'},'flow_id':'fixture','code_sha256':'code','allow_vm_start':True}
    def tearDown(self):[p.stop() for p in reversed(self.patches)];self.tmp.cleanup()
    def test_start_once_if_authorized(self):self.assertEqual(prep.prepare(self.req),0);self.assertEqual(sum(' start ' in c for c in self.calls),1)
    def test_no_start_without_authorization(self):self.req['allow_vm_start']=False;self.assertEqual(prep.prepare(self.req),1);self.assertFalse(any(' start ' in c for c in self.calls))
    def test_no_start_on_placement_mismatch(self):self.mismatch=True;self.assertEqual(prep.prepare(self.req),1);self.assertFalse(any(' start ' in c for c in self.calls))
    def test_readiness_never_starts(self):self.req['stage']='15';self.assertEqual(prep.prepare(self.req),1);self.assertFalse(any(' start ' in c for c in self.calls))
    def test_reboot_only_with_bound_evidence_and_timeout(self):
        self.state='running';self.ready=False;self.guest_timeout=True;rid='run-20261127T000000Z-12345678';d=self.root/'runs'/rid;d.mkdir(parents=True);(d/'result.json').write_text(json.dumps({'stage':'CPU-13','run_id':rid,'overall':'INCONCLUSIVE'}));seal(d);h=verify(d);f.atomic(self.root/'.validation/receipts'/(rid+'.json'),{'valid':True,'flow_id':'fixture','manifest_sha256':h,'policy_hashes':{'x':'y'},'code_sha256':'code'});self.req.update(stage='14',prior_preparation={'run_id':rid,'manifest':h},allow_vm_reboot=True)
        self.assertEqual(prep.prepare(self.req),0);self.assertEqual(sum(' reboot ' in c for c in self.calls),1)
    def test_no_reboot_on_auth_failure(self):
        self.state='running';self.ready=False;rid='run-20261127T000000Z-12345678';d=self.root/'runs'/rid;d.mkdir(parents=True);(d/'result.json').write_text(json.dumps({'stage':'CPU-13','run_id':rid,'overall':'INCONCLUSIVE'}));seal(d);h=verify(d);f.atomic(self.root/'.validation/receipts'/(rid+'.json'),{'valid':True,'flow_id':'fixture','manifest_sha256':h,'policy_hashes':{'x':'y'},'code_sha256':'code'});self.req.update(stage='14',prior_preparation={'run_id':rid,'manifest':h},allow_vm_reboot=True)
        self.assertEqual(prep.prepare(self.req),1);self.assertFalse(any(' reboot ' in c for c in self.calls))
