import sys,unittest,tempfile,json,shutil,zipfile,io,hashlib
from pathlib import Path
from unittest.mock import patch
import yaml
sys.path.insert(0,str(Path(__file__).resolve().parents[2]));sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server as s, flow as f, agent_exchange as ae
from common.evidence import seal,verify
class FlowTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.root=Path(self.t.name); self.old=(s.ENGINE,s.STATE,s.WEB,s.JOB,s.PENDING,f.THREAD)
        s.ENGINE=self.root/'engine';s.STATE=s.ENGINE/'.validation';s.STATE.mkdir(parents=True);s.WEB=self.root/'web';s.WEB.mkdir();s.JOB=s.PENDING=f.THREAD=None
        shutil.copytree(Path(__file__).resolve().parents[2]/'scripts',s.ENGINE/'scripts',ignore=shutil.ignore_patterns('__pycache__'));shutil.copytree(Path(__file__).resolve().parents[2]/'common',s.ENGINE/'common',ignore=shutil.ignore_patterns('__pycache__'))
        self.p={'online_cpus':'0-7','housekeeping_cpus':'0-3','isolated_cpus':'4-7','kthread_cpus':'0','isolation_mechanism':'isolcpus-domain','test_cpu':6,'vm':{'name':'vm','vcpu_count':4,'vcpu_pinning':{i:str(i) for i in range(4)},'emulator_cpus':'0-3','guest_user':'tester','iothread_pinning':{}},'realtime':{'max_latency_us':50},'allow_load_tests':True,'allow_io_test':True}
        (s.ENGINE/'isolation_policy.yaml').write_text(yaml.safe_dump(self.p));(s.ENGINE/'config.yaml').write_text('host: 192.0.2.1\nssh_user: test\nssh_port: 22\n');(s.ENGINE/'provision_policy.yaml').write_text('{}')
        f.atomic(s.WEB/'supplier.json',{'version':'spec-v1','reference':'fixture only','policy_sha256':s.sha(s.ENGINE/'isolation_policy.yaml')}); self.calls=[];self.fail={};self.mismatch=False;self.bad_receipt=False;self.session=None;self.journal=[]
        self.flow={'id':'flow-'+'a'*32,'created':f.now(),'state':'DISCOVERING','current':'01','mode':'local','supplier_version':'spec-v1','reference':'fixture only','device':s.device(),'policy':self.p,'code_digest':f.code_digest(),'config':{k:s.sha(s.ENGINE/k) for k in ('config.yaml','isolation_policy.yaml','provision_policy.yaml')},'runs':[],'agents':[],'comparison':None,'session_id':None};f.save(self.flow)
        self.patches=[patch.object(f,'local',side_effect=self.fake),patch.object(s,'active',side_effect=lambda:(self.session,self.journal)),patch.object(s,'engine_busy',return_value=False),patch.object(ae,'ENGINE',s.ENGINE)]; [p.start() for p in self.patches]
    def tearDown(self):
        if f.THREAD: f.THREAD.join(5)
        [p.stop() for p in reversed(self.patches)];s.ENGINE,s.STATE,s.WEB,s.JOB,s.PENDING,f.THREAD=self.old;self.t.cleanup()
    def fake(self,n):
        self.calls.append(n)
        if n=='approve': self.session={'session_id':'session-20261126T000000Z-abcdef12','local_current':True};return 0
        q=s.jsonfile(s.STATE/'web-stage-request.json');rid=q['run_id'];d=s.ENGINE/'runs'/rid;d.mkdir(parents=True);status=self.fail.get(n,'PASS');result={'run_id':rid,'stage':'CPU-'+n,'overall':status,'cases':[{'id':'TEST','name':'fixture','status':status,'actual':'simulated only'}]};f.atomic(d/'result.json',result)
        if n=='00':
            p=yaml.safe_load(yaml.safe_dump(self.p));p['isolated_cpus']='6-7' if self.mismatch else p['isolated_cpus'];(d/'isolation_policy.detected.yaml').write_text(yaml.safe_dump(p));f.atomic(d/'observed.json',{'realtime':'1','isolated':p['isolated_cpus'],'vm_inventory_complete':True});f.atomic(d/'environment.json',{**s.device(),'target_sha256':hashlib.sha256(json.dumps([s.device()['host'],s.device()['ssh_user'],s.device()['ssh_port']],separators=(',',':')).encode()).hexdigest()});f.atomic(d/'vm_config.json',[{'name':'vm','state':'running','live':p['vm']}])
        seal(d);h=verify(d);r={**q,'valid':not self.bad_receipt,'manifest_sha256':h,'overall':status};f.atomic(s.STATE/'receipts'/(rid+'.json'),r)
        if self.session:self.journal.append(r)
        return 0 if status=='PASS' else 1
    def discover(self): f.discover(self.flow); return f.get()
    def approve(self):
        q=f.get();f.approve({'flow_id':q['id'],'review_hash':q['review_hash'],'reviewed':True,'permissions_reviewed':True,'operator':'offline','opinion':'fixture'});f.THREAD.join(5);return f.get()
    def test_complete_sequence(self):
        self.assertEqual(self.discover()['state'],'WAITING_APPROVAL'); self.assertEqual(self.calls,['01','00']);q=self.approve();self.assertEqual(q['state'],'COMPLETED',q.get('reason'));self.assertEqual(self.calls,['01','00','approve',*f.STAGES,'09']);self.assertEqual(f.report(q)['overall'],'PASS');self.assertEqual(len(f.history()),1)
        rid=q['runs'][0]['run_id'];self.assertIn('fixture',f.evidence(rid,'result.json'));self.assertTrue(zipfile.ZipFile(io.BytesIO(f.evidence_zip(rid))).namelist());self.assertRaises(ValueError,f.evidence,rid,'../secret')
    def test_mismatch_stops_even_if_probe_inconclusive(self):
        self.mismatch=True;self.fail['00']='INCONCLUSIVE';q=self.discover();self.assertEqual(q['result'],'FAIL');self.assertEqual(self.calls,['01','00']);self.assertEqual(q['state'],'STOPPED');self.assertTrue(any(x['status']=='MISMATCH' for x in q['comparison']['rows']))
    def test_failure_stops_later_stages(self):
        self.discover();self.fail['05']='FAIL';q=self.approve();self.assertEqual(q['result'],'FAIL');self.assertNotIn('06',self.calls);self.assertIn('09',self.calls);self.assertEqual(f.report(q)['overall'],'FAIL')
    def test_warn_stops(self):
        self.discover();self.fail['03']='WARN';q=self.approve();self.assertEqual(q['result'],'INCONCLUSIVE');self.assertNotIn('04',self.calls)
    def test_unbound_receipt_stops(self):
        self.bad_receipt=True;q=self.discover();self.assertEqual(q['result'],'INCONCLUSIVE');self.assertEqual(self.calls,['01'])
    def test_tampered_evidence(self):
        q=self.discover();rid=q['runs'][-1]['run_id'];(s.ENGINE/'runs'/rid/'result.json').write_text('{}');self.assertRaises(ValueError,self.approve);self.assertRaises(ValueError,f.evidence,rid,'result.json')
    def test_approval_confirmation(self):
        q=self.discover();self.assertRaises(ValueError,f.approve,{'flow_id':q['id'],'review_hash':q['review_hash'],'reviewed':False});self.assertEqual(self.calls,['01','00'])
    def test_agent_reference_validation(self):
        q=self.discover();packet=f.report(q);rid=q['runs'][-1]['run_id'];obj={'summary':'fixture','findings':[{'text':'fixture','certainty':'observed','refs':[{'run_id':rid,'file':'result.json'}]}],'recommendations':[],'limitations':[]};self.assertEqual(ae.validate_analysis(obj,packet)['summary'],'fixture');obj['findings'][0]['refs'][0]['file']='../secret';self.assertRaises(ValueError,ae.validate_analysis,obj,packet)
if __name__=='__main__':unittest.main()
