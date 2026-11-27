import os,sys,tempfile,unittest,json,threading,base64,urllib.request,urllib.error,shutil
from pathlib import Path
from unittest.mock import patch
os.environ['WEB_PASSWORD']='test-only-long-password'
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server as s
class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.old=(s.ENGINE,s.STATE,s.WEB,s.JOB,s.PENDING); s.ENGINE=self.root/'engine';s.STATE=s.ENGINE/'.validation';s.WEB=self.root/'web';s.WEB.mkdir();s.STATE.mkdir(parents=True);s.JOB=s.PENDING=None
        for k in ('config.yaml','provision_policy.yaml'): (s.ENGINE/k).write_text('{}')
        (s.ENGINE/'scripts').mkdir();(s.ENGINE/'scripts/run_stage.py').write_text('print("fake")')
        (s.ENGINE/'isolation_policy.yaml').write_text('online_cpus: 0-7\nhousekeeping_cpus: 0-3\nisolated_cpus: 4-7\ntest_cpu: 6\nvm: {name: vm, vcpu_count: 4, guest_user: tester, emulator_cpus: 0-3}\nrealtime: {}\nallow_load_tests: false\nallow_io_test: false\n')
        self.http=s.ThreadingHTTPServer(('127.0.0.1',0),s.Handler);self.t=threading.Thread(target=self.http.serve_forever,daemon=True);self.t.start()
    def tearDown(self):
        self.http.shutdown();self.http.server_close();s.ENGINE,s.STATE,s.WEB,s.JOB,s.PENDING=self.old;self.tmp.cleanup()
    def call(self,path,body=None,auth=True,origin=None,header=True):
        h={};
        if auth:h['Authorization']='Basic '+base64.b64encode(('operator:'+s.PASSWORD).encode()).decode()
        if origin:h['Origin']=origin
        if body is not None:
            h['Content-Type']='application/json'
            if header:h['X-CPU-Request']='1'
        req=urllib.request.Request(f'http://127.0.0.1:{self.http.server_port}'+path,data=None if body is None else json.dumps(body).encode(),headers=h)
        try:
            with urllib.request.urlopen(req) as r:return r.status,r.read()
        except urllib.error.HTTPError as e:return e.code,e.read()
    def test_auth(self): self.assertEqual(self.call('/api/status',auth=False)[0],401)
    def test_status(self): self.assertEqual(self.call('/api/status')[0],200)
    def test_csrf_header(self): self.assertEqual(self.call('/api/run',{},header=False)[0],400)
    def test_cross_origin(self): self.assertEqual(self.call('/api/run',{},origin='http://evil.example')[0],400)
    def test_approval_gate(self):
        with patch.object(s,'start_local') as m:
            code,b=self.call('/api/run',{'action':'workflow','mode':'local','confirmed':True});self.assertEqual(code,400);self.assertIn(b'V3.2',b);m.assert_not_called()
    def test_explicit_approval(self):
        with patch.object(s,'start_local') as m:
            code,b=self.call('/api/approve',{'reviewed':False,'review_hash':s.snapshot(),'reference':'spec'});self.assertEqual(code,400);m.assert_not_called()
    def test_stale_review(self):
        with patch.object(s,'latest_discovery',return_value={'id':'demo'}),patch.object(s,'start_local') as m:
            code,b=self.call('/api/approve',{'reviewed':True,'review_hash':'stale','reference':'spec'});self.assertEqual(code,400);m.assert_not_called()
    def test_confirmed_approval(self):
        with patch.object(s,'latest_discovery',return_value={'id':'demo'}),patch.object(s,'snapshot',return_value='reviewed-hash'),patch.object(s,'verify_candidate'),patch.object(s,'supplier',return_value={'current':True,'reference':'spec','version':'v1'}),patch.object(s,'comparison',return_value={'verified':True,'rows':[{'path':'online_cpus','status':'MATCH'}]}),patch.object(s,'start_local',return_value={'job':'mock'}) as m:
            self.assertEqual(self.call('/api/approve',{'reviewed':True,'review_hash':s.snapshot(),'reference':'spec','permissions_reviewed':True})[0],400);m.assert_not_called()
    def test_mismatch_blocks_approval(self):
        with patch.object(s,'latest_discovery',return_value={'id':'demo'}),patch.object(s,'snapshot',return_value='reviewed-hash'),patch.object(s,'verify_candidate'),patch.object(s,'supplier',return_value={'current':True,'reference':'spec','version':'v1'}),patch.object(s,'comparison',return_value={'verified':True,'rows':[{'path':'online_cpus','status':'MISMATCH'}]}),patch.object(s,'start_local') as m:
            self.assertEqual(self.call('/api/approve',{'reviewed':True,'permissions_reviewed':True,'review_hash':'reviewed-hash','reference':'spec'})[0],400);m.assert_not_called()
    def test_no_spec_blocks_approval(self):
        with patch.object(s,'latest_discovery',return_value={'id':'demo'}),patch.object(s,'snapshot',return_value='reviewed-hash'),patch.object(s,'verify_candidate'),patch.object(s,'start_local') as m:
            self.assertEqual(self.call('/api/approve',{'reviewed':True,'permissions_reviewed':True,'review_hash':'reviewed-hash','reference':'spec'})[0],400);m.assert_not_called()
    def test_device_validation(self):
        result=self.call('/api/device',{'review_hash':s.snapshot(),'confirmed':True,'device':{'host':'-bad','ssh_user':'tester','ssh_port':22}})
        self.assertEqual(result[0],400)
    def test_device_change_preserves_credentials_and_revokes_session(self):
        (s.ENGINE/'config.yaml').write_text('host: 192.0.2.10\nssh_user: test\nssh_port: 22\nauth: {ssh_key: /example/key}\n')
        (s.STATE/'active.json').write_text('{}'); old=s.snapshot()
        result=s.update_device({'review_hash':old,'confirmed':True,'device':{'host':'192.0.2.11','ssh_user':'tester','ssh_port':2222}})
        self.assertTrue(result['saved']);self.assertEqual(s.device()['host'],'192.0.2.11');self.assertIn('/example/key',(s.ENGINE/'config.yaml').read_text());self.assertFalse((s.STATE/'active.json').exists());self.assertNotEqual(s.snapshot(),old)
        self.assertEqual(self.call('/api/device',{'review_hash':old,'confirmed':True,'device':{'host':'192.0.2.12','ssh_user':'tester','ssh_port':22}})[0],400)
    def test_no_password_loopback(self):
        with patch.object(s,'NO_AUTH',True): self.assertEqual(self.call('/api/status',auth=False)[0],200)
    def test_save_policy_version_and_invalidate(self):
        import yaml
        p={'online_cpus':'0-7','housekeeping_cpus':'0-3','isolated_cpus':'4-7','kthread_cpus':'0','test_cpu':6,'isolation_mechanism':'isolcpus-domain','vm':{'name':'vm','vcpu_count':4,'vcpu_pinning':{i:str(i) for i in range(4)},'emulator_cpus':'0-3','guest_user':'tester','iothread_pinning':{}},'realtime':{},'allow_load_tests':False,'allow_io_test':False}
        (s.ENGINE/'isolation_policy.yaml').write_text(yaml.safe_dump(p));(s.STATE/'active.json').write_text('{}');old=s.snapshot()
        d={'review_hash':old,'reference':'vendor-spec-v1','supplier_confirmed':True,'changes':{'housekeeping_cpus':'0, 1, 2, 3','vcpu_pinning':{str(i):str(i) for i in range(4)}}}
        self.assertTrue(s.update_policy(d)['saved']);self.assertFalse((s.STATE/'active.json').exists());self.assertTrue(s.supplier()['current']);self.assertEqual(s.policy()['housekeeping_cpus'],'0,1,2,3');self.assertEqual(len(list((s.WEB/'supplier-versions').glob('*.json'))),1)
        self.assertEqual(self.call('/api/policy',d)[0],400)
    def test_real_discovery_comparison(self):
        import yaml,hashlib
        p={'online_cpus':'0-7','housekeeping_cpus':'0-3','isolated_cpus':'4-7','kthread_cpus':'0','test_cpu':6,'isolation_mechanism':'isolcpus-domain','vm':{'name':'vm','vcpu_count':4,'vcpu_pinning':{i:str(i) for i in range(4)},'emulator_cpus':'0-3','guest_user':'tester','iothread_pinning':{}},'realtime':{},'allow_load_tests':False,'allow_io_test':False}
        (s.ENGINE/'isolation_policy.yaml').write_text(yaml.safe_dump(p));(s.ENGINE/'config.yaml').write_text('host: 192.0.2.10\nssh_user: test\nssh_port: 22\n')
        rid='discovery-20261126T000000Z-12345678';d=s.ENGINE/'runs'/rid;d.mkdir(parents=True)
        (d/'isolation_policy.detected.yaml').write_text(yaml.safe_dump(p));(d/'result.json').write_text(json.dumps({'overall':'PASS','stage':'CPU-00','run_id':rid}));(d/'observed.json').write_text(json.dumps({'realtime':'1'}));(d/'environment.json').write_text(json.dumps({'host':'192.0.2.10','ssh_user':'test','ssh_port':22,'target_sha256':hashlib.sha256(json.dumps(['192.0.2.10','test',22],separators=(',',':')).encode()).hexdigest()}));(d/'vm_config.json').write_text(json.dumps([{'name':'vm','state':'running','live':p['vm']}]))
        (d/'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+f.name+'\n' for f in sorted(d.iterdir())))
        c=s.comparison();self.assertTrue(c['verified'],c);self.assertEqual(c['summary']['MISMATCH'],0);self.assertEqual(c['summary']['UNKNOWN'],0);self.assertGreater(c['summary']['MATCH'],14)
        (d/'observed.json').write_text('{}');self.assertFalse(s.comparison()['verified'])
    def test_no_arbitrary_commands(self): self.assertEqual(self.call('/api/run',{'action':'rm -rf /','mode':'local','confirmed':True})[0],400)
    def test_dispatch_once_on_failure(self):
        with patch.object(s,'checked_task',return_value='abc'),patch.object(s,'oh',side_effect=ValueError('network')) as m:
            with self.assertRaises(ValueError):s.dispatch('00')
            self.assertTrue(s.PENDING);self.assertTrue((s.WEB/'pending.json').exists());m.assert_called_once();
            with self.assertRaises(ValueError):s.guard_idle()
    def test_task_prompt_guard(self):
        with patch.object(s,'match',return_value={'id':'abc'}),patch.object(s,'oh',return_value={'prompt':'bad','enabled':True}),patch.object(s,'local_prompt',return_value='good'):
            with self.assertRaisesRegex(ValueError,'differs'):s.checked_task('00')
    def test_long_local_only(self):
        with patch.object(s,'ensure_approval'),patch.object(s,'dispatch') as m:
            self.assertEqual(self.call('/api/run',{'action':'08','mode':'openhands','confirmed':True})[0],400);m.assert_not_called()
if __name__=='__main__': unittest.main()
