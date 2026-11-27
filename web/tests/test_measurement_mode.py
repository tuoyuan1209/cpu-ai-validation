import copy, hashlib, json, unittest
from unittest.mock import patch
import yaml
import test_flow as fixture
f=fixture.f; s=fixture.s
class MeasurementTests(fixture.FlowTests):
    # Inherited tests also exercise compatibility with formal threshold mode.
    def configure(self, io=True):
        self.p['realtime']['max_latency_us']=None;self.p['allow_io_test']=io
        (s.ENGINE/'isolation_policy.yaml').write_text(yaml.safe_dump(self.p));f.atomic(s.WEB/'supplier.json',{'version':'spec-v1','reference':'fixture only','policy_sha256':s.sha(s.ENGINE/'isolation_policy.yaml')})
        self.flow['config']['isolation_policy.yaml']=s.sha(s.ENGINE/'isolation_policy.yaml');f.save(self.flow)
    def fake(self,n):
        if self.p['realtime']['max_latency_us'] is not None or n not in ('07','08','09') or n in self.fail: return super().fake(n)
        self.fail[n]='INCONCLUSIVE'
        try: super().fake(n)
        finally: self.fail.pop(n)
        q=s.jsonfile(s.STATE/'web-stage-request.json');rid=q['run_id'];d=s.ENGINE/'runs'/rid;r=s.jsonfile(d/'result.json'); cases=[]
        if n=='09':
            for code in f.STAGES:
                rr=next((x for x in reversed(self.journal) if x['stage']==code),None)
                cases.append({'id':'SUM'+code,'status':rr['overall'] if rr else 'INCONCLUSIVE','actual':{'run_id':rr['run_id'],'status':rr['overall']} if rr else 'missing'})
        else:
            groups={'LAT01':'baseline','LAT02':'host','LAT03':'guest','LAT04':'joint'} if n=='07' else {'STAB01':'guest'}
            for cid,mode in groups.items():
                duration=60 if n=='07' else 3600
                m={'group':cid,'condition':mode,'cpu':6,'planned_seconds':duration,'threshold_us':None,'interval_us':1000,'priority':80,'min_us':1,'avg_us':2,'max_us':19,'cycles':duration*1000,'elapsed_s':duration,'fifo_thread_samples':2,'host_busy':.9,'guest':{'busy':.8}}
                if getattr(self,'invalid_metrics',False) and cid=='LAT02': m['host_busy']=.1
                cases.append({'id':cid,'status':'INCONCLUSIVE','expected':{'max_latency_us':None,'seconds':duration,'measurement_valid':True,'decision_basis':'threshold_missing'},'actual':m});f.atomic(d/'evidence'/(cid.lower()+'_metrics.json'),m)
            if getattr(self,'missing_group',False) and n=='07':cases.pop()
        r['cases']=cases;f.atomic(d/'result.json',r);fixture.seal(d);h=fixture.verify(d);self.journal[-1]['manifest_sha256']=h;f.atomic(s.STATE/'receipts'/(rid+'.json'),self.journal[-1]);return 1
    def test_no_threshold_runs_all(self):
        self.configure();self.discover();q=self.approve();self.assertEqual(q['state'],'COMPLETED',q.get('reason'));self.assertEqual(q['result'],'INCONCLUSIVE');self.assertTrue(q['measurement_complete']);self.assertTrue(f.report(q)['measurement_complete']);self.assertEqual(self.calls,['01','00','approve',*f.STAGES,'09'])
    def test_missing_io_does_not_authorize(self):
        self.configure(False);self.discover();self.assertRaises(ValueError,self.approve);self.assertEqual(self.calls,['01','00'])
    def test_invalid_load_stops(self):
        self.configure();self.invalid_metrics=True;self.discover();q=self.approve();self.assertEqual(q['state'],'STOPPED');self.assertNotIn('08',self.calls);self.assertFalse(q['measurement_complete'])
    def test_missing_group_stops(self):
        self.configure();self.missing_group=True;self.discover();q=self.approve();self.assertEqual(q['state'],'STOPPED');self.assertNotIn('08',self.calls)
    def test_real_failure_stops(self):
        self.configure();self.discover();self.fail['07']='FAIL';q=self.approve();self.assertEqual(q['result'],'FAIL');self.assertNotIn('08',self.calls)
    def test_long_failure_stays_incomplete(self):
        self.configure();self.discover();self.fail['08']='INCONCLUSIVE';q=self.approve();self.assertEqual(q['state'],'STOPPED');self.assertFalse(q['measurement_complete'])
    def test_missing_summary_stays_incomplete(self):
        self.configure();self.discover();self.fail['09']='INCONCLUSIVE';q=self.approve();self.assertEqual(q['state'],'STOPPED');self.assertFalse(q['measurement_complete'])
if __name__=='__main__': unittest.main()
