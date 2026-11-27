import test_measurement_mode as mm
import test_flow as fixture
import unittest
f,s=fixture.f,fixture.s
class IRQWarningTests(mm.MeasurementTests):
    def fake(self,n):
        rc=super().fake(n)
        if not getattr(self,'irq_warning',False) or n not in ('03','09'): return rc
        q=s.jsonfile(s.STATE/'web-stage-request.json'); rid=q['run_id']; d=s.ENGINE/'runs'/rid; r=s.jsonfile(d/'result.json')
        if n=='03':
            r['overall']='WARN';r['cases']=[{'id':f'ISO{i:02d}','name':'fixture','status':'WARN' if i==10 or (i==9 and getattr(self,'extra_warning',False)) else 'PASS','expected':'fixture','actual':'fixture'} for i in range(1,14)]
            if getattr(self,'missing_case',False):r['cases'].pop()
        elif self.p['realtime']['max_latency_us'] is not None:
            r['overall']='WARN';r['cases']=[{'id':'SUM'+x,'status':rr['overall'],'actual':{'run_id':rr['run_id'],'status':rr['overall']}} for x in f.STAGES for rr in [next((z for z in reversed(self.journal) if z['stage']==x),None)] if rr]
        f.atomic(d/'result.json',r);fixture.seal(d);self.journal[-1].update(overall=r['overall'],manifest_sha256=fixture.verify(d));f.atomic(s.STATE/'receipts'/(rid+'.json'),self.journal[-1]);return 2 if r['overall']=='WARN' else 1
    def test_irq_warning_measurement_continues(self):
        self.irq_warning=True;self.configure();self.discover();q=self.approve();self.assertEqual(q['state'],'COMPLETED',q.get('reason'));self.assertTrue(q['measurement_complete']);self.assertTrue(f.report(q)['measurement_complete']);self.assertEqual(q['result'],'INCONCLUSIVE');self.assertIn('08',self.calls);self.assertEqual(next(x for x in f.report(q)['stages'] if x['stage']=='03')['status'],'WARN')
    def test_irq_warning_formal_continues_but_not_pass(self):
        self.irq_warning=True;self.discover();q=self.approve();self.assertEqual(q['state'],'COMPLETED',q.get('reason'));self.assertTrue(q['execution_complete']);self.assertEqual(q['result'],'INCONCLUSIVE');self.assertIn('08',self.calls)
    def test_extra_warning_stops(self):
        self.irq_warning=True;self.extra_warning=True;self.discover();q=self.approve();self.assertEqual(q['state'],'STOPPED');self.assertNotIn('04',self.calls)
    def test_missing_case_stops(self):
        self.irq_warning=True;self.missing_case=True;self.discover();q=self.approve();self.assertEqual(q['state'],'STOPPED');self.assertNotIn('04',self.calls)
    def test_dynamic_failure_stops(self):
        self.irq_warning=True;self.configure();self.fail['06']='FAIL';self.discover();q=self.approve();self.assertEqual(q['result'],'FAIL');self.assertNotIn('07',self.calls)
if __name__=='__main__':unittest.main()
