import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from spec_compare import compare,check_comparison,summary,cpu_set
P={'online_cpus':'0-7','housekeeping_cpus':'0-3','isolated_cpus':'4-7','kthread_cpus':'0','isolation_mechanism':'isolcpus-domain','vm':{'name':'vm','vcpu_count':4,'vcpu_pinning':{i:str(i) for i in range(4)},'emulator_cpus':'0-3','iothread_pinning':{}}}
class CompareTests(unittest.TestCase):
    def test_equivalent(self):
        a=copy.deepcopy(P);a['housekeeping_cpus']='3,2,1,0';a['vm']['iothread_pinning']=[];a['vm']['vcpu_pinning']={str(i):str(i) for i in range(4)}
        rows=compare(P,a,'1');self.assertEqual(summary(rows),{'MATCH':14,'MISMATCH':0,'UNKNOWN':0});check_comparison(rows)
    def test_mismatch(self):
        a=copy.deepcopy(P);a['isolated_cpus']='6-7';r=compare(P,a,'1');self.assertEqual(summary(r)['MISMATCH'],1)
        with self.assertRaises(ValueError):check_comparison(r)
    def test_missing(self):
        a=copy.deepcopy(P);a['vm']['vcpu_pinning'].pop(3);r=compare(P,a,None);self.assertEqual(summary(r)['UNKNOWN'],2)
        with self.assertRaises(ValueError):check_comparison(r)
    def test_redacted(self):
        a=copy.deepcopy(P);a['vm']['name']='[REDACTED]';self.assertEqual(summary(compare(P,a,'1'))['UNKNOWN'],1)
    def test_not_rt(self):self.assertEqual(summary(compare(P,P,'0'))['MISMATCH'],1)
    def test_cpu_invalid(self):
        for x in ('','4-2','-1','1,foo','1-999999'):
            with self.assertRaises(ValueError):cpu_set(x)
