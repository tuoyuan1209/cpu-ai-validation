"""Offline SSH mock. Never touches a real SUT."""
import os, json, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
import yaml
from common.policy import BASE
from common.evidence import verify

class DiscoveryMock(unittest.TestCase):
    def test_secret_collision_and_readonly_discovery(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); repo=p/'repo'; repo.mkdir(); shutil.copytree(BASE/'common',repo/'common'); shutil.copytree(BASE/'scripts',repo/'scripts'); key=p/'key'; key.touch(); bin=p/'bin'; bin.mkdir()
            (repo/'config.yaml').write_text(yaml.safe_dump({'host':'192.0.2.10','ssh_user':'test','ssh_port':22,'auth':{'ssh_key':str(key)}}))
            ssh=bin/'ssh'; ssh.write_text('#!'+sys.executable+'\n'+r'''
import sys
c=sys.argv[-1]
if 'hostname; id -un; uname -r' in c: print('test-SUT\ntest\n6.17-rt')
elif 'list --all --name' in c: print('mock-vm')
elif 'domstate' in c: print('running')
elif 'dumpxml' in c: print('<domain type="kvm"><name>mock-vm</name><memory unit="KiB">4194304</memory><vcpu>2</vcpu><cputune><vcpupin vcpu="0" cpuset="0"/><vcpupin vcpu="1" cpuset="2"/><emulatorpin cpuset="0,2"/></cputune></domain>')
elif 'system/cpu/online' in c: print('0-3')
elif 'system/cpu/isolated' in c or 'system/cpu/nohz_full' in c: print('1,3')
elif 'cat /proc/cmdline' in c: print('isolcpus=1,3 rcu_nocbs=1,3 nohz_full=1,3 kthread_cpus=0')
else: print('fixture')
'''); ssh.chmod(0o755)
            env=dict(os.environ,PATH=str(bin)+':'+os.environ['PATH'],SUT_SUDO_PASSWORD='test',SUT_SSH_PASSWORD=''); z=subprocess.run([sys.executable,str(repo/'scripts/discover_sut.py')],env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(z.returncode,0,z.stdout+z.stderr); run=next((repo/'runs').iterdir()); x=json.loads((run/'result.json').read_text()); self.assertEqual(x['overall'],'PASS'); self.assertEqual(x['stage'],'CPU-00'); y=yaml.safe_load((run/'isolation_policy.detected.yaml').read_text()); self.assertEqual(y['housekeeping_cpus'],'0,2'); self.assertEqual(y['vm']['vcpu_pinning'],{0:'0',1:'2'}); self.assertIsNone(y['test_cpu']); self.assertIn('[REDACTED]',(run/'evidence/identity.stdout').read_text()); verify(run)
if __name__=='__main__': unittest.main()
