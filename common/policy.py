"""Explicit acceptance policy for host RT + libvirt KVM load on housekeeping CPUs."""
from pathlib import Path
import re, yaml, hashlib, json, ipaddress, os
BASE = Path(__file__).resolve().parents[1]

def read(name):
    d=yaml.safe_load((BASE/name).read_text())
    if not isinstance(d,dict): raise ValueError(f'{name}: expected mapping')
    return d

def cpus(value):
    if not isinstance(value,str) or not value.strip(): raise ValueError('nonempty CPU list string required')
    out=set()
    for s in value.strip().split(','):
        if not re.fullmatch(r'\d+(?:-\d+)?',s): raise ValueError('unsupported CPU list (exclusions not accepted)')
        a,b=map(int,(s.split('-')[0],s.split('-')[-1]))
        if a>b or b>65535: raise ValueError('invalid CPU range')
        out.update(range(a,b+1))
    return out

def fmt(c): return ','.join(map(str,sorted(c)))
def positive(v,name,lo=1,hi=65535):
    if type(v) is not int or not lo<=v<=hi: raise ValueError(f'{name}: invalid integer')
    return v

def validate(p,load=False):
    on,hk,iso=(cpus(p[k]) for k in ('online_cpus','housekeeping_cpus','isolated_cpus'))
    if hk&iso or hk|iso!=on: raise ValueError('housekeeping and isolated must partition online CPUs')
    if positive(p['test_cpu'],'test_cpu',0) not in iso: raise ValueError('test_cpu not isolated')
    if not cpus(p['kthread_cpus'])<=hk: raise ValueError('kthread_cpus outside housekeeping')
    if p.get('isolation_mechanism','isolcpus-domain')!='isolcpus-domain': raise ValueError('only isolcpus domain + host RT supported; review cpuset-only deployments separately')
    v=p['vm']; pins=v['vcpu_pinning']; n=positive(v['vcpu_count'],'vcpu_count',1,256)
    if not isinstance(v['name'],str) or not v['name'] or '[REDACTED]' in v['name'] or v['name'].startswith('-') or any(ord(c)<32 for c in v['name']): raise ValueError('invalid VM name')
    if not isinstance(pins,dict) or len(pins)!=n or {int(k) for k in pins}!=set(range(n)): raise ValueError('explicit pinning required for every vCPU')
    if any(not cpus(x)<=hk for x in pins.values()) or not cpus(v['emulator_cpus'])<=hk: raise ValueError('VM vCPU/emulator outside housekeeping; this test profile does not support guest RT')
    if v.get('iothread_pinning') not in (None,{},[]): raise ValueError('explicit IOThread pins need dedicated test profile; not silently ignored')
    if not isinstance(v.get('guest_user'),str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',v['guest_user']): raise ValueError('confirm VM guest_user')
    if v.get('guest_mac') and not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',v['guest_mac']): raise ValueError('invalid guest_mac')
    if v.get('guest_ip'): ipaddress.IPv4Address(v['guest_ip'])
    w=p.get('workload',{}); rt=p.get('realtime',{})
    for k,default in [('host_cpu_workers',len(hk)),('guest_cpu_workers',n),('scheduling_workers',2*len(hk))]:
        x=w.get(k,'auto'); positive(default if x=='auto' else x,k,1,512)
    for k,default,lo,hi in [('priority',80,1,99),('interval_us',1000,100,1000000),('short_duration_s',60,10,180),('long_duration_s',3600,3600,3600)]: positive(rt.get(k,default),k,lo,hi)
    for k in ('max_latency_us',):
        if rt.get(k) is not None: positive(rt[k],k,1,10000000)
    if load and p.get('allow_load_tests') is not True: raise ValueError('load tests require allow_load_tests: true after supplier authorization')
    return p

def workers(p,k):
    defaults={'host_cpu_workers':len(cpus(p['housekeeping_cpus'])),'guest_cpu_workers':p['vm']['vcpu_count'],'scheduling_workers':2*len(cpus(p['housekeeping_cpus']))}
    x=p.get('workload',{}).get(k,'auto'); return defaults[k] if x=='auto' else x

def verify_only():
    p=read('provision_policy.yaml')
    if p.get('validation_mode')!='verify': raise ValueError('provision_policy.yaml must set validation_mode: verify')
    for section in ('provision','virtualization'):
        for k,v in (p.get(section) or {}).items():
            if k.startswith('auto_') and v is not False: raise ValueError('all auto_* permissions must be false in verification mode: '+k)
    return p

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def policy_hashes(): return {x:digest(BASE/x) for x in ('config.yaml','isolation_policy.yaml','provision_policy.yaml')}

def clean_text(x):
    if isinstance(x,bytes): x=x.decode('utf-8',errors='replace')
    for s in sorted({os.getenv(k,'') for k in ('SUT_SUDO_PASSWORD','SUT_SSH_PASSWORD')}-{''},key=len,reverse=True): x=x.replace(s,'[REDACTED]')
    return x

def scrub(x):
    if isinstance(x,str): return clean_text(x)
    if isinstance(x,list): return [scrub(v) for v in x]
    if isinstance(x,dict): return {k:scrub(v) for k,v in x.items()}
    return x

def structured(x):
    # Controlled schema fields never derived from passwords. Scrub only descriptive data.
    if isinstance(x,dict): return {k:v if k in ('id','run_id','stage','overall','status','label','stdout_file','stderr_file') else structured(v) for k,v in x.items()}
    if isinstance(x,list): return [structured(v) for v in x]
    return scrub(x)
