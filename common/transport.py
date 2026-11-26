"""SSH transport, strict host key checks, read-only VM resolution, no password in argv."""
import os, re, shlex, subprocess, ipaddress, json, hashlib
from pathlib import Path
from .policy import read, cpus, fmt

def ssh_argv():
    c=read('config.yaml'); host,user=c['host'],c['ssh_user']; port=int(c.get('ssh_port',22)); key=Path((c.get('auth') or {}).get('ssh_key') or '~/.ssh/id_ed25519').expanduser()
    if not isinstance(host,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]+',host) or host.startswith('-') or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',user) or not 1<=port<=65535 or not key.is_file(): raise ValueError('invalid SSH configuration')
    return ['ssh','-T','-i',str(key),'-p',str(port),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',user+'@'+host]

def execute(cmd,root=False,timeout=25):
    secret=os.getenv('SUT_SUDO_PASSWORD',''); inp=''
    if root:
        if '\n' in secret or '\r' in secret: raise ValueError('invalid sudo secret')
        cmd=('sudo -k -S -p ""' if secret else 'sudo -n')+' -- sh -c '+shlex.quote(cmd); inp=secret+'\n' if secret else ''
    argv=ssh_argv()+[cmd]; env={k:v for k,v in os.environ.items() if k not in ('SUT_SUDO_PASSWORD','SUT_SSH_PASSWORD')}
    return subprocess.run(argv,input=inp,capture_output=True,text=True,timeout=timeout,env=env)

def fingerprint():
    p=execute('set -e; id -un; cat /etc/machine-id /proc/sys/kernel/random/boot_id /proc/cmdline /sys/devices/system/cpu/online /sys/devices/system/cpu/isolated /sys/devices/system/cpu/nohz_full /proc/irq/default_smp_affinity /sys/devices/virtual/workqueue/cpumask; grep Cpus_allowed_list /proc/1/status; uname -r')
    if p.returncode or p.stdout.splitlines()[:1]!=[read('config.yaml')['ssh_user']]: raise RuntimeError('target fingerprint unavailable')
    # Use stable fields, not cumulative interrupt counts or transient PSR.
    v=read('isolation_policy.yaml')['vm']; q=shlex.quote(v['name']); vir='LC_ALL=C virsh -r -c qemu:///system '
    r=execute(vir+'domstate '+q,root=True)
    if r.returncode: raise RuntimeError('selected VM state unavailable for fingerprint')
    state=r.stdout.strip(); from xml.etree import ElementTree as ET
    fields=[]
    for suffix in [' --inactive']+([''] if state=='running' else []):
        x=execute(vir+'dumpxml '+q+suffix,root=True)
        if x.returncode: raise RuntimeError('selected VM XML unavailable for fingerprint')
        root=ET.fromstring(x.stdout); fields.append([root.get('type'),root.findtext('uuid'),root.findtext('vcpu'),root.findtext('iothreads'),[dict(z.attrib) for z in root.findall('./cputune/vcpupin')],[dict(z.attrib) for z in root.findall('./cputune/emulatorpin')],[dict(z.attrib) for z in root.findall('./cputune/iothreadpin')]])
    a=execute('for f in /proc/irq/[0-9]*/effective_affinity_list; do [ -r "$f" ] || continue; printf "%s " "$f"; cat "$f" || exit 1; done')
    if a.returncode: raise RuntimeError('IRQ affinity inventory unavailable for fingerprint')
    return hashlib.sha256((p.stdout+'\n'+state+'\n'+json.dumps(fields,sort_keys=True)+'\n'+a.stdout).encode()).hexdigest()

def guest_ssh(run,p):
    """run(label, command, root)->(rc,out); requires unique lease or guest agent IP."""
    v=p['vm']; q=shlex.quote(v['name']); vir='LC_ALL=C virsh -c qemu:///system '
    r,o=run('vm_state',vir+'domstate '+q,True)
    if r!=0 or o!='running': raise ValueError('authorized test VM must already be running (no automatic start)')
    r,o=run('vm_interfaces',vir+'domiflist '+q,True)
    macs={m.lower() for m in re.findall(r'(?im)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',o)} if r==0 else set()
    if v.get('guest_mac'): macs&={v['guest_mac'].lower()}
    if len(macs)!=1: raise ValueError('confirm guest_mac for multiple or missing VM interfaces')
    ips=set()
    for source in ('lease','agent'):
        r,o=run('guest_ip_'+source,vir+'domifaddr '+q+' --source '+source,True)
        if r!=0: continue
        for line in o.splitlines():
            f=line.split()
            if len(f)>=4 and f[1].lower() in macs and f[2]=='ipv4':
                try: ips.add(str(ipaddress.IPv4Interface(f[3]).ip))
                except ValueError: pass
    if v.get('guest_ip'): ips&={str(ipaddress.IPv4Address(v['guest_ip']))}
    if len(ips)!=1: raise ValueError('no unique MAC-matched IPv4 from lease/agent; no guessed addresses')
    argv=['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',v['guest_user']+'@'+next(iter(ips))]
    r,o=run('guest_ssh_ready',shlex.join(argv+['set -e; id -un; nproc; command -v stress-ng; command -v python3']))
    lines=o.splitlines()
    if r!=0 or len(lines)!=4 or lines[:2]!=[v['guest_user'],str(v['vcpu_count'])]: raise ValueError('guest identity, CPU count or tools unavailable')
    # Verify live XML against the approved load placement before initiating workloads.
    from xml.etree import ElementTree as ET
    r,o=run('vm_live_load_guard',vir+'dumpxml '+q,True)
    if r!=0: raise ValueError('live VM placement not verified')
    d=ET.fromstring(o); pins={int(x.get('vcpu')):cpus(x.get('cpuset')) for x in d.findall('./cputune/vcpupin')}; expected={int(k):cpus(s) for k,s in v['vcpu_pinning'].items()}
    em=d.find('./cputune/emulatorpin')
    if d.get('type')!='kvm' or pins!=expected or em is None or cpus(em.get('cpuset'))!=cpus(v['emulator_cpus']) or d.findall('./cputune/iothreadpin') or int(d.findtext('iothreads','0')): raise ValueError('live VM affinity or unsupported dedicated IOThreads differs from approved profile')
    return argv
