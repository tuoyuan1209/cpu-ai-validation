"""Bounded, continuous host cyclictest with independent guest or host stress."""
import re, json, shlex
from .policy import cpus,fmt,workers,validate,verify_only,read
from .transport import guest_ssh
from .evidence import Run

GUEST=r'''
import sys,subprocess,time,json,os,signal
n,d=map(int,sys.argv[1:]); p=subprocess.Popen(['stress-ng','--cpu',str(n),'--cpu-method','matrixprod','--cpu-load','100','--timeout',str(d+30)+'s','--metrics-brief'],stdout=sys.stderr,stderr=sys.stderr,start_new_session=True)
def stat(): return list(map(int,open('/proc/stat').readline().split()[1:9]))
try:
 time.sleep(2)
 if p.poll() is not None: raise RuntimeError('guest stress failed before READY')
 a=stat(); t=time.monotonic(); print('READY',flush=True)
 while time.monotonic()-t<d+12:
  if p.poll() is not None: raise RuntimeError('guest stress ended early')
  time.sleep(1)
 b=stat(); z=[j-i for i,j in zip(a,b)]; total=sum(z)
 if total<=0 or min(z)<0: raise RuntimeError('invalid guest counters')
 print('METRIC '+json.dumps({'elapsed':time.monotonic()-t,'busy':sum(z[i] for i in (0,1,2,5,6))/total,'steal':z[7]/total,'ticks':z}),flush=True)
 if p.wait(timeout=25)!=0: raise RuntimeError('guest stress failed')
finally:
 if p.poll() is None: os.killpg(p.pid,signal.SIGTERM); p.wait(timeout=5)
'''
REMOTE=r'''
import sys,os,time,subprocess,signal,threading,queue,json,re
cfg=json.loads(sys.argv[1]); d=cfg['seconds']; cpu=cfg['cpu']; mode=cfg['mode']; hk=cfg['hk']; hostload=None; guestload=None; cyc=None; messages=queue.Queue(); samples=[]
def stop(p):
 if p and p.poll() is None:
  try: os.killpg(p.pid,signal.SIGTERM); p.wait(timeout=5)
  except subprocess.TimeoutExpired: os.killpg(p.pid,signal.SIGKILL); p.wait(timeout=5)
def stat():
 return {int(p[0][3:]):list(map(int,p[1:9])) for l in open('/proc/stat') if (p:=l.split()) and re.fullmatch(r'cpu\d+',p[0])}
def irq(): return open('/proc/interrupts').read()
def sample(pid):
 result=[]
 for tid in os.listdir('/proc/'+str(pid)+'/task'):
  try:
   tid=int(tid); result.append({'tid':tid,'allowed':sorted(os.sched_getaffinity(tid)),'scheduler':os.sched_getscheduler(tid),'priority':os.sched_getparam(tid).sched_priority})
  except (ProcessLookupError,FileNotFoundError): pass
 return result
try:
 if mode in ('host','joint'):
  hostload=subprocess.Popen(['taskset','-c',hk,'stress-ng','--cpu',str(cfg['workers']),'--cpu-method','matrixprod','--cpu-load','100','--timeout',str(d+(45 if mode=='joint' else 15))+'s','--metrics-brief'],stdout=sys.stderr,stderr=sys.stderr,start_new_session=True); time.sleep(2)
 if mode in ('guest','joint'):
  guestload=subprocess.Popen(cfg['guest'],stdout=subprocess.PIPE,stderr=sys.stderr,text=True,bufsize=1,start_new_session=True)
  def reader():
   for l in guestload.stdout: messages.put(l.rstrip())
   messages.put(None)
  threading.Thread(target=reader,daemon=True).start(); deadline=time.monotonic()+20
  while True:
   l=messages.get(timeout=max(.01,deadline-time.monotonic()))
   if l is None: raise RuntimeError('guest exited before READY')
   if l=='READY': break
   if time.monotonic()>=deadline: raise RuntimeError('guest READY timeout')
 loads=[p for p in (hostload,guestload) if p is not None]
 if any(p.poll() is not None for p in loads): raise RuntimeError('load exited before cyclictest')
 a=stat(); ib=irq(); t=time.monotonic(); cmd=['cyclictest','-a',str(cpu),'-t','1','-p',str(cfg['priority']),'-i',str(cfg['interval']),'-m','-D',str(d)+'s']+([] if cfg.get('trend') else ['-q'])
 cyc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 # Stream real display lines; retain bounded raw tail plus sampled raw lines, not synthetic trend.
 result={'out':'','err':'','stdout_tail':'','stdout_bytes':0,'trend':[]}; pattern=re.compile(rb'T:\s*\d+\s*\(\s*(\d+)\s*\)\s*P:\s*(\d+)\s*I:\s*(\d+)\s*C:\s*(\d+)\s*Min:\s*(\d+)\s*Act:\s*(\d+)\s*Avg:\s*(\d+)\s*Max:\s*(\d+)(?=[\r\n\x1b ]|$)')
 def collect_stdout():
  pending=b''; tail=b''; last=None; next_trend=0; total=0
  while True:
   b=os.read(cyc.stdout.fileno(),65536)
   if not b: break
   total+=len(b); tail=(tail+b)[-65536:]; pending+=b
   # Parse only complete lines during streaming; terminal display may use CR or LF.
   pieces=re.split(rb'[\r\n]',pending); pending=pieces.pop()
   for line in pieces:
    for m in pattern.finditer(line):
     last=m.group(0).decode(errors='replace'); n,mi,act,av,mx=map(int,m.groups()[3:]); elapsed=time.monotonic()-t
     if cfg.get('trend') and n>0 and elapsed>=next_trend:
      result['trend'].append({'elapsed_s':round(elapsed,3),'cycles':n,'min_us':mi,'avg_us':av,'max_us':mx,'raw_line':last}); next_trend=elapsed+30
   if len(pending)>65536: pending=pending[-65536:]
  for m in pattern.finditer(pending): last=m.group(0).decode(errors='replace')
  result['stdout_tail']=tail.decode(errors='replace'); result['stdout_bytes']=total
  result['out']=last or result['stdout_tail'] if cfg.get('trend') else result['stdout_tail']
 def collect_stderr():
  tail=b''
  while True:
   b=os.read(cyc.stderr.fileno(),65536)
   if not b: break
   tail=(tail+b)[-65536:]
  result['err']=tail.decode(errors='replace')
 th=threading.Thread(target=collect_stdout,daemon=True); eh=threading.Thread(target=collect_stderr,daemon=True); th.start(); eh.start(); next_sample=1
 while th.is_alive() or eh.is_alive() or cyc.poll() is None:
  elapsed=time.monotonic()-t
  if elapsed>d+15: raise RuntimeError('cyclictest exceeded bounded duration')
  if any(p.poll() is not None for p in loads): raise RuntimeError('load ended during cyclictest')
  if elapsed>=next_sample:
   try: samples.append({'elapsed':elapsed,'threads':sample(cyc.pid)})
   except FileNotFoundError: pass
   next_sample=elapsed+(1 if elapsed<3 else 5 if d<180 else 30)
  th.join(.25); eh.join(.01)
  if not th.is_alive() and cyc.poll() is None: time.sleep(.05)
 elapsed=time.monotonic()-t; b=stat(); ia=irq()
 if any(p.poll() is not None for p in loads): raise RuntimeError('load did not span complete window')
 metric=None
 if mode in ('guest','joint'):
  deadline=time.monotonic()+60
  while True:
   l=messages.get(timeout=max(.01,deadline-time.monotonic()))
   if l is None: break
   if l.startswith('METRIC '): metric=json.loads(l[7:])
  if guestload.wait(timeout=5)!=0 or not metric or metric['elapsed']<elapsed: raise RuntimeError('guest load duration/metrics invalid')
 if mode in ('host','joint'):
  if hostload.wait(timeout=60)!=0: raise RuntimeError('host stress failed')
 hk_ids=list(map(int,hk.split(','))); z=[sum(b[c][i]-a[c][i] for c in hk_ids) for i in range(8)]; total=sum(z)
 if total<=0 or min(z)<0: raise RuntimeError('invalid housekeeping counters')
 print(json.dumps({'cyclictest_argv':cmd,'rc':cyc.returncode,'stdout':result['out'],'stdout_tail':result['stdout_tail'],'stdout_bytes':result['stdout_bytes'],'trend':result['trend'],'stderr':result['err'],'elapsed':elapsed,'thread_samples':samples,'host_busy':sum(z[i] for i in (0,1,2,5,6))/total,'guest':metric,'irq_before':ib,'irq_after':ia}),flush=True)
finally:
 stop(cyc); stop(hostload); stop(guestload)
'''
PAT=re.compile(r'T:\s*\d+\s*\(\s*(\d+)\s*\)\s*P:\s*(\d+)\s*I:\s*(\d+)\s*C:\s*(\d+)\s*Min:\s*(\d+)\s*Act:\s*(\d+)\s*Avg:\s*(\d+)\s*Max:\s*(\d+)',re.M)

def parse_result(data,cpu,seconds,priority,interval,mode):
    rows=PAT.findall(data['stdout'])
    if data['rc']!=0 or len(rows)!=1: raise ValueError('cyclictest failed or summary missing/ambiguous')
    tid,p,i,n,mn,act,av,mx=map(int,rows[0]); expected=seconds*1_000_000/interval
    if p!=priority or i!=interval or not 0<=mn<=av<=mx or not .98*expected<=n<=1.02*expected or not seconds*.98<=data['elapsed']<=seconds+15: raise ValueError('cycle count, duration, priority or interval mismatch')
    samples=[(s['elapsed'],r) for s in data['thread_samples'] for r in s['threads'] if r['tid']==tid]
    if len(samples)<2 or not all(r['allowed']==[cpu] and r['priority']==priority and r['scheduler']==1 for _,r in samples): raise ValueError('actual FIFO thread affinity/priority evidence incomplete or inconsistent')
    if samples[0][0]>5 or samples[-1][0]<seconds-(40 if seconds>=180 else 10): raise ValueError('thread sampling window incomplete')
    if mode in ('host','joint') and data['host_busy']<.8: raise ValueError('host load insufficient')
    if mode in ('guest','joint') and (not data['guest'] or data['guest']['busy']<.5): raise ValueError('guest busy excluding steal below 50%')
    return dict(cpu=cpu,tid=tid,cycles=n,min_us=mn,avg_us=av,max_us=mx,elapsed_s=data['elapsed'],fifo_thread_samples=len(samples),host_busy=data['host_busy'],guest=data['guest'])

def main(long=False):
    stage='CPU-08' if long else 'CPU-07'; run=Run(stage)
    try:
        p=validate(read('isolation_policy.yaml'),load=True); verify_only(); rt=p.get('realtime',{}); priority=rt.get('priority',80); interval=rt.get('interval_us',1000); seconds=rt.get('long_duration_s',3600) if long else rt.get('short_duration_s',60); threshold=rt.get('max_latency_us'); cpu=p['test_cpu']; hk=fmt(cpus(p['housekeeping_cpus']))
        run.dump('environment.json',{'stage':stage,'policy':p,'duration_s':seconds,'threshold_us':threshold})
        r,o=run.run('baseline','cat /sys/devices/system/cpu/online /sys/devices/system/cpu/isolated /sys/kernel/realtime')
        z=o.splitlines()
        if r!=0 or len(z)!=3 or cpus(z[0])!=cpus(p['online_cpus']) or cpus(z[1])!=cpus(p['isolated_cpus']) or z[2]!='1': raise ValueError('runtime CPU/RT baseline mismatch')
        r,o=run.run('fifo_precheck',f'command -v cyclictest && chrt -f {priority} true && ulimit -l')
        if r!=0: raise ValueError('unprivileged RT execution not available; vendor must grant test permission')
        def phase(cid,c,mode):
            try:
                guest=[]
                if mode in ('guest','joint'): guest=guest_ssh(lambda label,cmd,root=False:run.run(cid.lower()+'_'+label,cmd,root),p)+[shlex.join(['python3','-c',GUEST,str(workers(p,'guest_cpu_workers')),str(seconds)])]
                cfg=dict(seconds=seconds,cpu=c,mode=mode,hk=hk,priority=priority,interval=interval,workers=workers(p,'host_cpu_workers'),guest=guest,trend=long)
                cmd=shlex.join(['taskset','-c',hk,'timeout','--kill-after=10s',str(seconds+100)+'s','python3','-c',REMOTE,json.dumps(cfg)])
                r,o=run.run(cid.lower(),cmd,timeout=seconds+130)
                if r!=0: raise ValueError('remote latency test failed, inspect evidence')
                data=json.loads(o); metrics=parse_result(data,c,seconds,priority,interval,mode)
                metrics.update(group=cid,condition=mode,planned_seconds=seconds,priority=priority,interval_us=interval,threshold_us=threshold)
                run.dump('evidence/'+cid.lower()+'_metrics.json',metrics)
                if long:
                    samples=data.get('trend',[])
                    # Keep measured cumulative summaries only, validate monotonic cycles/max.
                    trend=[]
                    for x in samples:
                        if x.get('cycles',0)>0 and x['cycles']<=metrics['cycles'] and x['max_us']<=metrics['max_us'] and (not trend or (x['cycles']>trend[-1]['cycles'] and x['max_us']>=trend[-1]['max_us'])): trend.append(x)
                    run.dump('evidence/'+cid.lower()+'_trend.json',{'kind':'cumulative cyclictest output','samples':trend,'source':f'evidence/{cid.lower()}.stdout','sample_interval_s':30,'complete_raw_stream':False,'note':'Samples are observed display lines; no interpolation or window maximum. Missing intermediate output is not fabricated.'})
                run.case(cid,f'{mode} cyclictest CPU {c}','INCONCLUSIVE' if threshold is None else 'PASS' if metrics['max_us']<=threshold else 'FAIL',{'max_latency_us':threshold,'seconds':seconds,'measurement_valid':True,'decision_basis':'threshold_missing' if threshold is None else 'threshold_provided'},metrics)
            except Exception as e: run.case(cid,f'{mode} cyclictest CPU {c}','INCONCLUSIVE','complete load/RT evidence',str(e))
        if long: phase('STAB01',cpu,'guest')
        else:
            phase('LAT01',cpu,'baseline'); phase('LAT02',cpu,'host'); phase('LAT03',cpu,'guest'); phase('LAT04',cpu,'joint')
            if rt.get('compare_isolated_cores') is True:
                for c in sorted(cpus(p['isolated_cpus'])-{cpu}): phase(f'LAT_CPU{c}',c,'baseline')
    except Exception as e: run.case('ERROR','prerequisite','INCONCLUSIVE','valid approved test profile',str(e))
    return run.finish()
