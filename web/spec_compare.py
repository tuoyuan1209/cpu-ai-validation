"""Compare independent supplier expectations against verified discovery evidence."""
import re, json
from pathlib import Path

FIELDS=[('online_cpus','在线 CPU','cpus'),('housekeeping_cpus','普通核心','cpus'),('isolated_cpus','隔离核心','cpus'),('kthread_cpus','内核线程绑定','cpus'),('isolation_mechanism','隔离机制','text'),('vm.name','KVM 名称','text'),('vm.vcpu_count','vCPU 数量','int'),('vm.emulator_cpus','模拟器绑定','cpus'),('vm.iothread_pinning','IOThread 绑定','empty')]

def get(p,path):
    for k in path.split('.'):
        if not isinstance(p,dict): return None
        p=p.get(k)
    return p

def cpu_set(s):
    if not isinstance(s,str) or not s.strip(): raise ValueError('CPU 范围不能为空')
    out=set()
    for piece in s.split(','):
        if not re.fullmatch(r'\d+(?:-\d+)?',piece.strip()): raise ValueError('CPU 范围格式错误')
        a,b=map(int,(piece.strip().split('-')[0],piece.strip().split('-')[-1]))
        if not 0<=a<=b<=65535: raise ValueError('CPU 范围无效')
        out.update(range(a,b+1))
    return out

def norm(x,kind):
    if x is None or x=='' or isinstance(x,str) and '[REDACTED]' in x: raise ValueError('缺少有效值')
    if kind=='cpus': return cpu_set(x)
    if kind=='int':
        if type(x) is not int: raise ValueError('需要整数')
        return x
    if kind=='empty':
        if x in ({},[]): return ()
        return x
    return x

def compare(expected,observed,rt=None):
    rows=[]
    def add(path,label,e,a,kind):
        try: status='MATCH' if norm(e,kind)==norm(a,kind) else 'MISMATCH'
        except (ValueError,TypeError): status='UNKNOWN'
        rows.append(dict(path=path,label=label,expected=e,actual=a,status=status))
    for path,label,kind in FIELDS: add(path,label,get(expected,path),get(observed,path),kind)
    ep=get(expected,'vm.vcpu_pinning') or {}; ap=get(observed,'vm.vcpu_pinning') or {}
    ep={str(k):v for k,v in ep.items()}; ap={str(k):v for k,v in ap.items()}
    for k in sorted(ep.keys()|ap.keys(),key=lambda k:(not k.isdigit(),int(k) if k.isdigit() else k)):
        add('vm.vcpu_pinning.'+k,'vCPU '+k+' 绑定',ep.get(k),ap.get(k),'cpus')
    add('rt_kernel','RT 内核（固定验收要求）','1',rt,'text')
    return rows

def summary(rows):
    return {s:sum(r['status']==s for r in rows) for s in ('MATCH','MISMATCH','UNKNOWN')}

def check_comparison(rows):
    if not rows or any(r['status']!='MATCH' for r in rows): raise ValueError('供应商规格与实际探测存在差异或无法确认，不能审批；请核对规格或要求供应商整改后重新探测')
