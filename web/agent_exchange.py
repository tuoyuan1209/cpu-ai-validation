#!/usr/bin/env python3
"""Bounded exchange for the 3 read-only analysis Automations.
Usage: agent_exchange.py ROLE read | evidence RUN FILE | submit (JSON stdin).
This is a validation interface, not a sandbox for an untrusted Agent process.
"""
import hashlib, json, os, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
ENGINE=ROOT.parent
WEB=ROOT/'.web-state'
sys.path.insert(0,str(ENGINE))
from common.evidence import verify
from common.policy import clean_text

def load(role):
    if role not in ('10','11','12'): raise ValueError('invalid analysis role')
    r=json.loads((WEB/'analysis_request.json').read_text())
    if r.get('role')!=role or not re.fullmatch(r'flow-[0-9a-f]{32}',r.get('flow_id','')) or not re.fullmatch(r'[0-9a-f]{32}',r.get('token','')): raise ValueError('no current request for this role')
    d=WEB/'flows'/r['flow_id']; f=d/'facts.json'
    if hashlib.sha256(f.read_bytes()).hexdigest()!=r['facts_sha256']: raise ValueError('facts checksum mismatch')
    packet=json.loads(f.read_text()); return r,d,packet

def stage_map(packet): return {x['run_id']:x for x in packet['stages'] if x.get('run_id') and x.get('files')}
def ref_path(packet,rid,name):
    stage=stage_map(packet).get(rid)
    if not stage or not re.fullmatch(r'(run|discovery)-\d{8}T\d{6}Z-[0-9a-f]{8}',rid) or name not in stage['files']: raise ValueError('reference outside current workflow evidence')
    p=ENGINE/'runs'/rid; target=p/name
    if target.is_symlink() or not target.resolve().is_relative_to(p.resolve()) or verify(p)!=stage['manifest']: raise ValueError('reference integrity failure')
    return target

def validate_analysis(obj,packet):
    if not isinstance(obj,dict) or set(obj)!={'summary','findings','recommendations','limitations'}: raise ValueError('expected summary/findings/recommendations/limitations')
    if not isinstance(obj['summary'],str) or not 1<=len(obj['summary'])<=4000: raise ValueError('invalid summary')
    out={'summary':clean_text(obj['summary'])}
    for k in ('findings','recommendations','limitations'):
        rows=obj[k]
        if not isinstance(rows,list) or len(rows)>30: raise ValueError('invalid analysis list')
        out[k]=[]
        for row in rows:
            if not isinstance(row,dict) or set(row)!={'text','certainty','refs'} or row['certainty'] not in ('observed','hypothesis','limitation') or not isinstance(row['text'],str) or not 1<=len(row['text'])<=2000: raise ValueError('invalid analysis item')
            refs=row['refs']
            if not isinstance(refs,list) or len(refs)>12 or (not refs and row['certainty']!='limitation'): raise ValueError('evidence references required')
            for ref in refs:
                if not isinstance(ref,dict) or set(ref)!={'run_id','file'}: raise ValueError('invalid reference')
                ref_path(packet,ref['run_id'],ref['file'])
            out[k].append({'text':clean_text(row['text']),'certainty':row['certainty'],'refs':refs})
    return out

def main():
    role,action=sys.argv[1:3]; r,d,packet=load(role)
    if action=='read':
        previous=[]
        for code in ('10','11'):
            if int(code)>=int(role): continue
            path=d/('agent-'+code+'.json')
            if path.is_file():
                value=json.loads(path.read_text())
                if value.get('facts_sha256')==r['facts_sha256']: previous.append({'role':code,'analysis':validate_analysis(value['analysis'],packet)})
        print(json.dumps({**packet,'prior_agent_analysis':previous},ensure_ascii=False)); return
    if action=='evidence':
        if len(sys.argv)!=5: raise ValueError('supply exact run ID and file')
        f=ref_path(packet,sys.argv[3],sys.argv[4]); size=f.stat().st_size
        # Only bounded previews; report missing details rather than claiming completeness.
        with f.open('rb') as h: b=h.read(24000)
        print(clean_text(b.decode(errors='replace')))
        if size>len(b): print('\n[PREVIEW TRUNCATED; DO NOT CLAIM FULL CONTENT]')
        return
    if action=='submit':
        raw=sys.stdin.read(200001)
        if len(raw)>200000: raise ValueError('analysis too large')
        a=validate_analysis(json.loads(raw),packet)
        # Check current request again before committing. A second submit never overwrites.
        r2,_,_=load(role)
        if r2!=r: raise ValueError('request changed')
        out=d/('agent-'+role+'.json'); fd=os.open(out,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f: json.dump({'token':r['token'],'facts_sha256':r['facts_sha256'],'analysis':a},f,ensure_ascii=False,indent=2)
        print('ANALYSIS_SUBMITTED '+role+' '+r['flow_id']); return
    raise ValueError('invalid action')
if __name__=='__main__':
    try: main()
    except Exception as e: print('ANALYSIS_REJECTED: '+clean_text(str(e)),file=sys.stderr); sys.exit(1)
