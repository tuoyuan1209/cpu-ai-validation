"""Safety prerequisites are distinct from performance-conformity results."""

def allows_active(stage, result):
    cases=result.get('cases',[])
    rows={c.get('id'):c.get('status') for c in cases}
    if len(rows)!=len(cases): return False
    known={'PASS','WARN','FAIL','INCONCLUSIVE','NOT_EXECUTED'}
    if any(x not in known for x in rows.values()): return False
    if stage=='02':
        expected={f'DISC{i:02d}' for i in range(1,5)}|{f'TP{i:02d}' for i in range(1,11)}
        critical=expected-{'TP09'}
    elif stage=='03':
        expected={f'ISO{i:02d}' for i in range(1,14)}
        critical={'ISO01','ISO02','ISO03','ISO04','ISO11','ISO12','ISO13'}
    elif stage=='04':
        expected={f'AFF{i:02d}' for i in range(1,6)}
        critical=expected-{'AFF05'}
    else: return False
    return set(rows)==expected and all(rows[k]=='PASS' for k in critical)
