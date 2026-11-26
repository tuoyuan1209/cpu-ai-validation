#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common.latency import main
if __name__=='__main__':
    if '--continuous-60min' not in sys.argv: raise SystemExit('Use run_stage.py 08 --allow-long from a persistent controller terminal')
    raise SystemExit(main(long=True))
