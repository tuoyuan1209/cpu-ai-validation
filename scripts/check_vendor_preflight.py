#!/usr/bin/env python3
"""CPU-02 verification-only entry; does not call the old provisioning script."""
import sys
from discover_sut import main
if __name__ == '__main__':
    sys.argv.append('--preflight')
    raise SystemExit(main())
