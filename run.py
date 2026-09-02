#!/usr/bin/env python
"""Simple launcher:  python run.py -t targets.txt -p 554"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from CamReaper.__main__ import main

if __name__ == "__main__":
    main()
