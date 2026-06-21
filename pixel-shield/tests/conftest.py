"""Put the package root (oled_maintainer/) on sys.path so `import core...` works
whether pytest is invoked from the repo root or the package dir.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
