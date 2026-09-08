"""Check a built wheel in isolation, without installing into the user's Python."""
import argparse
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('wheel', type=Path)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='draghunt-wheel-smoke-') as temp:
    root = Path(temp)
    installed = root / 'installed'
    with zipfile.ZipFile(args.wheel) as wheel:
        required = {'draghunt/siem/__init__.py', 'draghunt/siem/wazuh.py', 'draghunt/static/index.html',
                    'draghunt/static/app.js', 'draghunt/static/app.css'}
        assert required <= set(wheel.namelist()), 'wheel is missing runtime files'
        wheel.extractall(installed)
    script = '''import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from draghunt.config import RangeConfig
from draghunt.workflow import Workflow
from draghunt.web import STATIC
from draghunt.cli import main
assert (STATIC / "index.html").exists()
w = Workflow(RangeConfig(data_dir=sys.argv[2]))
c = w.create("DEMO-BRUTE", 7)
w.save_draft(c["id"], {"narrative": "Persisted wheel smoke test"})
assert Workflow(w.cfg).get(c["id"])["draft"]["narrative"] == "Persisted wheel smoke test"
assert main(["--help"]) is None
'''
    # argparse's --help exits zero; earlier assertions must already have passed.
    result = subprocess.run([sys.executable, '-I', '-c', script, str(installed), str(root/'data')],
                            cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(result.stderr or result.stdout)
    print('Isolated wheel check passed: SIEM, static assets, CLI imports, case creation and draft persistence.')
