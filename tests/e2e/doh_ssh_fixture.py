"""Keep the test-owned SSH server outside any running PL's child-process hooks."""
import runpy
from pathlib import Path
from doh_transport import isolate_controller

isolate_controller()
runpy.run_path(str(Path(__file__).resolve().parents[1] / 'ssh_test_servers.py'), run_name='__main__')
