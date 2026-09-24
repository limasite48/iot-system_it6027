import sys
import os

# Ensure net-sec directory is in Python path for test discovery
net_sec_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if net_sec_dir not in sys.path:
    sys.path.insert(0, net_sec_dir)
