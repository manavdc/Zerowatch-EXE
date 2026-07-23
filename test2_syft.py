import subprocess
import os
import sys
import threading
import time

syft_path = os.path.join("resources", "syft.exe")

p = subprocess.Popen(
    [syft_path, "dir:C:\\Users\\admin\\Desktop", "-o", "json=test_sbom.json", "-vv"],
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
    creationflags=subprocess.CREATE_NO_WINDOW
)

def read_stderr():
    count = 0
    for line in iter(p.stderr.readline, ''):
        if "cataloging path=" in line:
            print("SCANNED:", line.strip().split("cataloging path=")[-1])
            count += 1
        if count > 10:
            p.kill()
            break

t = threading.Thread(target=read_stderr)
t.start()
t.join(5)
p.kill()
print("Done")
