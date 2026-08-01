import subprocess
import os

syft_path = os.path.join("resources", "syft.exe")
p = subprocess.Popen(
    [syft_path, "dir:C:\\Users\\admin\\Desktop", "-o", "json", "-vv"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)
count = 0
found_trace = False
for line in p.stderr:
    if "TRACE" in line or "DEBUG" in line or "cataloging" in line or "path" in line:
        print(line.strip())
        found_trace = True
        count += 1
    if count > 30:
        break
p.kill()
