import os, subprocess, shutil

temp_dir = os.environ.get('TEMP', 'C:\\Windows\\Temp')
ps_script = (
    '[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms");'
    '$objNotifyIcon = New-Object System.Windows.Forms.NotifyIcon;'
    '$objNotifyIcon.Icon = [System.Drawing.SystemIcons]::Information;'
    '$objNotifyIcon.BalloonTipTitle = "ZeroWatch";'
    '$objNotifyIcon.BalloonTipText = "Zerowatch agent is starting an inventory scan";'
    '$objNotifyIcon.Visible = $True;'
    '$objNotifyIcon.ShowBalloonTip(5000);'
    'Start-Sleep -Seconds 5;'
    '$objNotifyIcon.Dispose();'
)
ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
zw_exe = os.path.join(temp_dir, "SentinelAgent.exe")

if not os.path.exists(zw_exe):
    shutil.copy2(ps_exe, zw_exe)

print("Running script:", ps_script)
subprocess.run([zw_exe, "-WindowStyle", "Hidden", "-Command", ps_script])
