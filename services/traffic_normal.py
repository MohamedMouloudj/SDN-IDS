import subprocess
import time
import random

commands = [
    'wget -q -O /dev/null http://192.168.10.10',
    'wget -q -O /dev/null ftp://192.168.20.10/',
    'nslookup http.local 192.168.20.12',
    'nslookup ftp.local 192.168.20.12',
    'python3 -c "import smtplib; s = smtplib.SMTP(\'192.168.20.11\', 25); s.sendmail(\'h1@test.com\', \'h2@test.com\', \'Subject: test\\n\\nhello\'); s.quit()"',
]

while True:
    cmd = random.choice(commands)
    subprocess.run(cmd, shell=True)
    time.sleep(random.uniform(1, 5))