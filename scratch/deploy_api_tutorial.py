import paramiko

host = '38.250.116.71'
user = 'root'
passwd = 'upt2026'

LOCAL = r'c:\Users\Gerardo\Documents\GitHub\proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp\app\templates\api_tutorial.html'
REMOTE = '/opt/owasp-verificador/app/templates/api_tutorial.html'

print("Connecting to VM...")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, username=user, password=passwd, timeout=15)

print("Uploading api_tutorial.html via SFTP...")
sftp = client.open_sftp()
sftp.put(LOCAL, REMOTE)
sftp.close()
print("Uploaded successfully!")

def run(cmd):
    _, o, e = client.exec_command(cmd)
    r = o.read().decode('utf-8', 'replace').strip()
    if r:
        print(f"$ {cmd}\n{r}")
    else:
        print(f"$ {cmd} (no output)")

print("Restarting service...")
run("systemctl restart owasp-verificador.service")

import time
time.sleep(3)

print("Checking service status...")
run("systemctl is-active owasp-verificador.service")

print("Checking endpoint response /api-tutorial...")
run("curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/api-tutorial")

client.close()
print("Deployment completed!")
