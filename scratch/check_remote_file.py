import paramiko

host = '38.250.116.71'
user = 'root'
passwd = 'upt2026'

print("Connecting to VM...")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, username=user, password=passwd, timeout=15)

def run(cmd):
    _, o, e = client.exec_command(cmd)
    r = o.read().decode('utf-8', 'replace').strip()
    return r

print("Inspecting remote api_tutorial.html lines 245-275...")
out = run("sed -n '245,275p' /opt/owasp-verificador/app/templates/api_tutorial.html")
print(out.encode('ascii', 'backslashreplace').decode('ascii'))

client.close()
