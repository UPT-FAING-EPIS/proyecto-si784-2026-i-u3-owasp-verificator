import paramiko
import os
import time

host = '38.250.116.71'
user = 'root'
passwd = 'upt2026'

BASE_LOCAL = r'c:\Users\Gerardo\Documents\GitHub\proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp'
REMOTE_BASE = '/opt/owasp-verificador'

# Dynamically build files to deploy
FILES = []
REMOTE_DIRS = set()

# Add root files
FILES.append(('schema.sql', f'{REMOTE_BASE}/schema.sql'))
FILES.append(('requirements.txt', f'{REMOTE_BASE}/requirements.txt'))

for root, dirs, files in os.walk(BASE_LOCAL):
    # Only keep the app directory
    if os.path.join(BASE_LOCAL, 'app') in root:
        if '__pycache__' in root or '.pytest_cache' in root:
            continue
        for file in files:
            local_path = os.path.join(root, file)
            relative_local = os.path.relpath(local_path, BASE_LOCAL)
            remote = f"{REMOTE_BASE}/{relative_local.replace(os.sep, '/')}"
            FILES.append((relative_local, remote))
            REMOTE_DIRS.add(os.path.dirname(remote))

def run(client, cmd, show=True):
    _, o, e = client.exec_command(cmd)
    out = o.read().decode('utf-8', 'replace').strip()
    err = e.read().decode('utf-8', 'replace').strip()
    if show:
        print(f"  $ {cmd}")
        if out:
            print(f"    {out}")
        if err:
            print(f"  ERR: {err}")
    return out

print("=" * 60)
print("  OWASP Verificador — Deploy a VM (puerto 8000)")
print("=" * 60)

print(f"\n[1/5] Conectando a {host}...")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, username=user, password=passwd, timeout=15)
print("      Conectado OK")

print(f"\n[2/5] Creando directorios remotos necesarios...")
# Create remote directory structure dynamically
for rdir in sorted(REMOTE_DIRS):
    run(client, f"mkdir -p {rdir}", show=False)
print("      Directorios listos")

print(f"\n[3/5] Subiendo {len(FILES)} archivos via SFTP...")
sftp = client.open_sftp()
for relative_local, remote in FILES:
    local_path = os.path.join(BASE_LOCAL, relative_local)
    if os.path.exists(local_path):
        print(f"      >> {relative_local}")
        sftp.put(local_path, remote)
    else:
        print(f"      SKIP (no existe): {relative_local}")
sftp.close()
print("      Todos los archivos subidos")

print(f"\n[4/5] Recreando base de datos MySQL...")
# Drop y recrear la BD completa con schema actualizado (incluye email en users)
run(client, "mysql -u root -pupt2026 -e 'DROP DATABASE IF EXISTS owasp_verificador;'")
db_cmd = f"mysql -u root -pupt2026 < {REMOTE_BASE}/schema.sql"
run(client, db_cmd)
# Verificar tablas
tables_out = run(client, "mysql -u root -pupt2026 -e 'USE owasp_verificador; SHOW TABLES;' 2>/dev/null")
print(f"      Tablas en BD: {tables_out.replace(chr(10), ', ')}")

print(f"\n[5/5] Reiniciando servicio en puerto 8000...")
run(client, "systemctl restart owasp-verificador.service")
time.sleep(4)

status = run(client, "systemctl is-active owasp-verificador.service")
print(f"\n  Estado servicio: {status}")

print("\n  Verificando endpoints (puerto 8000):")
run(client, "curl -s -o /dev/null -w '      / -> %{http_code}\\n' http://localhost:8000/")
run(client, "curl -s -o /dev/null -w '      /analyze -> %{http_code}\\n' http://localhost:8000/analyze")
run(client, "curl -s -o /dev/null -w '      /login -> %{http_code}\\n' http://localhost:8000/login")
run(client, "curl -s -o /dev/null -w '      /about -> %{http_code}\\n' http://localhost:8000/about")
run(client, "curl -s -o /dev/null -w '      /owasp -> %{http_code}\\n' http://localhost:8000/owasp")

client.close()
print("\n" + "=" * 60)
print("  Deploy completado exitosamente")
print("  URL: http://38.250.116.71:8000")
print("=" * 60)
