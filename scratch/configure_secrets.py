import sys
import os
import subprocess
import json

# Ensure PyNaCl and requests are installed
try:
    import requests
    from nacl import encoding, public
except ImportError:
    print("Instalando dependencias necesarias (requests, pynacl)...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "pynacl"])
    import requests
    from nacl import encoding, public

# Ensure stdout uses UTF-8 encoding on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


# Configuración
GH_PAT = "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"
REPO = "UPT-FAING-EPIS/proyecto-si784-2026-i-u3-owasp-verificator"

SECRETS = {
    "SNYK_TOKEN": "snyk_uat.1fcad39e.eyJlIjoxNzg5NDAzNDgxLCJoIjoic255ay5pbyIsImoiOiJBWjdSUmd1UHUwcmdkR0xUbzhyNDZBIiwicyI6Iml1VmxkdG5LU2xxdmhydFRUZ2ZSR2ciLCJ0aWQiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIn0.1bhE7zSYRcmAE5GCqqXVaRZocTl6XkH7wv4m0ejkXHd1kXvk27GJqLdNr1XcV3foTNxAZ4Z1Y4LclopeN236Bg",
    "SONAR_TOKEN": "96788ff57be3d418fa9f4b232e0015ad0f686a7b",
    "OWASP_VERIFICATOR_TOKEN": "5b728645-7043-4ce5-8404-319d77f965fb",
    "GH_PAT": "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"
}

def encrypt(public_key: str, secret_value: str) -> str:
    """Encripta un valor secreto usando la clave pública del repositorio."""
    from base64 import b64encode
    public_key_obj = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key_obj)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")

def get_public_key(headers):
    url = f"https://api.github.com/repos/{REPO}/actions/secrets/public-key"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Error al obtener clave pública: {response.status_code} - {response.text}")
    return response.json()

def set_secret(headers, key_id, public_key, secret_name, secret_value):
    encrypted_value = encrypt(public_key, secret_value)
    url = f"https://api.github.com/repos/{REPO}/actions/secrets/{secret_name}"
    data = {
        "encrypted_value": encrypted_value,
        "key_id": key_id
    }
    response = requests.put(url, headers=headers, json=data)
    if response.status_code in (201, 204):
        print(f"[OK] Secreto '{secret_name}' guardado exitosamente.")
    else:
        print(f"[FAIL] Fallo al guardar '{secret_name}': {response.status_code} - {response.text}")

def main():
    headers = {
        "Authorization": f"token {GH_PAT}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    print(f"Obteniendo la clave pública para {REPO}...")
    try:
        pub_key_data = get_public_key(headers)
        key_id = pub_key_data["key_id"]
        public_key = pub_key_data["key"]
        print(f"Clave pública obtenida (Key ID: {key_id}).")
        
        for name, value in SECRETS.items():
            print(f"Configurando el secreto {name}...")
            set_secret(headers, key_id, public_key, name, value)
            
    except Exception as e:
        print(f"Ocurrió un error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
