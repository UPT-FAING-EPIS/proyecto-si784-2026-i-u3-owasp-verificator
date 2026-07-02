# Archivo de prueba con vulnerabilidades OWASP para pruebas

import os
import requests
import pickle

# OWASP-A02: Fallas Criptográficas (Secretos expuestos)
DB_PASSWORD = "super_secret_password_123!"
API_KEY = "xyz-98765-alpha-beta"

# OWASP-A05: Configuración Incorrecta
debug = True
SECRET_KEY = "unsafe_jwt_secret_key"

# OWASP-A01: Control de Acceso Roto (endpoints sin chequeo explícito)
def get_user_data(request):
    user_id = request.get('user_id')
    return {"id": user_id, "role": "admin"}

# OWASP-A03: Inyección de Código
def execute_user_code(user_input):
    # Esto activará la alerta de inyección de código
    eval(user_input)
    
# OWASP-A03: Deserialización insegura
def load_data(payload):
    return pickle.loads(payload)

# OWASP-A04: Diseño Inseguro (Comentarios sugestivos)
# TODO: Implementar autenticación segura antes de producción
# FIXME: Quitar esta lógica temporal que salta la firma
# HACK: Bypass temporal para agilizar las pruebas

# OWASP-A07: Fallas de Autenticación
def login(username, password):
    # Comparación insegura
    if password == "password":
        return True
    return False

# OWASP-A08 y OWASP-A10: Fallas de Integridad y SSRF
def fetch_external_report(url):
    # Llama a un endpoint arbitrario sin validación
    response = requests.get(url)
    return response.text

# OWASP-A09: Fallas en Logging y Monitoreo
def process_data(data):
    try:
        result = data / 0
    except:
        # Excepción silenciosa sin registro de logging
        pass
