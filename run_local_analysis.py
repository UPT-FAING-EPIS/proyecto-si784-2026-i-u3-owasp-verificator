#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
import shutil

# Ensure stdout uses UTF-8 encoding on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Colors for formatting
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

def print_section(title):
    print(f"\n{BLUE}{'=' * 60}{RESET}")
    print(f"{BLUE}🔍 {title}{RESET}")
    print(f"{BLUE}{'=' * 60}{RESET}\n")

def run_command(command, env=None):
    """Ejecuta un comando en consola y retorna el código de salida y la salida estándar/error."""
    current_env = os.environ.copy()
    current_env["APP_ENV"] = "test"
    if env:
        current_env.update(env)
    
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=current_env
        )
        output = []
        for line in iter(process.stdout.readline, ''):
            print(line, end='')
            output.append(line)
        process.stdout.close()
        return_code = process.wait()
        return return_code, "".join(output)
    except Exception as e:
        print(f"{RED}Error al ejecutar {command}: {e}{RESET}")
        return -1, str(e)

def main():
    results = {}
    
    # 1. Pruebas Unitarias
    print_section("Pruebas Unitarias (Pytest)")
    cmd = f'"{sys.executable}" -m pytest tests/test_scanner.py tests/test_api.py -v --tb=short'
    code, _ = run_command(cmd)
    results["Pruebas Unitarias"] = "Exitoso" if code == 0 else "Fallido"
    
    # 2. Pruebas de Integración
    print_section("Pruebas de Integración (Pytest)")
    cmd = f'"{sys.executable}" -m pytest tests/test_integration.py -v --tb=short'
    code, _ = run_command(cmd)
    results["Pruebas de Integración"] = "Exitoso" if code == 0 else "Fallido"
    
    # 3. Pruebas de Interfaz (UI)
    print_section("Pruebas de Interfaz/UI (Playwright)")
    # Playwright requires installation check, but let's run it
    cmd = f'"{sys.executable}" -m pytest tests/test_ui.py -v --tb=short'
    code, _ = run_command(cmd)
    results["Pruebas de Interfaz/UI"] = "Exitoso" if code == 0 else "Fallido"
    
    # 4. Pruebas BDD
    print_section("Pruebas BDD (Behave)")
    cmd = f'"{sys.executable}" -m behave features/ --format pretty --no-capture'
    code, _ = run_command(cmd)
    results["Pruebas BDD (Behave)"] = "Exitoso" if code == 0 else "Fallido"
    
    # 5. Pruebas de Mutación
    print_section("Pruebas de Mutación (Mutmut)")
    if shutil.which("mutmut"):
        cmd = f'mutmut run --paths-to-mutate=app/services/scanner.py --tests-dir=tests/ --runner="\\"{sys.executable}\\" -m pytest tests/test_scanner.py -x -q" --no-progress'
        code, _ = run_command(cmd)
        results["Pruebas de Mutación"] = "Exitoso" if code == 0 else "Fallido"
    else:
        print(f"{YELLOW}Mutmut no está instalado o no se encuentra en el PATH. Omitiendo.{RESET}")
        results["Pruebas de Mutación"] = "Omitido"
        
    # 6. Análisis Estático - Semgrep
    print_section("Análisis Estático (Semgrep)")
    if shutil.which("semgrep"):
        cmd = "semgrep scan --config p/owasp-top-ten --config p/python app/"
        code, _ = run_command(cmd)
        results["Semgrep Scan"] = "Exitoso" if code == 0 else "Fallido"
    else:
        print(f"{YELLOW}Semgrep no está instalado o no se encuentra en el PATH. Omitiendo.{RESET}")
        results["Semgrep Scan"] = "Omitido"
        
    # 7. Análisis Estático - Snyk
    print_section("Análisis Estático (Snyk)")
    if shutil.which("snyk"):
        cmd = "snyk test --file=requirements.txt"
        code, _ = run_command(cmd)
        results["Snyk Scan"] = "Exitoso" if code == 0 else "Fallido"
    else:
        print(f"{YELLOW}Snyk CLI no está instalado o no se encuentra en el PATH. Omitiendo.{RESET}")
        results["Snyk Scan"] = "Omitido"

    # Mostrar Resumen
    print("\n" + "=" * 60)
    print(f"📊 {BLUE}RESUMEN DE EJECUCIÓN LOCAL{RESET}")
    print("=" * 60)
    all_ok = True
    for test_name, status in results.items():
        if status == "Exitoso":
            print(f"  ✅ {test_name}: {GREEN}{status}{RESET}")
        elif status == "Omitido":
            print(f"  ⚠️  {test_name}: {YELLOW}{status}{RESET}")
        else:
            print(f"  ❌ {test_name}: {RED}{status}{RESET}")
            all_ok = False
    print("=" * 60)
    
    if not all_ok:
        sys.exit(1)

if __name__ == "__main__":
    main()
