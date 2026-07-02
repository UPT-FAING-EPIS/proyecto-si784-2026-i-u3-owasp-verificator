#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import json
import re

# Add the project root to sys.path to resolve imports correctly
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Ensure stdout uses UTF-8 encoding (fixes Windows accent character issues)
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

try:
    from app.services.scanner import RULES, remediation_for, detect_frameworks
    from app.services.cve_analyzer import analyze_for_cves
except ImportError as e:
    print(json.dumps({"error": f"Import error: {str(e)}"}), file=sys.stderr)
    sys.exit(1)

# Translation mappings for English support
TRANSLATIONS = {
    "en": {
        "OWASP-A01": {
            "title": "Broken Access Control",
            "description": "Detected endpoints or functions without explicit permission or authentication validation.",
            "remediation": "1. Verify permissions on each endpoint.\n2. Use authentication decorators.\n3. Validate user roles before operations.\n4. Implement Role-Based Access Control (RBAC)."
        },
        "OWASP-A02": {
            "title": "Cryptographic Failures - Secret Exposure",
            "description": "Hardcoded secrets, passwords, or keys detected in the code.",
            "remediation": "1. Never hardcode secrets.\n2. Use environment variables (os.getenv()).\n3. Implement a secret manager (Azure Key Vault, HashiCorp Vault).\n4. Rotate credentials regularly."
        },
        "OWASP-A03": {
            "title": "Code Injection",
            "description": "Detected functions allowing dynamic code execution or unsafe code injection.",
            "remediation": "1. Avoid eval(), exec(), pickle.loads().\n2. Use safe alternative functions.\n3. Validate and sanitize ALL user input.\n4. Use ORM for SQL queries."
        },
        "OWASP-A04": {
            "title": "Insecure Design",
            "description": "Comments suggesting insecure logic or lack of business validation.",
            "remediation": "1. Design with security in mind from the start.\n2. Use threat modeling.\n3. Implement rate limiting and timeouts.\n4. Validate business flows."
        },
        "OWASP-A05": {
            "title": "Security Misconfiguration",
            "description": "Insufficient security configuration detected (active debug, exposed secrets).",
            "remediation": "1. Add security HTTP headers (CSP, HSTS, X-Frame-Options).\n2. Disable debug mode in production.\n3. Enforce HTTPS.\n4. Configure restrictive CORS."
        },
        "OWASP-A06": {
            "title": "Vulnerable and Outdated Components",
            "description": "Imported libraries detected (verify versions and CVEs of dependencies).",
            "remediation": "1. Keep dependencies updated.\n2. Use `pip audit` to check for vulnerabilities.\n3. Review CVEs regularly.\n4. Use tools like OWASP Dependency-Check."
        },
        "OWASP-A07": {
            "title": "Identification and Authentication Failures",
            "description": "Authentication logic detected without clear security implementation.",
            "remediation": "1. Implement strong authentication (JWT, OAuth2, SAML).\n2. Hash passwords (bcrypt, argon2).\n3. Use MFA when possible.\n4. Secure session management."
        },
        "OWASP-A08": {
            "title": "Software and Data Integrity Failures",
            "description": "Downloads or code imports detected that could be intercepted.",
            "remediation": "1. Implement code integrity (digital signatures).\n2. Use HTTPS for all downloads.\n3. Verify checksums of integrity.\n4. Use secure CI/CD."
        },
        "OWASP-A09": {
            "title": "Security Logging and Monitoring Failures",
            "description": "Exception handling without visible logging (security events could be hidden).",
            "remediation": "1. Implement security event logging.\n2. Monitor failed authentication attempts.\n3. Setup alerts for suspicious activity.\n4. Maintain adequate log retention."
        },
        "OWASP-A10": {
            "title": "Server-Side Request Forgery (SSRF)",
            "description": "HTTP calls detected that could be exploited for SSRF.",
            "remediation": "1. Validate and whitelist destination URLs.\n2. Avoid user-supplied URLs in requests.\n3. Use network segmentation.\n4. Disable access to private IPs."
        }
    }
}

def scan_file(filepath, lang="es"):
    if not os.path.exists(filepath):
        return {"error": f"Archivo no encontrado: {filepath}" if lang == "es" else f"File not found: {filepath}"}
    if os.path.isdir(filepath):
        msg = "La ruta especificada es un directorio, no un archivo" if lang == "es" else "Specified path is a directory, not a file"
        return {"error": f"{msg}: {filepath}"}

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            f.seek(0)
            lines = f.readlines()
    except Exception as e:
        msg = "No se pudo leer el archivo" if lang == "es" else "Could not read file"
        return {"error": f"{msg}: {str(e)}"}

    findings = []
    frameworks = detect_frameworks(content)

    # 1. Analizar reglas estándar línea por línea para ubicar la posición exacta
    for line_num, line_content in enumerate(lines, start=1):
        for rule in RULES:
            for pattern in rule["patterns"]:
                match = re.search(pattern, line_content, re.IGNORECASE)
                if match:
                    rule_id = rule["rule_id"]
                    title = rule["title"]
                    description = rule["description"]
                    remediation = remediation_for(rule_id, frameworks)

                    # Apply translation if requested
                    if lang == "en" and rule_id in TRANSLATIONS["en"]:
                        trans = TRANSLATIONS["en"][rule_id]
                        title = trans["title"]
                        description = trans["description"]
                        remediation = trans["remediation"]

                    findings.append({
                        "rule_id": rule_id,
                        "title": title,
                        "severity": rule["severity"],
                        "description": description,
                        "evidence": match.group(0).strip(),
                        "line": line_num,
                        "character": match.start(),
                        "remediation": remediation
                    })
                    break  # solo reportar una coincidencia de esta regla por línea

    # 2. Analizar vulnerabilidades de dependencias (CVEs)
    cve_findings = analyze_for_cves(content)
    for cve in cve_findings:
        matched_line = 1
        matched_char = 0
        package_name = cve.title.replace("Componente vulnerable: ", "").strip()
        
        for line_num, line_content in enumerate(lines, start=1):
            if re.search(r"\bimport\s+" + re.escape(package_name) + r"\b", line_content) or \
               re.search(r"\bfrom\s+" + re.escape(package_name) + r"\b", line_content) or \
               re.search(r"\b" + re.escape(package_name) + r"\s*==\s*", line_content):
                matched_line = line_num
                match = re.search(r"\b(import|from|" + re.escape(package_name) + r")\b", line_content)
                if match:
                    matched_char = match.start()
                break

        title = cve.title
        description = cve.description
        remediation = "Actualizar el paquete a una versión segura o remover el uso del módulo inseguro."

        if lang == "en":
            title = title.replace("Componente vulnerable: ", "Vulnerable Component: ")
            remediation = "Update the package to a secure version or remove the use of the insecure module."
            
            # Translate descriptions for known CVEs
            if "pickle" in title.lower():
                description = "The pickle module is inherently insecure."
            elif "cryptography" in title.lower():
                description = "Weak cryptography configuration."
            elif "requests" in title.lower():
                if "headers" in description.lower():
                    description = "Header injection vulnerability."
                else:
                    description = "Insufficient resource limitation."
            elif "django" in title.lower():
                if "confidencial" in description.lower():
                    description = "Confidential information exposed."
                else:
                    description = "Insufficient URL validation."
            elif "flask-cors" in title.lower():
                description = "Insecure CORS configuration."
            elif "flask" in title.lower():
                description = "Jinja variable injection."
            elif "pyyaml" in title.lower():
                description = "Insecure deserialization."

        findings.append({
            "rule_id": cve.rule_id,
            "title": title,
            "severity": cve.severity,
            "description": description,
            "evidence": cve.evidence,
            "line": matched_line,
            "character": matched_char,
            "remediation": remediation
        })

    return findings

def main():
    lang = "es"
    if "--lang" in sys.argv:
        try:
            idx = sys.argv.index("--lang")
            if idx + 1 < len(sys.argv):
                lang = sys.argv[idx + 1]
                sys.argv.pop(idx + 1)
                sys.argv.pop(idx)
        except Exception:
            pass

    if len(sys.argv) < 2:
        print(json.dumps({"error": "Uso: python cli.py <ruta_del_archivo> [--lang es|en]"}), file=sys.stderr)
        sys.exit(1)

    filepath = sys.argv[1]
    
    if filepath in ("-h", "--help"):
        print("OWASP Verificator CLI Scanner")
        print("Uso: python cli.py <ruta_del_archivo> [--lang es|en]")
        sys.exit(0)

    results = scan_file(filepath, lang)
    print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
