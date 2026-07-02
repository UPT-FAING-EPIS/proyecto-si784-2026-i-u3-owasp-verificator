"""CVE Analyzer service for identifying vulnerable dependencies."""
import re

import re

# Import Finding from scanner since it's defined there
class Finding:
    def __init__(self, rule_id, title, severity, description, evidence):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.description = description
        self.evidence = evidence
# Known vulnerable versions mapping (simplified for demo)
KNOWN_CVES = {
    "requests": {
        "<2.20.0": {"cve": "CVE-2018-18074", "severity": "high", "desc": "Vulnerabilidad de inyección en headers"},
        "<2.25.0": {"cve": "CVE-2021-33503", "severity": "medium", "desc": "Limitación de recursos insuficiente"},
    },
    "django": {
        "<2.2.20": {"cve": "CVE-2021-3281", "severity": "high", "desc": "Información confidencial expuesta"},
        "<3.0.13": {"cve": "CVE-2021-32052", "severity": "medium", "desc": "Validación de URLs insuficiente"},
    },
    "flask": {
        "<1.1.0": {"cve": "CVE-2018-1000656", "severity": "medium", "desc": "Inyección de variables Jinja"},
    },
    "flask-cors": {
        "<3.0.9": {"cve": "CVE-2020-25032", "severity": "high", "desc": "Configuración CORS insegura"},
    },
    "cryptography": {
        "<3.2": {"cve": "CVE-2020-36242", "severity": "high", "desc": "Criptografía débil"},
    },
    "pyyaml": {
        "<5.4": {"cve": "CVE-2020-14343", "severity": "high", "desc": "Deserialización insegura"},
    },
    "pickle": {
        "all": {"cve": "CVE-PICKLE", "severity": "high", "desc": "Módulo pickle es inherentemente inseguro"},
    },
}


def detect_imports(content: str) -> dict[str, str]:
    """Detect imported libraries and their versions from code."""
    imports = {}
    
    # Pattern: import module, from module import ...
    import_patterns = [
        r'^import\s+(\w+)',
        r'^from\s+(\w+)',
    ]
    
    for line in content.split('\n'):
        line = line.strip()
        for pattern in import_patterns:
            match = re.match(pattern, line)
            if match:
                module = match.group(1)
                imports[module] = "unknown"
    
    return imports


def parse_requirements(requirements_content: str) -> dict[str, str]:
    """Parse requirements.txt format and extract package versions."""
    packages = {}
    for line in requirements_content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Parse: package==version, package>=version, etc.
        match = re.match(r'([\w-]+)\s*([=><!]+)\s*([\d.]+)', line)
        if match:
            package, op, version = match.groups()
            packages[package] = version
    
    return packages


def check_cve_vulnerabilities(imports: dict[str, str]) -> list[Finding]:
    """Check for known CVEs in detected imports."""
    findings = []
    
    for package, version in imports.items():
        package_lower = package.lower()
        
        if package_lower in KNOWN_CVES:
            cve_info = KNOWN_CVES[package_lower]
            
            for version_range, vuln_info in cve_info.items():
                if version_range == "all":
                    # Always vulnerable
                    findings.append(
                        Finding(
                            rule_id="OWASP-A06-CVE",
                            title=f"Componente vulnerable: {package}",
                            severity="high",
                            description=f"{vuln_info['desc']} ({vuln_info['cve']})",
                            evidence=f"import {package} (versión detectada: {version})",
                        )
                    )
                    break
    
    return findings


def analyze_for_cves(content: str) -> list[Finding]:
    """Main function to analyze code for CVE-related issues."""
    findings = []
    
    # Detect imports from code
    imports = detect_imports(content)
    
    # Check for CVE vulnerabilities
    cve_findings = check_cve_vulnerabilities(imports)
    findings.extend(cve_findings)
    
    # Check for requirements.txt if present in content
    if 'requirements' in content.lower() or '==' in content:
        # Try to parse as requirements.txt
        packages = parse_requirements(content)
        cve_findings = check_cve_vulnerabilities(packages)
        findings.extend(cve_findings)
    
    return findings
