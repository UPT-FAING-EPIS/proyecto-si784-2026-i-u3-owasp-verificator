import os

wiki_path = os.path.join(os.path.dirname(__file__), "..", "app", "templates", "owasp_wiki.html")

with open(wiki_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Sidebar navigation emojis
content = content.replace("🔒 A01: Control de Acceso", "A01: Control de Acceso")
content = content.replace("🔑 A02: Fallas Criptográficas", "A02: Fallas Criptográficas")
content = content.replace("💉 A03: Inyección", "A03: Inyección")
content = content.replace("📝 A04: Diseño Inseguro", "A04: Diseño Inseguro")
content = content.replace("⚙️ A05: Configuración Incorrecta", "A05: Configuración Incorrecta")
content = content.replace("📦 A06: Componentes Desactualizados", "A06: Componentes Desactualizados")
content = content.replace("👤 A07: Fallas de Autenticación", "A07: Fallas de Autenticación")
content = content.replace("💾 A08: Integridad de Software", "A08: Integridad de Software")
content = content.replace("📊 A09: Logging y Monitoreo", "A09: Logging y Monitoreo")
content = content.replace("📡 A10: Server-Side Request (SSRF)", "A10: Server-Side Request (SSRF)")

# 2. Main category headings
content = content.replace("🔒 A01: Control de Acceso Roto", "A01: Control de Acceso Roto")
content = content.replace("🔑 A02: Fallas Criptográficas", "A02: Fallas Criptográficas")
content = content.replace("💉 A03: Inyección", "A03: Inyección")
content = content.replace("📝 A04: Diseño Inseguro", "A04: Diseño Inseguro")
content = content.replace("⚙️ A05: Configuración Incorrecta de Seguridad", "A05: Configuración Incorrecta de Seguridad")
content = content.replace("📦 A06: Componentes Vulnerables y Desactualizados", "A06: Componentes Vulnerables y Desactualizados")
content = content.replace("👤 A07: Fallas en Identificación y Autenticación", "A07: Fallas en Identificación y Autenticación")
content = content.replace("💾 A08: Fallas en Integridad de Software y Datos", "A08: Fallas en Integridad de Software y Datos")
content = content.replace("📊 A09: Fallas de Registro y Monitoreo", "A09: Fallas de Registro y Monitoreo")
content = content.replace("📡 A10: Server-Side Request Forgery (SSRF)", "A10: Server-Side Request Forgery (SSRF)")

# 3. Severity indicators in headings
content = content.replace("🔴 RIESGO ALTO", "RIESGO ALTO")
content = content.replace("🟡 RIESGO MEDIO", "RIESGO MEDIO")
content = content.replace("🟢 RIESGO BAJO", "RIESGO BAJO")

# 4. Code comparison headers
content = content.replace("❌ Inseguro", "Inseguro")
content = content.replace("✅ Seguro", "Seguro")

# 5. Resources section heading
content = content.replace("📚 Recursos Adicionales de Referencia", "Recursos Adicionales de Referencia")

with open(wiki_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Redesign of owasp_wiki.html completed successfully!")
