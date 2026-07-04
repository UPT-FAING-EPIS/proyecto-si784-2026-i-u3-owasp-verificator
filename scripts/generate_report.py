import sys, os, json, urllib.request, re

with open('response.json', 'r') as f:
    data = json.load(f)

findings = data.get('findings', [])
ai_text = ''

if findings:
    # Ordenar por severidad y limitar a los 10 más críticos para evitar 413 Payload Too Large
    severity_priority = {'high': 0, 'critical': 0, 'medium': 1, 'low': 2, 'info': 3}
    findings.sort(key=lambda x: severity_priority.get(x.get('severity', '').lower(), 99))
    
    total_findings = len(findings)
    findings_to_analyze = findings[:10]
    
    print(f'Generando remediaciones con IA para los {len(findings_to_analyze)} hallazgos más críticos (de {total_findings} totales)...')
    
    prompt = 'Eres GitHub Copilot Security Expert. Analiza los siguientes hallazgos de seguridad OWASP encontrados en nuestro código y para cada uno de ellos proporciona:\n1. Una explicación clara y concisa de la vulnerabilidad y por qué es un riesgo.\n2. El bloque de código corregido (remediación segura) con comentarios explicativos.\n\nHallazgos a analizar:\n'
    for i, f in enumerate(findings_to_analyze, 1):
        prompt += f'\nHallazgo #{i}:\n- Regla: {f.get("rule_id")}\n- Título: {f.get("title")}\n- Severidad: {f.get("severity")}\n- Descripción: {f.get("description")}\n- Evidencia: {f.get("evidence")}\n'
        
    url = 'https://models.inference.ai.azure.com/chat/completions'
    headers = {
        'Authorization': f'Bearer {os.getenv("GH_PAT")}',
        'Content-Type': 'application/json'
    }
    req_data = {
        'messages': [
            {'role': 'system', 'content': 'Eres un consultor experto de seguridad OWASP y asistente técnico de GitHub Copilot.'},
            {'role': 'user', 'content': prompt}
        ],
        'model': 'gpt-4o-mini',
        'temperature': 0.2
    }
    
    try:
        req = urllib.request.Request(url, data=json.dumps(req_data).encode('utf-8'), headers=headers, method='POST')
        with urllib.request.urlopen(req) as response:
            res = json.loads(response.read().decode('utf-8'))
            ai_text = res['choices'][0]['message']['content']
            
            summary_file_path = os.getenv('GITHUB_STEP_SUMMARY')
            if summary_file_path:
                with open(summary_file_path, 'a', encoding='utf-8') as summary_file:
                    summary_file.write('\n\n## 🤖 Remediación Inteligente (GitHub Copilot Agent)\n\n')
                    if total_findings > 10:
                        summary_file.write(f'*(Se muestran análisis de remediación para los 10 hallazgos más críticos de un total de {total_findings} detectados)*\n\n')
                    summary_file.write(ai_text)
            print('✅ Reporte de remediación por IA generado con éxito.')
    except Exception as e:
        print(f'Error al llamar al API de GitHub Models: {e}')
        ai_text = f'Error al llamar al API de GitHub Models: {e}\n\n*Nota: Asegúrate de que el secreto GH_PAT esté correctamente configurado y tenga permisos para usar GitHub Models.*'
else:
    ai_text = '¡No se detectaron vulnerabilidades! Tu código está seguro. 👍'

# Generar reporte HTML completo para GH Pages
scan_id = data.get('id', 'N/A')
status = data.get('status', 'N/A')
score = data.get('score', 'N/A')

# Convertir markdown básico a HTML
def md_to_html(text):
    # Convertir encabezados
    text = re.sub(r'### (.*?)\n', r'<h3>\g<1></h3>', text)
    text = re.sub(r'## (.*?)\n', r'<h2>\g<1></h2>', text)
    text = re.sub(r'# (.*?)\n', r'<h1>\g<1></h1>', text)
    # Convertir bloques de código
    text = re.sub(r'```python\n(.*?)```', r'<pre><code style="color:#f472b6;">\g<1></code></pre>', text, flags=re.DOTALL)
    text = re.sub(r'```\n(.*?)```', r'<pre><code>\g<1></code></pre>', text, flags=re.DOTALL)
    text = re.sub(r'```(.*?)```', r'<pre><code>\g<1></code></pre>', text, flags=re.DOTALL)
    # Convertir código en línea
    text = re.sub(r'`(.*?)`', r'<code>\g<1></code>', text)
    # Convertir negrita
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\g<1></strong>', text)
    # Convertir listas
    text = re.sub(r'^\s*-\s+(.*?)\n', r'<li>\g<1></li>\n', text, flags=re.MULTILINE)
    # Reemplazar saltos de línea por <br> fuera de etiquetas
    lines = text.split('\n')
    for i, line in enumerate(lines):
        if not line.startswith('<h') and not line.startswith('<li') and not line.startswith('<pre') and not line.endswith('pre>'):
            lines[i] = line + '<br>'
    return '\n'.join(lines)

ai_html = md_to_html(ai_text)

rows = ''
for idx, f in enumerate(findings, 1):
    rule_id = f.get('rule_id', 'N/A')
    title = f.get('title', 'N/A')
    sev = f.get('severity', 'info').lower()
    desc = f.get('description', 'N/A')
    ev = f.get('evidence', 'N/A')
    
    badge_cls = 'badge-danger' if sev in ('high', 'critical') else 'badge-warn' if sev == 'medium' else 'badge-info'
    
    rows += f'''
    <tr>
        <td>{idx}</td>
        <td><span class="badge {badge_cls}">{sev.upper()}</span></td>
        <td><code>{rule_id}</code></td>
        <td><strong>{title}</strong><br><span style="color:#94a3b8; font-size:0.85rem;">{desc}</span></td>
        <td><pre style="background:rgba(255,255,255,0.05); padding:0.5rem; border-radius:4px; font-size:0.8rem; overflow-x:auto;"><code>{ev}</code></pre></td>
    </tr>
    '''
    
if not findings:
    rows = '<tr><td colspan="5" style="text-align:center; padding:3rem; color:#10b981; font-weight:bold;">🎉 ¡No se encontraron vulnerabilidades en el análisis! Tu código cumple con las reglas OWASP.</td></tr>'

html_content = f'''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Auditoría de Seguridad con IA (Skill IA)</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Plus Jakarta Sans', sans-serif; background-color: #020617; color: #f8fafc; padding: 2rem; margin: 0; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ margin-bottom: 2rem; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 1.5rem; }}
        h1 {{ font-family: 'Outfit', sans-serif; font-size: 2.2rem; margin: 0; background: linear-gradient(to right, #6366f1, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .stats {{ display: flex; gap: 1.5rem; margin-bottom: 2.5rem; }}
        .stat-card {{ background: rgba(30,41,59,0.5); border: 1px solid rgba(255,255,255,0.05); padding: 1.5rem; border-radius: 12px; flex: 1; text-align: center; }}
        .stat-card h3 {{ margin: 0 0 0.5rem 0; color: #94a3b8; font-size: 0.9rem; font-weight: 500; text-transform: uppercase; }}
        .stat-val {{ font-size: 1.8rem; font-weight: 700; }}
        table {{ width: 100%; border-collapse: collapse; background: rgba(30,41,59,0.3); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; overflow: hidden; margin-bottom: 3rem; }}
        th, td {{ padding: 1rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.05); vertical-align: top; }}
        th {{ background: rgba(30,41,59,0.6); color: #94a3b8; font-weight: 600; font-size: 0.9rem; }}
        tr:last-child td {{ border-bottom: none; }}
        code {{ background: rgba(255,255,255,0.05); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; color: #f472b6; }}
        pre {{ background: #0f172a; padding: 1rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.05); overflow-x: auto; }}
        .badge {{ padding: 0.25rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; display: inline-block; }}
        .badge-danger {{ background: rgba(239,68,68,0.2); color: #ef4444; border: 1px solid #ef4444; }}
        .badge-warn {{ background: rgba(245,158,11,0.2); color: #f59e0b; border: 1px solid #f59e0b; }}
        .badge-info {{ background: rgba(59,130,246,0.2); color: #3b82f6; border: 1px solid #3b82f6; }}
        .ai-section {{ background: rgba(99,102,241,0.05); border: 1px solid rgba(99,102,241,0.15); border-radius: 16px; padding: 2rem; margin-top: 2rem; }}
        .ai-section h2 {{ font-family: 'Outfit', sans-serif; color: #a5b4fc; margin-top: 0; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.5rem; }}
        .back-btn {{ display: inline-block; margin-bottom: 1.5rem; color: #6366f1; text-decoration: none; font-weight: 600; }}
        .back-btn:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <a href="../index.html" class="back-btn">← Volver al Panel</a>
        <header>
            <h1>Auditoría de Seguridad con Inteligencia Artificial</h1>
            <p style="color: #94a3b8; margin: 0.5rem 0 0 0;">Hallazgos detectados por la API y propuestas de remediación generadas por Copilot Security</p>
        </header>
        <div class="stats">
            <div class="stat-card"><h3>Puntuación (Score)</h3><div class="stat-val" style="color:#10b981;">{score}/100</div></div>
            <div class="stat-card"><h3>ID Escaneo</h3><div class="stat-val" style="font-size:1.2rem; line-height:2.2rem;">{scan_id}</div></div>
            <div class="stat-card"><h3>Hallazgos</h3><div class="stat-val" style="color:#ef4444;">{len(findings)}</div></div>
        </div>
        
        <h2>Detalle de Hallazgos OWASP</h2>
        <table>
            <thead>
                <tr>
                    <th style="width:5%;">#</th>
                    <th style="width:10%;">Severidad</th>
                    <th style="width:15%;">Regla ID</th>
                    <th style="width:35%;">Vulnerabilidad</th>
                    <th style="width:35%;">Evidencia</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        
        <div class="ai-section">
            <h2>🤖 Propuestas de Remediación con IA</h2>
            <div>{ai_html}</div>
        </div>
    </div>
</body>
</html>
'''

with open('skill-ia-report.html', 'w', encoding='utf-8') as f_out:
    f_out.write(html_content)
print('Report HTML generated successfully.')
