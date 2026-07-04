import json, os

html_path = 'sonar-report.html'
measures = []

if os.path.exists('metrics.json'):
    try:
        with open('metrics.json', 'r') as f:
            data = json.load(f)
        measures = data.get('component', {}).get('measures', [])
    except Exception as e:
        print('Error loading metrics.json:', e)

labels = {
    'bugs': ('🐛 Bugs', '#ef4444'),
    'vulnerabilities': ('🔓 Vulnerabilidades', '#f59e0b'),
    'code_smells': ('🦨 Code Smells', '#a855f7'),
    'coverage': ('📊 Cobertura', '#10b981'),
    'duplicated_lines_density': ('📋 Líneas duplicadas', '#3b82f6'),
    'ncloc': ('📏 Líneas de código', '#6366f1'),
    'security_hotspots': ('🔥 Security Hotspots', '#ec4899')
}

rows = ''
for m in measures:
    metric = m.get('metric')
    val = m.get('value', '0')
    if metric in ('coverage', 'duplicated_lines_density'):
        val += '%'
    label, color = labels.get(metric, (metric, '#94a3b8'))
    rows += f'''
    <tr>
        <td><strong style="color: {color}; font-size: 1.1rem;">{label}</strong></td>
        <td style="font-size: 1.3rem; font-weight: bold;">{val}</td>
    </tr>
    '''

if not measures:
    rows = '<tr><td colspan="2" style="text-align:center; padding: 2rem;">No se pudieron recuperar las métricas de SonarCloud.</td></tr>'

html_content = f'''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte de Calidad SonarCloud</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&family=Plus+Jakarta+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
    <style>
        body {{
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: #020617;
            color: #f8fafc;
            margin: 0; padding: 2rem;
        }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        header {{ margin-bottom: 2.5rem; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 1.5rem; }}
        h1 {{ font-family: 'Outfit', sans-serif; font-size: 2.2rem; margin: 0; background: linear-gradient(to right, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        table {{ width: 100%; border-collapse: collapse; background: rgba(30,41,59,0.3); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; overflow: hidden; }}
        th, td {{ padding: 1.25rem 1.5rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.05); }}
        th {{ background: rgba(30,41,59,0.6); color: #94a3b8; font-weight: 600; font-size: 0.9rem; text-transform: uppercase; }}
        tr:last-child td {{ border-bottom: none; }}
        .back-btn {{ display: inline-block; margin-bottom: 1.5rem; color: #6366f1; text-decoration: none; font-weight: 600; }}
        .back-btn:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <a href="../index.html" class="back-btn">← Volver al Panel</a>
        <header>
            <h1>Calidad de Código y Métricas (SonarCloud)</h1>
            <p style="color: #94a3b8; margin: 0.5rem 0 0 0;">Mejoras sugeridas, cobertura y estado del código procesado en la nube</p>
        </header>
        <table>
            <thead>
                <tr>
                    <th>Métrica de Calidad</th>
                    <th>Valor Actual</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
</body>
</html>
'''

with open(html_path, 'w', encoding='utf-8') as f:
    f.write(html_content)
