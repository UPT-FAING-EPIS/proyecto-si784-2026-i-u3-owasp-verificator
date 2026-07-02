import urllib.request
import re

url = "http://38.250.116.71:8000/api-tutorial"
try:
    with urllib.request.urlopen(url) as response:
        html = response.read().decode('utf-8')
    
    # Search for all occurrences of hrefs near "Abrir en VS Code"
    # we can search for the block containing class="ig-btn-row"
    matches = re.findall(r'<a[^>]+href="([^"]+)"[^>]*>[^<]*?(?:Abrir en VS Code|Ver en Marketplace|Instalar por ID|Abrir en Cursor|Open VSX Registry)', html)
    print("Found links:")
    for m in matches:
        print(m)
        
    print("\nFull section html snippet:")
    start_idx = html.find('id="btn-open-vscode"')
    if start_idx != -1:
        print(html[start_idx-200:start_idx+600])
    else:
        print("btn-open-vscode not found in html!")
except Exception as e:
    print("Error:", e)
