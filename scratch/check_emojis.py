import re
import os
import glob

# Standard regex to find emoji characters
# Emojis can be in different unicode blocks. A common regex pattern for emojis is:
emoji_pattern = re.compile(
    "["
    "\U00010000-\U0010ffff"  # Supplemental planes (most emojis)
    "\u2000-\u3300"          # Various symbols and punctuation
    "\ud83c[\ud000-\udfff]"  # Surrogates
    "\ud83d[\ud000-\udfff]"
    "\ud83e[\ud000-\udfff]"
    "]",
    flags=re.UNICODE
)

templates_path = os.path.join(os.path.dirname(__file__), "..", "app", "templates", "*.html")
template_files = glob.glob(templates_path)

print(f"Scanning {len(template_files)} template files for emojis...")
found_any = False

for file_path in template_files:
    filename = os.path.basename(file_path)
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    matches = []
    # Find matches line by line
    lines = content.splitlines()
    for idx, line in enumerate(lines, 1):
        found = emoji_pattern.findall(line)
        if found:
            # Filter out standard quotes, accents, spanish characters (á, é, í, ó, ú, ñ, ¿, ¡)
            spanish_and_punctuation = "áéíóúÁÉÍÓÚñÑ¿¡üÜ"
            real_emojis = []
            for char in found:
                # Emojis are usually not in standard Spanish characters
                if char not in spanish_and_punctuation and ord(char) > 127:
                    # Let's check code points
                    codepoint = ord(char)
                    # Exclude common Spanish letters or symbols
                    if not (192 <= codepoint <= 255): 
                        real_emojis.append(char)
            
            if real_emojis:
                matches.append((idx, line.strip(), real_emojis))
                
    if matches:
        print(f"\n[+] File: {filename}")
        for line_num, line_text, emojis in matches:
            print(f"  Line {line_num}: {' '.join(emojis)} -> {line_text}")
        found_any = True

if not found_any:
    print("No emojis found in templates!")
