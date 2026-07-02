const fs = require('fs');
const path = require('path');

const srcAppServices = path.join(__dirname, '..', 'app', 'services');
const destAppServices = path.join(__dirname, 'app', 'services');
const srcCli = path.join(__dirname, '..', 'cli.py');
const destCli = path.join(__dirname, 'cli.py');

// Asegurar que exista la carpeta de destino
fs.mkdirSync(destAppServices, { recursive: true });

// Copiar archivos de servicios necesarios
const filesToCopy = ['scanner.py', 'cve_analyzer.py'];
filesToCopy.forEach(file => {
    const src = path.join(srcAppServices, file);
    const dest = path.join(destAppServices, file);
    if (fs.existsSync(src)) {
        fs.copyFileSync(src, dest);
        console.log(`✓ Sincronizado: ${file}`);
    } else {
        console.warn(`⚠️ Advertencia: No se encontró el archivo de origen ${src}`);
    }
});

// Copiar cli.py
if (fs.existsSync(srcCli)) {
    fs.copyFileSync(srcCli, destCli);
    console.log(`✓ Sincronizado: cli.py`);
} else {
    console.warn(`⚠️ Advertencia: No se encontró el archivo de origen ${srcCli}`);
}
