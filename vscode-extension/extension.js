const vscode = require('vscode');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

// Umbral máximo de tamaño de archivo para evitar problemas de rendimiento (2 MB)
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;

let statusBarItem;
let extensionPath;
let resolvedPythonCommand = null;
let sidebarProvider;

const activeAiScans = new Map();
const documentFindings = new Map();

/**
 * Verifica si un comando de Python funciona ejecutando "-V"
 * @param {string} cmd 
 * @returns {Promise<boolean>}
 */
function checkPythonCommand(cmd) {
    return new Promise((resolve) => {
        exec(`"${cmd}" -V`, (error) => {
            resolve(!error);
        });
    });
}

/**
 * Busca de manera ordenada qué comando de Python está disponible
 * @returns {Promise<string|null>}
 */
function resolvePythonPath() {
    return new Promise((resolve) => {
        const config = vscode.workspace.getConfiguration('owaspVerificator');
        const customPath = config.get('pythonPath');
        
        if (customPath && customPath !== 'python') {
            checkPythonCommand(customPath).then(ok => {
                if (ok) return resolve(customPath);
                tryCandidates();
            });
        } else {
            tryCandidates();
        }

        function tryCandidates() {
            const candidates = ['python', 'python3', 'py'];
            let index = 0;

            function next() {
                if (index >= candidates.length) {
                    return resolve(null);
                }
                const candidate = candidates[index++];
                checkPythonCommand(candidate).then(ok => {
                    if (ok) return resolve(candidate);
                    next();
                });
            }
            next();
        }
    });
}

/**
 * Instala silenciosamente la librería requests si no está disponible
 * @param {string} pythonCmd 
 */
function checkAndInstallDependencies(pythonCmd) {
    if (!pythonCmd) return;
    exec(`"${pythonCmd}" -c "import requests"`, (err) => {
        if (err) {
            console.log("OWASP Verificator: 'requests' library missing. Attempting silent install...");
            exec(`"${pythonCmd}" -m pip install requests`, (installErr) => {
                if (installErr) {
                    console.error(`OWASP Verificator: Failed to install 'requests' automatically: ${installErr.message}`);
                } else {
                    console.log("OWASP Verificator: 'requests' installed successfully.");
                }
            });
        }
    });
}

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    extensionPath = context.extensionPath;
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('owasp-verificator');
    context.subscriptions.push(diagnosticCollection);

    // Inicializar indicador en la barra de estado
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    context.subscriptions.push(statusBarItem);

    // Registrar proveedor de la barra lateral (Sidebar)
    sidebarProvider = new OwaspSidebarProvider(context);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            'owasp-verificator-sidebar-view',
            sidebarProvider
        )
    );

    // Escuchar cambios de configuración
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration('owaspVerificator.language')) {
                const config = vscode.workspace.getConfiguration('owaspVerificator');
                let lang = config.get('language') || 'es';
                if (lang === 'auto') {
                    lang = vscode.env.language.startsWith('es') ? 'es' : 'en';
                }
                if (sidebarProvider) {
                    sidebarProvider.updateLanguage(lang);
                }
                if (dashboardPanel) {
                    dashboardPanel.webview.postMessage({
                        command: 'updateSettings',
                        enableAIScan: false
                    });
                }
            }
        })
    );

    // Registrar comando para escaneo manual
    let scanCommand = vscode.commands.registerCommand('owasp-verificator.scanFile', () => {
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor) {
            runScan(activeEditor.document, diagnosticCollection, true, context);
        } else {
            vscode.window.showInformationMessage('No hay ningún archivo activo para analizar.');
        }
    });
    context.subscriptions.push(scanCommand);

    // Registrar comando para escaneo de todo el workspace
    let scanWorkspaceCommand = vscode.commands.registerCommand('owasp-verificator.scanWorkspace', () => {
        scanWorkspaceAndShowDashboard(context);
    });
    context.subscriptions.push(scanWorkspaceCommand);

    // Registrar proveedor de acciones de código (Quick Fixes)
    let codeActionProvider = vscode.languages.registerCodeActionsProvider(
        { scheme: 'file' },
        new OwaspCodeActionProvider(),
        {
            providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
        }
    );
    context.subscriptions.push(codeActionProvider);

    // Comando para preguntar a la IA desactivado

    // Eventos de activación
    vscode.workspace.onDidOpenTextDocument(doc => runScan(doc, diagnosticCollection), null, context.subscriptions);
    vscode.workspace.onDidSaveTextDocument(doc => runScan(doc, diagnosticCollection), null, context.subscriptions);
    
    // Escaneo al cambiar de archivo activo
    vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor) {
            runScan(editor.document, diagnosticCollection);
        } else {
            statusBarItem.hide();
        }
    }, null, context.subscriptions);

    // Limpiar diagnósticos al cerrar archivos
    vscode.workspace.onDidCloseTextDocument(doc => {
        diagnosticCollection.delete(doc.uri);
    }, null, context.subscriptions);

    // Resolver comando de Python y validar dependencias en segundo plano
    resolvePythonPath().then(cmd => {
        resolvedPythonCommand = cmd;
        if (cmd) {
            console.log(`OWASP Verificator: resolved Python command as "${cmd}"`);
            checkAndInstallDependencies(cmd);
            
            // Ejecutar escaneo inicial una vez detectado Python
            if (vscode.window.activeTextEditor) {
                runScan(vscode.window.activeTextEditor.document, diagnosticCollection);
            }
        } else {
            vscode.window.showWarningMessage('OWASP Verificator: No se detectó ninguna instalación de Python 3.');
        }
    });
}

/**
 * Ejecuta el script cli.py y publica los hallazgos en VS Code
 * @param {vscode.TextDocument} document 
 * @param {vscode.DiagnosticCollection} collection 
 * @param {boolean} showDashboard
 * @param {vscode.ExtensionContext} context
 */
function runScan(document, collection, showDashboard = false, context = null) {
    // Solo escanear archivos guardados en disco (scheme 'file')
    if (document.uri.scheme !== 'file') {
        statusBarItem.hide();
        return;
    }

    // Comprobación de seguridad por tamaño de archivo para evitar retrasos
    try {
        const stats = fs.statSync(document.uri.fsPath);
        if (stats.size > MAX_FILE_SIZE_BYTES) {
            statusBarItem.hide();
            return;
        }
    } catch (err) {
        statusBarItem.hide();
        return;
    }

    const cliPath = path.join(extensionPath, 'cli.py');

    // Verificar si cli.py existe en la extensión
    if (!fs.existsSync(cliPath)) {
        console.error(`Error: No se encuentra cli.py en la ruta: ${cliPath}`);
        statusBarItem.hide();
        return;
    }

    // Determinar directorio de trabajo
    let cwd = path.dirname(document.uri.fsPath);
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (workspaceFolder) {
        cwd = workspaceFolder.uri.fsPath;
    }

    // Leer ruta de Python configurada por el usuario o resolver dinámicamente
    const config = vscode.workspace.getConfiguration('owaspVerificator');
    const userConfigPath = config.get('pythonPath');
    const pythonPath = (userConfigPath && userConfigPath !== 'python') ? userConfigPath : (resolvedPythonCommand || 'python');

    // Mostrar estado de escaneo
    statusBarItem.text = '$(sync~spin) OWASP: Analizando...';
    statusBarItem.tooltip = 'Ejecutando verificador de cumplimiento OWASP';
    statusBarItem.color = undefined;
    statusBarItem.show();

    let lang = config.get('language') || 'es';
    if (lang === 'auto') {
        lang = vscode.env.language.startsWith('es') ? 'es' : 'en';
    }

    const docUriStr = document.uri.toString();

    // Inicializar mapa de hallazgos
    let docData = documentFindings.get(docUriStr);
    if (!docData) {
        docData = { cli: [], ai: [], isAiScanning: false };
        documentFindings.set(docUriStr, docData);
    }

    // Cancelar cualquier escaneo de IA activo anterior para este archivo
    if (activeAiScans.has(docUriStr)) {
        activeAiScans.get(docUriStr).cancel();
        activeAiScans.delete(docUriStr);
    }

    const command = `"${pythonPath}" "${cliPath}" "${document.uri.fsPath}" --lang ${lang}`;

    exec(command, { cwd: cwd }, async (error, stdout, stderr) => {
        if (error) {
            console.error(`OWASP Verificator CLI Error: ${stderr || error.message}`);
            statusBarItem.text = '$(error) OWASP: Error de análisis';
            statusBarItem.tooltip = `Error al ejecutar cli.py:\n${stderr || error.message}`;
            statusBarItem.color = new vscode.ThemeColor('statusBarItem.errorForeground');
            return;
        }

        try {
            const findings = JSON.parse(stdout);
            
            if (findings.error) {
                console.error(`OWASP Verificator scan error in JSON: ${findings.error}`);
                statusBarItem.text = '$(error) OWASP: Error en JSON';
                statusBarItem.tooltip = findings.error;
                statusBarItem.color = new vscode.ThemeColor('statusBarItem.errorForeground');
                return;
            }

            // Guardar hallazgos de reglas
            docData.cli = findings;
            docData.isAiScanning = false;

            // Actualizar interfaz con escaneo rápido
            refreshDiagnosticsAndUI(document, collection, lang, showDashboard, context);

            // Escaneo asíncrono con IA si está habilitado
            const enableAI = false;
            if (enableAI && vscode.lm) {
                docData.isAiScanning = true;
                refreshDiagnosticsAndUI(document, collection, lang, showDashboard, context);

                const cts = new vscode.CancellationTokenSource();
                activeAiScans.set(docUriStr, cts);

                try {
                    const aiFindings = await scanFileWithAI(document, lang, cts.token);
                    if (!cts.token.isCancellationRequested) {
                        docData.ai = aiFindings;
                    }
                } catch (aiErr) {
                    console.error("OWASP Verificator background AI scan error:", aiErr);
                } finally {
                    if (!cts.token.isCancellationRequested) {
                        docData.isAiScanning = false;
                        activeAiScans.delete(docUriStr);
                        refreshDiagnosticsAndUI(document, collection, lang, showDashboard, context);
                    }
                }
            } else {
                // Limpiar hallazgos antiguos de IA si se desactivó
                docData.ai = [];
                refreshDiagnosticsAndUI(document, collection, lang, showDashboard, context);
            }

        } catch (e) {
            console.error(`OWASP Verificator parse failed: ${e.message}. Output: ${stdout}`);
            statusBarItem.text = '$(error) OWASP: Error de parseo';
            statusBarItem.tooltip = `No se pudo interpretar el resultado JSON del escáner.`;
            statusBarItem.color = new vscode.ThemeColor('statusBarItem.errorForeground');
        }
    });
}

function refreshDiagnosticsAndUI(document, collection, lang, showDashboard, context) {
    const docUriStr = document.uri.toString();
    const docData = documentFindings.get(docUriStr);
    if (!docData) return;

    const merged = mergeFindings(docData.cli, docData.ai);
    const config = vscode.workspace.getConfiguration('owaspVerificator');
    const showDiagnostics = config.get('showDiagnostics') !== false;

    if (showDiagnostics) {
        updateDiagnostics(document, merged, collection, lang);
    } else {
        collection.delete(document.uri);
    }

    if (docData.isAiScanning) {
        const isEs = lang.startsWith('es');
        statusBarItem.text = `$(sync~spin) OWASP: ${merged.length} (${isEs ? 'auditoría IA...' : 'AI auditing...'})`;
        statusBarItem.tooltip = isEs ? 'El escaneo rápido finalizó. Ejecutando auditoría de IA en segundo plano...' : 'Fast scan finished. Running background AI audit...';
        statusBarItem.color = undefined;
        statusBarItem.show();
    } else {
        updateStatusBar(merged, lang);
    }

    if (showDashboard && context) {
        const scanResults = [{
            uri: document.uri,
            fsPath: document.uri.fsPath,
            fileName: path.basename(document.uri.fsPath),
            findings: merged
        }];
        showDashboardPanel(context, scanResults, lang, 1);
    }
}

function mergeFindings(cliFindings, aiFindings) {
    const merged = [...cliFindings];
    
    aiFindings.forEach(aiF => {
        // De-duplicar usando la línea, el rule_id y la evidencia (con limpieza básica)
        const aiEv = (aiF.evidence || '').trim();
        const isDuplicate = cliFindings.some(cliF => 
            cliF.line === aiF.line && 
            cliF.rule_id === aiF.rule_id &&
            (cliF.evidence || '').trim() === aiEv
        );
        if (!isDuplicate) {
            merged.push({
                rule_id: aiF.rule_id || 'OWASP-A00',
                title: aiF.title || 'Security Finding (AI)',
                severity: aiF.severity || 'medium',
                description: aiF.description || '',
                evidence: aiF.evidence || '',
                line: aiF.line || 1,
                character: aiF.character || 0,
                remediation: aiF.remediation || '',
                isAi: true
            });
        }
    });

    merged.sort((a, b) => a.line - b.line);
    return merged;
}

function parseAIResponse(text) {
    text = text.trim();
    const firstBracket = text.indexOf('[');
    const lastBracket = text.lastIndexOf(']');
    if (firstBracket !== -1 && lastBracket !== -1 && lastBracket > firstBracket) {
        text = text.substring(firstBracket, lastBracket + 1);
    }
    try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) {
            return parsed;
        }
    } catch (err) {
        console.error("OWASP Verificator: Failed to parse AI response JSON: " + err.message + "\nContent: " + text);
    }
    return [];
}

async function scanFileWithAI(document, lang, token) {
    if (!vscode.lm) {
        console.log("OWASP Verificator: vscode.lm API is not available.");
        return [];
    }

    try {
        let models = [];
        try {
            models = await vscode.lm.selectChatModels({ family: 'gpt-4o' });
        } catch (e) {
            try {
                models = await vscode.lm.selectChatModels();
            } catch (err) {
                console.log("OWASP Verificator: selectChatModels failed: " + err.message);
                return [];
            }
        }

        if (!models || models.length === 0) {
            console.log("OWASP Verificator: No language models available.");
            return [];
        }

        const model = models[0];
        const isEs = lang.startsWith('es');
        
        const systemPrompt = `You are an OWASP Top 10 secure code auditor. Analyze the provided source code and detect potential vulnerabilities.
Return ONLY a valid JSON array of findings. If no vulnerabilities are found, return an empty array [].
Each vulnerability object in the array MUST have this exact schema:
- rule_id: (string, e.g. "OWASP-A01" to "OWASP-A10")
- title: (string, short title in ${isEs ? 'Spanish' : 'English'})
- severity: (string, one of: "high", "medium", "low")
- description: (string, detailed explanation in ${isEs ? 'Spanish' : 'English'})
- evidence: (string, the exact snippet of code that is vulnerable)
- line: (number, 1-based index of the line in the code)
- character: (number, 0-based start character position of the evidence on that line)
- remediation: (string, specific steps to fix in ${isEs ? 'Spanish' : 'English'})

CRITICAL:
1. Return ONLY the raw JSON array. Do not include markdown code block formatting (like \`\`\`json) or any conversational text.
2. Ensure the "line" number matches the actual 1-based line index in the provided code.
3. Be precise and avoid false positives. If the language is not natively targeted by the local regex engine (like Solidity, Dart, Kotlin, Swift, etc.), run a full security audit on it using that language's specific security rules.`;

        const userPrompt = `Here is the code of the file "${path.basename(document.uri.fsPath)}" (language: ${document.languageId}):

${document.getText()}

Analyze it and return the JSON array of findings:`;

        let messages = [];
        if (vscode.LanguageModelChatMessage.System) {
            messages.push(vscode.LanguageModelChatMessage.System(systemPrompt));
            messages.push(vscode.LanguageModelChatMessage.User(userPrompt));
        } else {
            messages.push(vscode.LanguageModelChatMessage.User(`${systemPrompt}\n\n${userPrompt}`));
        }

        const response = await model.sendRequest(messages, {}, token);
        let responseText = '';
        for await (const fragment of response.text) {
            if (token.isCancellationRequested) {
                return [];
            }
            responseText += fragment;
        }

        return parseAIResponse(responseText);
    } catch (err) {
        console.error("OWASP Verificator: AI scan error:", err);
        return [];
    }
}

/**
 * @param {vscode.TextDocument} document 
 * @param {Array} findings 
 * @param {vscode.DiagnosticCollection} collection 
 */
function updateDiagnostics(document, findings, collection, lang) {
    collection.delete(document.uri);

    const diagnostics = [];
    const isEs = lang.startsWith('es');
    const labelDetail = isEs ? 'Detalle' : 'Detail';
    const labelEvidence = isEs ? 'Evidencia' : 'Evidence';
    const labelRemediation = isEs ? 'Recomendación de Remediación' : 'Remediation Recommendation';

    findings.forEach(finding => {
        // VS Code usa base 0 para líneas, el cli devuelve base 1
        const line = Math.max(0, finding.line - 1);
        const character = Math.max(0, finding.character);

        let lineText = '';
        try {
            lineText = document.lineAt(line).text;
        } catch (e) {}

        const startPos = new vscode.Position(line, character);
        // Resaltar la longitud de la evidencia o un carácter si no hay
        const matchLength = finding.evidence ? finding.evidence.length : 1;
        const endCharacter = Math.min(lineText.length, character + matchLength);
        const endPos = new vscode.Position(line, endCharacter);

        const range = new vscode.Range(startPos, endPos);

        // Mapear severidades
        let severity = vscode.DiagnosticSeverity.Information;
        if (finding.severity === 'high') {
            severity = vscode.DiagnosticSeverity.Error;
        } else if (finding.severity === 'medium') {
            severity = vscode.DiagnosticSeverity.Warning;
        }

        // Formato estructurado del tooltip del problema
        const message = 
`[${finding.rule_id}] ${finding.title}
--------------------------------------------------
${labelDetail}:
${finding.description}

${labelEvidence}:
"${finding.evidence}"

${labelRemediation}:
${finding.remediation}`;

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.code = finding.rule_id;
        diagnostic.source = 'OWASP Verificator';

        diagnostics.push(diagnostic);
    });

    collection.set(document.uri, diagnostics);
}

/**
 * @param {Array} findings 
 */
function updateStatusBar(findings, lang) {
    const isEs = lang.startsWith('es');
    const errors = findings.filter(f => f.severity === 'high').length;
    const warnings = findings.filter(f => f.severity === 'medium').length;
    const info = findings.filter(f => f.severity === 'low').length;

    if (errors > 0) {
        statusBarItem.text = isEs ? `$(bug) OWASP: ${errors} error${errors > 1 ? 'es' : ''}` : `$(bug) OWASP: ${errors} error${errors > 1 ? 's' : ''}`;
        statusBarItem.tooltip = isEs ? `Se encontraron ${errors} problemas críticos de seguridad OWASP en este archivo.` : `Found ${errors} critical OWASP security problems in this file.`;
        statusBarItem.color = new vscode.ThemeColor('statusBarItem.errorForeground');
    } else if (warnings > 0) {
        statusBarItem.text = isEs ? `$(warning) OWASP: ${warnings} advertencia${warnings > 1 ? 's' : ''}` : `$(warning) OWASP: ${warnings} warning${warnings > 1 ? 's' : ''}`;
        statusBarItem.tooltip = isEs ? `Se encontraron ${warnings} advertencias de seguridad OWASP en este archivo.` : `Found ${warnings} OWASP security warnings in this file.`;
        statusBarItem.color = new vscode.ThemeColor('statusBarItem.warningForeground');
    } else if (info > 0) {
        statusBarItem.text = isEs ? `$(info) OWASP: ${info} recomendación${info > 1 ? 'es' : ''}` : `$(info) OWASP: ${info} info${info > 1 ? 's' : ''}`;
        statusBarItem.tooltip = isEs ? `Se encontraron ${info} recomendaciones menores en este archivo.` : `Found ${info} minor recommendations in this file.`;
        statusBarItem.color = undefined;
    } else {
        statusBarItem.text = isEs ? `$(check) OWASP: Seguro` : `$(check) OWASP: Secure`;
        statusBarItem.tooltip = isEs ? 'Cumplimiento OWASP verificado. No se detectaron problemas.' : 'OWASP compliance verified. No problems detected.';
        statusBarItem.color = undefined;
    }
}

// --- ACCIONES DE CÓDIGO (QUICK FIXES) ---

class OwaspCodeActionProvider {
    provideCodeActions(document, range, context, token) {
        const actions = [];
        const config = vscode.workspace.getConfiguration('owaspVerificator');
        let lang = config.get('language') || 'es';
        if (lang === 'auto') {
            lang = vscode.env.language.startsWith('es') ? 'es' : 'en';
        }
        const isEs = lang === 'es';

        for (const diagnostic of context.diagnostics) {
            // Sugerencia para preguntar a Copilot en cualquier hallazgo OWASP
            if (diagnostic.code && diagnostic.code.startsWith('OWASP-')) {
                const ruleId = diagnostic.code;
                const msg = diagnostic.message;
                const titleMatch = msg.match(/^\[.*?\]\s*(.*)$/m);
                const title = titleMatch ? titleMatch[1] : (isEs ? "Vulnerabilidad OWASP" : "OWASP Vulnerability");
                
                const remLabel = isEs ? 'Recomendación de Remediación' : 'Remediation Recommendation';
                const remIdx = msg.indexOf(remLabel);
                const remediation = remIdx !== -1 ? msg.substring(remIdx + remLabel.length + 2).trim() : "";
                
                const evLabel = isEs ? 'Evidencia' : 'Evidence';
                const evIdx = msg.indexOf(evLabel);
                const detIdx = msg.indexOf(isEs ? 'Recomendación' : 'Remediation');
                let evidence = "";
                if (evIdx !== -1 && detIdx !== -1) {
                    evidence = msg.substring(evIdx + evLabel.length + 2, detIdx).trim();
                    if (evidence.startsWith('"') && evidence.endsWith('"')) {
                        evidence = evidence.substring(1, evidence.length - 1);
                    }
                } else {
                    evidence = document.getText(diagnostic.range) || "";
                }

                // Preguntar a IA desactivado
            }

            if (diagnostic.code === 'OWASP-A02' && document.languageId === 'python') {
                const lineText = document.lineAt(diagnostic.range.start.line).text;
                const match = lineText.match(/([a-zA-Z0-9_-]+)\s*=\s*(["'])(.*?)\2/);
                if (match) {
                    const varName = match[1];
                    const quote = match[2];
                    const secretValue = match[3];
                    const envVarName = varName.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
                    
                    const action = new vscode.CodeAction(
                        isEs ? `Reemplazar con os.getenv()` : `Replace with os.getenv()`,
                        vscode.CodeActionKind.QuickFix
                    );
                    action.diagnostics = [diagnostic];
                    action.isPreferred = true;
                    
                    const edit = new vscode.WorkspaceEdit();
                    const startIdx = lineText.indexOf(match[0]);
                    const endIdx = startIdx + match[0].length;
                    const replaceRange = new vscode.Range(
                        new vscode.Position(diagnostic.range.start.line, startIdx),
                        new vscode.Position(diagnostic.range.start.line, endIdx)
                    );
                    
                    const replacement = `${varName} = os.getenv('${envVarName}', ${quote}${secretValue}${quote})`;
                    edit.replace(document.uri, replaceRange, replacement);
                    action.edit = edit;
                    actions.push(action);
                }
            } else if (diagnostic.code === 'OWASP-A09' && document.languageId === 'python') {
                const lineNum = diagnostic.range.start.line;
                const lineText = document.lineAt(lineNum).text;
                
                let targetLine = -1;
                let targetText = "";
                
                if (lineText.includes('pass')) {
                    targetLine = lineNum;
                    targetText = lineText;
                } else if (lineNum + 1 < document.lineCount) {
                    const nextLineText = document.lineAt(lineNum + 1).text;
                    if (nextLineText.includes('pass')) {
                        targetLine = lineNum + 1;
                        targetText = nextLineText;
                    }
                }
                
                if (targetLine !== -1) {
                    const action = new vscode.CodeAction(
                        isEs ? `Registrar excepción con logging.exception` : `Log exception using logging.exception`,
                        vscode.CodeActionKind.QuickFix
                    );
                    action.diagnostics = [diagnostic];
                    action.isPreferred = true;
                    
                    const edit = new vscode.WorkspaceEdit();
                    const passIdx = targetText.indexOf('pass');
                    const replaceRange = new vscode.Range(
                        new vscode.Position(targetLine, passIdx),
                        new vscode.Position(targetLine, passIdx + 4)
                    );
                    
                    const logMsg = isEs ? 'logging.exception("Detalle del error")' : 'logging.exception("Error details")';
                    edit.replace(document.uri, replaceRange, logMsg);
                    action.edit = edit;
                    actions.push(action);
                }
            }
        }
        return actions;
    }
}

class OwaspSidebarProvider {
    constructor(context) {
        this.context = context;
        this._view = undefined;
    }

    resolveWebviewView(webviewView, context, token) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [vscode.Uri.file(this.context.extensionPath)]
        };

        const config = vscode.workspace.getConfiguration('owaspVerificator');
        let lang = config.get('language') || 'es';
        if (lang === 'auto') {
            lang = vscode.env.language.startsWith('es') ? 'es' : 'en';
        }

        webviewView.webview.html = this.getHtmlContent(lang);

        webviewView.webview.onDidReceiveMessage(async (message) => {
            if (message.command === 'scanFile') {
                vscode.commands.executeCommand('owasp-verificator.scanFile');
            } else if (message.command === 'scanWorkspace') {
                vscode.commands.executeCommand('owasp-verificator.scanWorkspace');
            } else if (message.command === 'openDashboard') {
                vscode.commands.executeCommand('owasp-verificator.scanWorkspace');
            }
        });
    }

    updateLanguage(lang) {
        if (this._view) {
            this._view.webview.html = this.getHtmlContent(lang);
        }
    }

    getHtmlContent(lang) {
        const isEs = lang.startsWith('es');
        const config = vscode.workspace.getConfiguration('owaspVerificator');
        const isAIEnabled = false;

        const t = {
            es: {
                title: "Controles OWASP",
                scanFile: "Analizar Archivo Actual",
                scanWorkspace: "Escanear todo el Workspace",
                openDashboard: "Abrir Dashboard completo",
                statusTitle: "Estado del Escáner",
                statusIdle: "Esperando comando...",
                donation: "Apoya el proyecto:"
            },
            en: {
                title: "OWASP Controls",
                scanFile: "Analyze Current File",
                scanWorkspace: "Scan entire Workspace",
                openDashboard: "Open Full Dashboard",
                statusTitle: "Scanner Status",
                statusIdle: "Waiting for command...",
                donation: "Support project:"
            }
        }[isEs ? 'es' : 'en'];

        return `<!DOCTYPE html>
<html lang="${lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif);
            color: var(--vscode-foreground);
            padding: 12px;
            margin: 0;
            font-size: 13px;
            background-color: var(--vscode-sidebar-background);
        }
        .header {
            font-weight: 700;
            font-size: 15px;
            margin-bottom: 16px;
            letter-spacing: -0.2px;
            color: var(--vscode-editor-foreground, #e2e8f0);
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            padding-bottom: 8px;
        }
        .btn {
            background-color: var(--vscode-button-background, #3b82f6);
            color: var(--vscode-button-foreground, #ffffff);
            border: none;
            padding: 8px 12px;
            border-radius: 6px;
            cursor: pointer;
            width: 100%;
            font-weight: 600;
            margin-bottom: 10px;
            font-size: 12px;
            box-sizing: border-box;
            transition: background-color 0.2s;
            display: inline-flex;
            justify-content: center;
            align-items: center;
            gap: 6px;
        }
        .btn:hover {
            background-color: var(--vscode-button-hoverBackground, #2563eb);
        }
        .btn-secondary {
            background-color: rgba(255, 255, 255, 0.06);
            color: var(--vscode-foreground);
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin-top: 10px;
        }
        .btn-secondary:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        .toggle-container {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 12px;
            margin: 16px 0;
        }
        .toggle-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
        }
        .toggle-label {
            font-weight: 600;
            font-size: 12px;
        }
        .toggle-desc {
            font-size: 11px;
            color: #94a3b8;
            margin-top: 4px;
            line-height: 1.3;
        }
        /* Switch UI */
        .switch {
            position: relative;
            display: inline-block;
            width: 34px;
            height: 20px;
            flex-shrink: 0;
        }
        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(255, 255, 255, 0.12);
            transition: .3s;
            border-radius: 20px;
        }
        .slider:before {
            position: absolute;
            content: "";
            height: 14px;
            width: 14px;
            left: 3px;
            bottom: 3px;
            background-color: #ffffff;
            transition: .3s;
            border-radius: 50%;
        }
        input:checked + .slider {
            background-color: var(--vscode-button-background, #3b82f6);
        }
        input:checked + .slider:before {
            transform: translateX(14px);
        }
        .sponsorship {
            margin-top: 24px;
            border-top: 1px solid rgba(255, 255, 255, 0.08);
            padding-top: 12px;
            text-align: center;
            font-size: 11px;
            color: #94a3b8;
        }
        .paypal-link {
            display: inline-flex;
            align-items: center;
            background: #ffd140;
            color: #00457c;
            padding: 4px 10px;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 700;
            margin-top: 6px;
            font-size: 10px;
        }
    </style>
</head>
<body>
    <div class="header">${t.title}</div>
    
    <button class="btn" onclick="sendMessage('scanFile')">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
        </svg>
        ${t.scanFile}
    </button>
    
    <button class="btn" onclick="sendMessage('scanWorkspace')">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="2" y="2" width="20" height="20" rx="2.18" ry="2.18"/>
            <line x1="9" y1="2" x2="9" y2="22"/>
        </svg>
        ${t.scanWorkspace}
    </button>
    
    <button class="btn btn-secondary" onclick="sendMessage('openDashboard')">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
            <line x1="9" y1="3" x2="9" y2="21"/>
            <line x1="15" y1="3" x2="15" y2="21"/>
            <line x1="3" y1="9" x2="21" y2="9"/>
            <line x1="3" y1="15" x2="21" y2="15"/>
        </svg>
        ${t.openDashboard}
    </button>



    <div class="sponsorship">
        <span>${t.donation}</span><br>
        <a href="https://www.paypal.com/donate/?hosted_button_id=MASK8JSBNSZPQ" target="_blank" class="paypal-link">
            Donar
        </a>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        function sendMessage(command) {
            vscode.postMessage({ command: command });
        }
    </script>
</body>
</html>`;
    }
}

async function askAI(finding) {
    const config = vscode.workspace.getConfiguration('owaspVerificator');
    let lang = config.get('language') || 'es';
    if (lang === 'auto') {
        lang = vscode.env.language.startsWith('es') ? 'es' : 'en';
    }
    const isEs = lang === 'es';

    const promptText = isEs
        ? `Tengo una vulnerabilidad del tipo ${finding.ruleId} (${finding.title}) en mi código Python.
La línea afectada contiene la siguiente evidencia:
\`\`\`python
${finding.evidence}
\`\`\`

La recomendación del linter es:
${finding.remediation}

Por favor:
1. Explica brevemente qué vulnerabilidad es y qué vas a hacer para solucionarla antes de proceder.
2. Luego, muestra el código corregido paso a paso y cómo implementarlo de forma segura.`
        : `I have a ${finding.ruleId} (${finding.title}) vulnerability in my Python code.
The affected line contains the following evidence:
\`\`\`python
${finding.evidence}
\`\`\`

The linter recommendation is:
${finding.remediation}

Please:
1. Briefly explain what the vulnerability is and what you will do to fix it before proceeding.
2. Then, provide the step-by-step corrected code and the explanation of how to apply it safely.`;

    const hasCopilot = vscode.extensions.getExtension('github.copilot-chat') !== undefined;
    const hasGemini = vscode.extensions.getExtension('google.gemini-code-assist') !== undefined || vscode.extensions.getExtension('google.cloudcode') !== undefined;

    if (hasCopilot || hasGemini) {
        try {
            await vscode.commands.executeCommand('workbench.action.chat.open', { query: promptText });
        } catch (err) {
            await vscode.env.clipboard.writeText(promptText);
            vscode.window.showInformationMessage(
                isEs ? "¡Prompt de solución copiado al portapapeles! Pégalo en tu chat de IA."
                     : "Solution prompt copied to clipboard! Paste it into your AI chat."
            );
        }
    } else {
        await vscode.env.clipboard.writeText(promptText);
        vscode.window.showInformationMessage(
            isEs ? "¡Prompt de solución copiado al portapapeles! Pégalo en tu IA preferida."
                 : "Solution prompt copied to clipboard! Paste it into your preferred AI."
        );
    }
}

// --- ESCANEO DE WORKSPACE Y DASHBOARD ---

async function scanWorkspaceAndShowDashboard(context) {
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "OWASP: Escaneando todo el Workspace...",
        cancellable: false
    }, async (progress) => {
        const config = vscode.workspace.getConfiguration('owaspVerificator');
        let lang = config.get('language') || 'es';
        if (lang === 'auto') {
            lang = vscode.env.language.startsWith('es') ? 'es' : 'en';
        }
        const isEs = lang === 'es';

        const files = await vscode.workspace.findFiles(
            '**/*.{py,js,jsx,ts,tsx,html,css,json,java,php,go,c,cpp,h,hpp,rb,rs,sh,sql,yaml,yml,cs,cshtml,aspx,ascx,asmx,ashx,master,kt,swift,scala,lua,pl}',
            '{**/node_modules/**,**/.venv/**,**/venv/**,**/env/**,**/.git/**,**/.pytest_cache/**,**/__pycache__/**,**/dist/**,**/build/**}'
        );
        
        if (files.length === 0) {
            vscode.window.showInformationMessage(
                isEs ? "No se encontraron archivos de código soportados para escanear en el workspace."
                     : "No supported code files were found to scan in the workspace."
            );
            return;
        }

        progress.report({ message: `Analizando ${files.length} archivos...` });

        const userConfigPath = config.get('pythonPath');
        const pythonPath = (userConfigPath && userConfigPath !== 'python') ? userConfigPath : (resolvedPythonCommand || 'python');
        const cliPath = path.join(extensionPath, 'cli.py');
        const enableAI = false;

        const scanResults = await scanFiles(files, pythonPath, cliPath, lang, enableAI);
        showDashboardPanel(context, scanResults, lang, files.length);
    });
}

async function scanFiles(files, pythonPath, cliPath, lang, enableAI) {
    const results = [];
    const limit = enableAI ? 2 : 5;
    let index = 0;
    
    async function worker() {
        while (index < files.length) {
            const fileUri = files[index++];
            try {
                const result = await scanFilePromise(fileUri, pythonPath, cliPath, lang, enableAI);
                if (result && result.length > 0) {
                    results.push({
                        uri: fileUri,
                        fsPath: fileUri.fsPath,
                        fileName: path.basename(fileUri.fsPath),
                        findings: result
                    });
                }
            } catch (err) {
                console.error(`Error scanning ${fileUri.fsPath}:`, err);
            }
        }
    }
    
    const workers = [];
    for (let i = 0; i < Math.min(limit, files.length); i++) {
        workers.push(worker());
    }
    await Promise.all(workers);
    return results;
}

function scanFilePromise(fileUri, pythonPath, cliPath, lang, enableAI) {
    return new Promise((resolve) => {
        try {
            const stats = fs.statSync(fileUri.fsPath);
            if (stats.size > MAX_FILE_SIZE_BYTES) {
                return resolve([]);
            }
        } catch (e) {
            return resolve([]);
        }

        const command = `"${pythonPath}" "${cliPath}" "${fileUri.fsPath}" --lang ${lang}`;
        exec(command, async (error, stdout) => {
            let findings = [];
            if (!error) {
                try {
                    const parsed = JSON.parse(stdout);
                    if (!parsed.error) {
                        findings = parsed;
                    }
                } catch (e) {}
            }

            if (enableAI && vscode.lm) {
                try {
                    const document = await vscode.workspace.openTextDocument(fileUri);
                    const token = new vscode.CancellationTokenSource().token;
                    const aiFindings = await scanFileWithAI(document, lang, token);
                    findings = mergeFindings(findings, aiFindings);
                } catch (aiErr) {
                    console.error(`OWASP Verificator: AI scan failed for ${fileUri.fsPath}:`, aiErr);
                }
            }

            resolve(findings);
        });
    });
}

async function askAIInline(finding, fileIdx, findingIdx, groupFirstFindingIdx, panel, lang) {
    if (!panel) return;

    const isEs = lang.startsWith('es');
    
    // Notify the webview that streaming has started
    panel.webview.postMessage({
        command: 'aiResponseStart',
        fileIdx: fileIdx,
        findingIdx: groupFirstFindingIdx
    });

    if (!vscode.lm) {
        panel.webview.postMessage({
            command: 'aiResponseError',
            fileIdx: fileIdx,
            findingIdx: groupFirstFindingIdx,
            error: isEs ? "La API de modelos de lenguaje (vscode.lm) no está disponible en esta versión de VS Code." 
                        : "The language model API (vscode.lm) is not available in this version of VS Code."
        });
        return;
    }

    try {
        let models = [];
        try {
            models = await vscode.lm.selectChatModels({ family: 'gpt-4o' });
        } catch (e) {
            try {
                models = await vscode.lm.selectChatModels();
            } catch (err) {}
        }

        if (!models || models.length === 0) {
            panel.webview.postMessage({
                command: 'aiResponseError',
                fileIdx: fileIdx,
                findingIdx: groupFirstFindingIdx,
                error: isEs ? "No se encontraron modelos de lenguaje disponibles (e.g. Copilot o Gemini)." 
                            : "No language models available (e.g. Copilot or Gemini)."
            });
            return;
        }

        const model = models[0];
        const promptText = isEs
            ? `Tengo una vulnerabilidad del tipo ${finding.ruleId} (${finding.title}) en mi código.
La línea afectada contiene la siguiente evidencia:
\`\`\`
${finding.evidence}
\`\`\`

La recomendación del linter es:
${finding.remediation}

Por favor:
1. Explica brevemente qué vulnerabilidad es y qué riesgo implica.
2. Muestra el código corregido de manera clara y segura.
3. Explica los cambios aplicados en español.`
            : `I have a ${finding.ruleId} (${finding.title}) vulnerability in my code.
The affected line contains the following evidence:
\`\`\`
${finding.evidence}
\`\`\`

The linter recommendation is:
${finding.remediation}

Please:
1. Briefly explain what the vulnerability is and the risk it poses.
2. Provide the corrected code clearly and securely.
3. Explain the changes applied in English.`;

        let messages = [
            vscode.LanguageModelChatMessage.User(promptText)
        ];

        const response = await model.sendRequest(messages, {}, new vscode.CancellationTokenSource().token);
        
        for await (const fragment of response.text) {
            panel.webview.postMessage({
                command: 'aiResponseChunk',
                fileIdx: fileIdx,
                findingIdx: groupFirstFindingIdx,
                chunk: fragment
            });
        }

        panel.webview.postMessage({
            command: 'aiResponseDone',
            fileIdx: fileIdx,
            findingIdx: groupFirstFindingIdx
        });

    } catch (err) {
        panel.webview.postMessage({
            command: 'aiResponseError',
            fileIdx: fileIdx,
            findingIdx: groupFirstFindingIdx,
            error: err.message
        });
    }
}

let dashboardPanel = null;

function showDashboardPanel(context, scanResults, lang, totalFilesScanned) {
    if (dashboardPanel) {
        dashboardPanel.reveal(vscode.ViewColumn.Active);
    } else {
        dashboardPanel = vscode.window.createWebviewPanel(
            'owaspDashboard',
            'OWASP Verificator Dashboard',
            vscode.ViewColumn.Active,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );
        
        dashboardPanel.onDidDispose(() => {
            dashboardPanel = null;
        }, null, context.subscriptions);
    }

    dashboardPanel.webview.html = getDashboardHtml(scanResults, lang, totalFilesScanned);

    dashboardPanel.webview.onDidReceiveMessage(message => {
        if (message.command === 'openFile') {
            const openPath = vscode.Uri.file(message.fsPath);
            vscode.workspace.openTextDocument(openPath).then(doc => {
                vscode.window.showTextDocument(doc).then(editor => {
                    const line = Math.max(0, message.line - 1);
                    const pos = new vscode.Position(line, 0);
                    editor.selection = new vscode.Selection(pos, pos);
                    editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
                });
            });
        // Comandos de IA de dashboard desactivados
        }
    }, null, context.subscriptions);
}

function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function getDashboardHtml(scanResults, lang, totalFilesScanned) {
    const isEs = lang.startsWith('es');
    const config = vscode.workspace.getConfiguration('owaspVerificator');
    let aiStatus = 'inactive';
    
    const t = {
        es: {
            title: "OWASP Verificator - Dashboard de Seguridad",
            subtitle: "Reporte consolidado de cumplimiento e integridad del workspace",
            scoreTitle: "Puntuación de Seguridad",
            totalFiles: "Archivos Analizados",
            totalFindings: "Vulnerabilidades",
            findingSingular: "vulnerabilidad",
            findingPlural: "vulnerabilidades",
            high: "Crítico",
            medium: "Advertencia",
            low: "Recomendación",
            viewInEditor: "Ver en Editor",

            evidence: "Evidencia",
            remediation: "Remediación Sugerida",
            emptyTitle: "¡Sin vulnerabilidades detectadas!",
            emptyDesc: "Excelente trabajo. Todos los archivos de tu espacio de trabajo cumplen con las reglas de seguridad analizadas.",
            donation: "Apoya el desarrollo de esta extensión:",
            rule: "Regla",
            location: "Ubicación",
            file: "Archivo",
            severity: "Severidad"
        },
        en: {
            title: "OWASP Verificator - Security Dashboard",
            subtitle: "Consolidated workspace compliance and integrity report",
            scoreTitle: "Security Score",
            totalFiles: "Files Scanned",
            totalFindings: "Vulnerabilities",
            findingSingular: "vulnerability",
            findingPlural: "vulnerabilities",
            high: "Critical",
            medium: "Warning",
            low: "Recommendation",
            viewInEditor: "Open in Editor",

            evidence: "Evidence",
            remediation: "Suggested Remediation",
            emptyTitle: "No vulnerabilities detected!",
            emptyDesc: "Excellent work. All workspace files comply with analyzed security rules.",
            donation: "Support the development of this extension:",
            rule: "Rule",
            location: "Location",
            file: "File",
            severity: "Severity"
        }
    }[isEs ? 'es' : 'en'];

    function renderFileCards() {
        return scanResults.map((fileResult, fileIdx) => {
            let filePenalty = 0;
            fileResult.findings.forEach(f => {
                const sev = (f.severity || 'low').toLowerCase();
                if (sev === 'high') filePenalty += 30;
                else if (sev === 'medium') filePenalty += 15;
                else filePenalty += 5;
            });
            const fileScore = Math.max(100 - Math.min(filePenalty, 100), 0);
            let fileColor = 'var(--color-safe)';
            if (fileScore < 40) fileColor = 'var(--color-high)';
            else if (fileScore < 80) fileColor = 'var(--color-medium)';

            // Group findings by rule_id for this file
            const groupedFindingsMap = new Map();
            fileResult.findings.forEach((f, idx) => {
                if (!groupedFindingsMap.has(f.rule_id)) {
                    groupedFindingsMap.set(f.rule_id, {
                        firstFindingIdx: idx,
                        rule_id: f.rule_id,
                        title: f.title,
                        severity: f.severity,
                        description: f.description,
                        remediation: f.remediation,
                        occurrences: []
                    });
                }
                groupedFindingsMap.get(f.rule_id).occurrences.push({
                    findingIdx: idx,
                    line: f.line,
                    evidence: f.evidence
                });
            });
            const groupedFindings = Array.from(groupedFindingsMap.values());

            const findingsHtml = groupedFindings.map(group => {
                const occurrencesHtml = group.occurrences.map(occ => {
                    return `
                        <div style="display: flex; flex-direction: column; gap: 4px; padding: 8px; background: rgba(15, 17, 21, 0.35); border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.03);">
                            <div style="display: flex; align-items: center; justify-content: space-between; gap: 10px;">
                                <span class="finding-line" style="font-size: 12px; font-weight: 600; color: #cbd5e1; margin-bottom: 0;">Línea ${occ.line}</span>
                                <div style="display: flex; gap: 8px;">

                                    <button class="open-btn" style="padding: 4px 10px; font-size: 11px;" title="${isEs ? 'Ir a la línea exacta de la vulnerabilidad en tu editor de código.' : 'Go to the exact vulnerability line in your code editor.'}" onclick="openFile('${fileResult.fsPath.replace(/\\/g, '\\\\')}', ${occ.line})">${t.viewInEditor}</button>
                                </div>
                            </div>
                            <pre style="padding: 6px 10px; background: rgba(0, 0, 0, 0.4); margin: 0; border: none; border-radius: 4px; overflow-x: auto;"><code style="font-size: 12px; white-space: pre-wrap; word-break: break-all;">${escapeHtml(occ.evidence)}</code></pre>
                        </div>
                    `;
                }).join('');

                const occurrenceLabel = group.occurrences.length === 1 
                    ? (isEs ? 'ocurrencia' : 'occurrence') 
                    : (isEs ? 'ocurrencias' : 'occurrences');

                const linesLabel = isEs ? 'Líneas Afectadas y Evidencia' : 'Affected Lines & Evidence';

                return `
                    <div class="finding-row severity-${group.severity.toLowerCase()}">
                        <div class="finding-main" style="margin-bottom: 8px;">
                            <span class="finding-badge">${group.rule_id}</span>
                            <span class="finding-title">${group.title}</span>
                            <span class="file-badge" style="background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.08); font-size: 11px; padding: 2px 8px; border-radius: 12px;">
                                ${group.occurrences.length} ${occurrenceLabel}
                            </span>
                        </div>
                        <div class="finding-details" style="padding-left: 8px;">
                            <p class="finding-desc">${group.description}</p>
                            
                            <!-- Ocurrencias en lista compacta -->
                            <div style="margin-bottom: 14px; background: rgba(15, 17, 21, 0.25); border: 1px solid rgba(255, 255, 255, 0.03); border-radius: 8px; padding: 8px 12px;">
                                <strong style="font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 8px;">
                                    ${linesLabel}:
                                </strong>
                                <div style="display: flex; flex-direction: column; gap: 8px;">
                                    ${occurrencesHtml}
                                </div>
                            </div>

                            <!-- Recomendación común -->
                            <div class="finding-remediation">
                                <strong>${t.remediation}:</strong>
                                <p>${group.remediation.replace(/\n/g, '<br>')}</p>
                            </div>

                            <!-- Contenedor de IA inline común para el grupo -->
                            <div id="ai-response-${fileIdx}-${group.firstFindingIdx}" class="ai-response-container">
                                <div class="ai-response-title">
                                    <div class="ai-spinner" id="ai-spinner-${fileIdx}-${group.firstFindingIdx}"></div>
                                    <svg class="ai-sparkle-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display: none; vertical-align: middle;" id="ai-sparkle-${fileIdx}-${group.firstFindingIdx}">
                                        <path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m11.314 11.314l.707-.707M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z"/>
                                    </svg>
                                    <span id="ai-status-text-${fileIdx}-${group.firstFindingIdx}">Asistente de Seguridad IA</span>
                                </div>
                                <div class="ai-response-content" id="ai-content-${fileIdx}-${group.firstFindingIdx}"></div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');

            return `
                <div class="file-card">
                    <div class="file-header" onclick="toggleFile(this)" style="position: relative;" title="${isEs ? 'Haz clic para colapsar o expandir los detalles de este archivo' : 'Click to collapse or expand details for this file'}">
                        <!-- Chevron SVG -->
                        <svg class="chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="6 9 12 15 18 9"/>
                        </svg>
                        <span class="file-name">${fileResult.fileName}</span>
                        <span class="file-path">${escapeHtml(fileResult.fsPath)}</span>
                        <span class="file-badge" style="background: ${fileColor}14; color: ${fileColor}; border: 1px solid ${fileColor}25;">${fileResult.findings.length} ${fileResult.findings.length === 1 ? t.findingSingular : t.findingPlural}</span>
                        
                        <!-- Barra de progreso de seguridad -->
                        <div style="position: absolute; bottom: 0; left: 0; width: 100%; height: 3px; background: rgba(255, 255, 255, 0.05);">
                            <div style="width: ${fileScore}%; height: 100%; background: ${fileColor}; transition: width 0.3s;"></div>
                        </div>
                    </div>
                    <div class="file-body" style="display: block; padding-bottom: 12px;">
                        ${findingsHtml}
                    </div>
                </div>
            `;
        }).join('');
    }

    const allFindings = scanResults.flatMap(r => r.findings);
    const totalFindings = allFindings.length;
    const highCount = allFindings.filter(f => f.severity === 'high').length;
    const mediumCount = allFindings.filter(f => f.severity === 'medium').length;
    const lowCount = allFindings.filter(f => f.severity === 'low').length;

    // Calcular score promedio ponderado por archivo (más preciso y justo para workspace)
    let totalScoreSum = 0;
    scanResults.forEach(r => {
        let filePenalty = 0;
        r.findings.forEach(f => {
            const sev = (f.severity || 'low').toLowerCase();
            if (sev === 'high') filePenalty += 30;
            else if (sev === 'medium') filePenalty += 15;
            else filePenalty += 5;
        });
        const fileScore = Math.max(100 - Math.min(filePenalty, 100), 0);
        totalScoreSum += fileScore;
    });
    const filesWithFindingsCount = scanResults.length;
    const filesWithoutFindingsCount = totalFilesScanned - filesWithFindingsCount;
    totalScoreSum += filesWithoutFindingsCount * 100;
    
    const score = totalFilesScanned > 0 ? Math.round(totalScoreSum / totalFilesScanned) : 100;
    
    let scoreColor = '#2ebb4e'; // green
    if (score < 40) {
        scoreColor = '#ff4d4d';
    } else if (score < 80) {
        scoreColor = '#ffaa00';
    }

    const scanResultsJson = JSON.stringify(scanResults).replace(/<\/script/g, '<\\/script');

    return `<!DOCTYPE html>
<html lang="${lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${t.title}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

        :root {
            --bg-color: var(--vscode-editor-background, #0f1115);
            --fg-color: var(--vscode-editor-foreground, #e2e8f0);
            --card-bg: rgba(30, 41, 59, 0.4);
            --card-border: rgba(255, 255, 255, 0.06);
            --hover-bg: rgba(255, 255, 255, 0.08);
            
            --color-high: #f43f5e;
            --color-medium: #fbbf24;
            --color-low: #3b82f6;
            --color-safe: #10b981;
            
            --glow-high: 0 0 20px rgba(244, 63, 94, 0.2);
            --glow-medium: 0 0 20px rgba(251, 191, 36, 0.15);
            --glow-low: 0 0 20px rgba(59, 130, 246, 0.15);
            --glow-safe: 0 0 20px rgba(16, 185, 129, 0.2);

            --font-main: 'Plus Jakarta Sans', var(--vscode-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif);
            --font-mono: 'JetBrains Mono', var(--vscode-editor-font-family, monospace);
        }

        body {
            background-color: var(--bg-color);
            color: var(--fg-color);
            font-family: var(--font-main);
            margin: 0;
            padding: 28px;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }

        .dashboard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 20px;
            margin-bottom: 28px;
            gap: 20px;
        }

        .dashboard-title h1 {
            margin: 0;
            font-size: 26px;
            font-weight: 700;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, var(--vscode-editor-foreground, #e2e8f0), #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .dashboard-title p {
            margin: 6px 0 0 0;
            font-size: 13px;
            color: #94a3b8;
        }

        .sponsorship-container {
            display: flex;
            align-items: center;
            gap: 15px;
            font-size: 13px;
            color: #94a3b8;
        }

        .paypal-badge {
            display: inline-flex;
            align-items: center;
            background: rgba(255, 255, 255, 0.04);
            color: #94a3b8;
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 5px 12px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 11px;
            font-weight: 600;
            transition: all 0.2s ease;
        }

        .paypal-badge:hover {
            background: rgba(255, 255, 255, 0.08);
            color: var(--vscode-foreground, #ffffff);
            border-color: rgba(255, 255, 255, 0.2);
        }

        .kpis-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 28px;
        }

        .kpi-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .kpi-card:hover {
            transform: translateY(-4px);
            border-color: rgba(255, 255, 255, 0.12);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.2);
        }

        .kpi-value {
            font-size: 38px;
            font-weight: 700;
            margin-top: 8px;
            letter-spacing: -1px;
        }

        .kpi-label {
            font-size: 11px;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }

        .score-container {
            grid-column: span 2;
            flex-direction: row;
            justify-content: space-around;
            padding: 20px 28px;
        }

        .score-info {
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        .score-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 4px;
            color: var(--fg-color);
        }

        .score-desc {
            font-size: 12px;
            color: #94a3b8;
        }

        .score-circle {
            transform: rotate(-90deg);
            filter: drop-shadow(0 0 8px ${scoreColor}30);
        }
        .score-circle circle {
            fill: none;
            stroke-width: 10;
        }
        .score-circle circle.bg {
            stroke: var(--vscode-input-border, rgba(255, 255, 255, 0.05));
        }
        .score-circle circle.fg {
            stroke: ${scoreColor};
            stroke-linecap: round;
            transition: stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .score-circle text {
            transform: rotate(90deg);
            transform-origin: center;
            text-anchor: middle;
            fill: var(--fg-color);
            font-size: 26px;
            font-weight: 700;
        }

        .status-banner {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 16px 24px;
            border-radius: 12px;
            margin-bottom: 28px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .filters-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            gap: 20px;
        }

        .search-box {
            position: relative;
            width: 340px;
        }

        .search-input {
            background: var(--vscode-input-background, rgba(30, 41, 59, 0.3));
            color: var(--vscode-input-foreground, #e2e8f0);
            border: 1px solid var(--vscode-input-border, rgba(255, 255, 255, 0.1));
            border-radius: 8px;
            padding: 10px 14px 10px 36px;
            font-size: 13px;
            width: 100%;
            outline: none;
            box-sizing: border-box;
            transition: all 0.3s;
            font-family: var(--font-main);
        }

        .search-input:focus {
            border-color: var(--vscode-focusBorder, #3b82f6);
            box-shadow: 0 0 12px rgba(59, 130, 246, 0.2);
            background: rgba(30, 41, 59, 0.5);
        }

        .search-icon-svg {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: #94a3b8;
            pointer-events: none;
        }

        .filter-buttons {
            display: flex;
            gap: 10px;
        }

        .filter-btn {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            color: var(--fg-color);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            font-family: var(--font-main);
        }

        .filter-btn:hover {
            background: var(--hover-bg);
            border-color: rgba(255, 255, 255, 0.15);
        }

        .filter-btn.active {
            background: var(--vscode-button-background, #3b82f6);
            color: var(--vscode-button-foreground, #ffffff);
            border-color: transparent;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.25);
        }

        .file-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
            transition: border-color 0.3s;
        }

        .file-card:hover {
            border-color: rgba(255, 255, 255, 0.1);
        }

        .file-header {
            background: rgba(255, 255, 255, 0.01);
            padding: 16px 20px;
            display: flex;
            align-items: center;
            cursor: pointer;
            border-bottom: 1px solid var(--card-border);
            transition: background 0.3s;
        }

        .file-header:hover {
            background: var(--hover-bg);
        }

        .chevron {
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            color: #94a3b8;
            margin-right: 12px;
            flex-shrink: 0;
        }

        .collapsed .chevron {
            transform: rotate(-90deg);
        }

        .file-name {
            font-weight: 600;
            font-size: 15px;
            color: var(--fg-color);
        }

        .file-path {
            font-size: 12px;
            color: #94a3b8;
            margin-left: 14px;
            flex-grow: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            opacity: 0.8;
        }

        .file-badge {
            background: rgba(255, 255, 255, 0.06);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }

        .file-body {
            padding: 0 20px;
            transition: all 0.3s ease;
        }

        .finding-row {
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            padding: 20px 0;
        }

        .finding-row:last-child {
            border-bottom: none;
        }

        .finding-main {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
        }

        .finding-badge {
            padding: 3px 10px;
            border-radius: 6px;
            font-family: var(--font-mono);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: -0.2px;
        }

        .severity-high .finding-badge {
            background: rgba(244, 63, 94, 0.12);
            color: var(--color-high);
            border: 1px solid rgba(244, 63, 94, 0.25);
            box-shadow: var(--glow-high);
        }

        .severity-medium .finding-badge {
            background: rgba(251, 191, 36, 0.1);
            color: var(--color-medium);
            border: 1px solid rgba(251, 191, 36, 0.2);
            box-shadow: var(--glow-medium);
        }

        .severity-low .finding-badge {
            background: rgba(59, 130, 246, 0.1);
            color: var(--color-low);
            border: 1px solid rgba(59, 130, 246, 0.2);
            box-shadow: var(--glow-low);
        }

        .finding-title {
            font-weight: 600;
            font-size: 15px;
        }

        .finding-line {
            font-size: 12px;
            font-weight: 500;
            color: #94a3b8;
            background: rgba(255, 255, 255, 0.04);
            padding: 3px 8px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.02);
        }

        .open-btn {
            background: rgba(255, 255, 255, 0.04);
            color: var(--fg-color);
            border: 1px solid rgba(255, 255, 255, 0.08);
            padding: 6px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            font-family: var(--font-main);
        }

        .open-btn:hover {
            background: var(--hover-bg);
            border-color: rgba(255, 255, 255, 0.15);
        }

        .ai-btn {
            background: linear-gradient(135deg, #8b5cf6, #3b82f6) !important;
            color: #ffffff !important;
            border: none;
            padding: 6px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            display: inline-flex;
            align-items: center;
            gap: 6px;
            box-shadow: 0 4px 12px rgba(139, 92, 246, 0.2);
            font-family: var(--font-main);
        }

        .ai-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 18px rgba(139, 92, 246, 0.35);
            background: linear-gradient(135deg, #9065f7, #4b8eff) !important;
        }

        .finding-details {
            padding-left: 8px;
        }

        .finding-desc {
            margin: 0 0 14px 0;
            font-size: 14px;
            color: #cbd5e1;
        }

        .finding-code, .finding-remediation {
            margin-bottom: 14px;
        }

        .finding-code strong, .finding-remediation strong {
            font-size: 12px;
            color: #94a3b8;
            display: block;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }

        pre {
            background: rgba(15, 17, 21, 0.55);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 12px 16px;
            margin: 0;
            overflow-x: auto;
        }

        code {
            font-family: var(--font-mono);
            font-size: 13px;
            color: #f59e0b;
        }

        .finding-remediation p {
            margin: 0;
            font-size: 14px;
            color: #10b981;
            background: rgba(16, 185, 129, 0.05);
            border-left: 3px solid var(--color-safe);
            padding: 10px 14px;
            border-radius: 0 8px 8px 0;
        }

        .empty-state {
            text-align: center;
            padding: 64px 32px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
        }

        .empty-state h3 {
            margin: 0 0 8px 0;
            font-size: 20px;
            font-weight: 600;
            color: var(--color-safe);
        }

        .empty-state p {
            margin: 0;
            font-size: 14px;
            color: #94a3b8;
        }

        /* Switch UI */
        .switch {
            position: relative;
            display: inline-block;
            width: 34px;
            height: 20px;
            flex-shrink: 0;
        }
        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(255, 255, 255, 0.12);
            transition: .3s;
            border-radius: 20px;
        }
        .slider:before {
            position: absolute;
            content: "";
            height: 14px;
            width: 14px;
            left: 3px;
            bottom: 3px;
            background-color: #ffffff;
            transition: .3s;
            border-radius: 50%;
        }
        input:checked + .slider {
            background-color: var(--vscode-button-background, #3b82f6);
        }
        input:checked + .slider:before {
            transform: translateX(14px);
        }

        /* Contenedor de respuesta IA */
        .ai-response-container {
            margin-top: 16px;
            background: rgba(139, 92, 246, 0.04);
            border: 1px solid rgba(139, 92, 246, 0.15);
            border-radius: 8px;
            padding: 16px;
            display: none;
            position: relative;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        }

        .ai-response-container.active {
            display: block;
            animation: slideFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        @keyframes slideFadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .ai-response-title {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            font-weight: 600;
            color: #a78bfa;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .ai-response-content {
            font-size: 13.5px;
            color: #cbd5e1;
            line-height: 1.6;
        }

        .ai-response-content pre {
            background: rgba(15, 17, 21, 0.75);
            border-color: rgba(139, 92, 246, 0.2);
            margin: 10px 0;
        }

        .ai-response-content code {
            color: #f59e0b;
        }

        .ai-response-content p {
            margin: 0 0 10px 0;
        }

        .ai-response-content p:last-child {
            margin-bottom: 0;
        }

        .ai-spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(139, 92, 246, 0.2);
            border-radius: 50%;
            border-top-color: #a78bfa;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="dashboard-header">
        <div class="dashboard-title">
            <h1>${t.title}</h1>
            <p>${t.subtitle}</p>
        </div>
        <div class="sponsorship-container">
            <span>${t.donation}</span>
            <a href="https://www.paypal.com/donate/?hosted_button_id=MASK8JSBNSZPQ" target="_blank" class="paypal-badge" title="${isEs ? 'Apoya el desarrollo de código abierto de OWASP Verificator' : 'Support the open source development of OWASP Verificator'}">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 5px;">
                    <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>
                </svg>
                <strong>Donar</strong>
            </a>
        </div>
    </div>

    <!-- Status Banner -->
    <div class="status-banner" style="background: ${score >= 90 ? 'linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(4, 120, 87, 0.15))' : (score >= 70 ? 'linear-gradient(135deg, rgba(245, 158, 11, 0.12), rgba(180, 83, 9, 0.12))' : 'linear-gradient(135deg, rgba(244, 63, 94, 0.15), rgba(190, 24, 74, 0.15))')}; border-color: ${score >= 90 ? 'rgba(16, 185, 129, 0.3)' : (score >= 70 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(244, 63, 94, 0.3)')};">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="${score >= 90 ? 'var(--color-safe)' : (score >= 70 ? 'var(--color-medium)' : 'var(--color-high)')}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0;">
            ${score >= 90 
                ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>' 
                : (score >= 70 
                    ? '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>' 
                    : '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>')}
        </svg>
        <div>
            <strong style="font-size: 15px; display: block; margin-bottom: 2px; color: ${score >= 90 ? 'var(--color-safe)' : (score >= 70 ? 'var(--color-medium)' : 'var(--color-high)')};">
                ${score >= 90 
                    ? (isEs ? '¡Código Altamente Seguro!' : 'Highly Secure Code!') 
                    : (score >= 70 
                        ? (isEs ? 'Advertencias de Cumplimiento Detectadas' : 'Compliance Warnings Detected') 
                        : (isEs ? 'Riesgos Críticos de Seguridad Detectados' : 'Critical Security Risks Detected'))}
            </strong>
            <span style="font-size: 13px; color: #cbd5e1; display: block; line-height: 1.4;">
                ${score >= 90 
                    ? (isEs ? 'Tu nivel de cumplimiento de las reglas OWASP es excelente. Continúa programando de forma segura.' : 'Your compliance rating with OWASP rules is excellent. Keep coding securely.') 
                    : (score >= 70 
                        ? (isEs ? 'Se encontraron advertencias de seguridad menores. Te recomendamos revisarlas para evitar posibles ataques.' : 'Minor security warnings found. We suggest reviewing them to prevent potential vulnerabilities.') 
                        : (isEs ? '¡Acción requerida! Se detectaron fallas críticas de cumplimiento de seguridad en tu código. Resuélvelas de inmediato.' : 'Action required! Critical security compliance issues detected in your code. Fix them immediately.'))}
            </span>
        </div>
    </div>

    <div class="kpis-grid">
        <div class="kpi-card score-container">
            <div class="score-info">
                <div class="score-title">${t.scoreTitle}</div>
                <div class="score-desc">OWASP Compliance Rating</div>
            </div>
            <svg width="100" height="100" viewBox="0 0 120 120" class="score-circle">
                <circle cx="60" cy="60" r="50" class="bg" />
                <circle cx="60" cy="60" r="50" class="fg" stroke-dasharray="314" stroke-dashoffset="${314 - (314 * score) / 100}" />
                <text x="60" y="68" class="score-text">${score}%</text>
            </svg>
        </div>
        <div class="kpi-card">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="opacity: 0.85;">
                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                </svg>
                <div class="kpi-label">${t.totalFiles}</div>
            </div>
            <div class="kpi-value" style="color: var(--fg-color);">${totalFilesScanned}</div>
        </div>
        <div class="kpi-card" style="border-bottom: 3px solid var(--color-high);">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-high)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="17"/>
                </svg>
                <div class="kpi-label" style="color: var(--color-high); font-weight: 600;">${t.high}</div>
            </div>
            <div class="kpi-value" style="color: var(--color-high);">${highCount}</div>
        </div>
        <div class="kpi-card" style="border-bottom: 3px solid var(--color-medium);">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-medium)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                <div class="kpi-label" style="color: var(--color-medium); font-weight: 600;">${t.medium}</div>
            </div>
            <div class="kpi-value" style="color: var(--color-medium);">${mediumCount}</div>
        </div>
        <div class="kpi-card" style="border-bottom: 3px solid var(--color-low);">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-low)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
                </svg>
                <div class="kpi-label" style="color: var(--color-low); font-weight: 600;">${t.low}</div>
            </div>
            <div class="kpi-value" style="color: var(--color-low);">${lowCount}</div>
        </div>
    </div>

    ${totalFindings === 0 ? `
        <div class="empty-state">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--color-safe)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom: 16px;">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
            <h3>${t.emptyTitle}</h3>
            <p>${t.emptyDesc}</p>
        </div>
    ` : `
        <div class="filters-bar">
            <div class="search-box">
                <svg class="search-icon-svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
                <input type="text" id="search" class="search-input" placeholder="${isEs ? 'Buscar por archivo, regla o título...' : 'Search by file, rule or title...'}">
            </div>
            <div class="filter-buttons">
                <button class="filter-btn active" data-severity="all" onclick="setFilter('all')" title="${isEs ? 'Ver todos los hallazgos' : 'View all findings'}">Todos (${totalFindings})</button>
                <button class="filter-btn" data-severity="high" onclick="setFilter('high')" style="color: var(--color-high);" title="${isEs ? 'Filtrar por severidad Crítica' : 'Filter by Critical severity'}">Crítico (${highCount})</button>
                <button class="filter-btn" data-severity="medium" onclick="setFilter('medium')" style="color: var(--color-medium);" title="${isEs ? 'Filtrar por severidad de Advertencia' : 'Filter by Warning severity'}">Advertencia (${mediumCount})</button>
                <button class="filter-btn" data-severity="low" onclick="setFilter('low')" style="color: var(--color-low);" title="${isEs ? 'Filtrar por severidad de Recomendación' : 'Filter by Recommendation severity'}">Recomendación (${lowCount})</button>
            </div>
        </div>

        <div class="files-container">
            ${renderFileCards()}
        </div>
    `}

    <script>
        const vscode = acquireVsCodeApi();
        const scanResultsData = ${scanResultsJson};
        
        function openFile(fsPath, line) {
            vscode.postMessage({
                command: 'openFile',
                fsPath: fsPath,
                line: line
            });
        }

        function toggleAI() {
            vscode.postMessage({
                command: 'toggleAI'
            });
        }

        function askAIInline(fileIdx, findingIdx, groupFirstFindingIdx) {
            const fileResult = scanResultsData[fileIdx];
            const finding = fileResult.findings[findingIdx];
            
            const container = document.getElementById('ai-response-' + fileIdx + '-' + groupFirstFindingIdx);
            const spinner = document.getElementById('ai-spinner-' + fileIdx + '-' + groupFirstFindingIdx);
            const sparkle = document.getElementById('ai-sparkle-' + fileIdx + '-' + groupFirstFindingIdx);
            const statusText = document.getElementById('ai-status-text-' + fileIdx + '-' + groupFirstFindingIdx);
            const contentDiv = document.getElementById('ai-content-' + fileIdx + '-' + groupFirstFindingIdx);
            
            container.classList.add('active');
            spinner.style.display = 'inline-block';
            sparkle.style.display = 'none';
            statusText.textContent = "${isEs ? 'Analizando con IA...' : 'Analyzing with AI...'}";
            contentDiv.innerHTML = '';
            delete contentDiv.dataset.raw;
            
            vscode.postMessage({
                command: 'askAIInline',
                fileIdx: fileIdx,
                findingIdx: findingIdx,
                groupFirstFindingIdx: groupFirstFindingIdx,
                finding: {
                    ruleId: finding.rule_id,
                    title: finding.title,
                    evidence: finding.evidence,
                    remediation: finding.remediation
                }
            });
        }

        window.addEventListener('message', event => {
            const message = event.data;
            

            
            const { fileIdx, findingIdx } = message;
            const container = document.getElementById('ai-response-' + fileIdx + '-' + findingIdx);
            if (!container) return;
            
            const spinner = document.getElementById('ai-spinner-' + fileIdx + '-' + findingIdx);
            const sparkle = document.getElementById('ai-sparkle-' + fileIdx + '-' + findingIdx);
            const statusText = document.getElementById('ai-status-text-' + fileIdx + '-' + findingIdx);
            const contentDiv = document.getElementById('ai-content-' + fileIdx + '-' + findingIdx);
            
            switch (message.command) {
                case 'aiResponseStart':
                    break;
                case 'aiResponseChunk':
                    if (!contentDiv.dataset.raw) {
                        contentDiv.dataset.raw = '';
                    }
                    contentDiv.dataset.raw += message.chunk;
                    contentDiv.innerHTML = formatMarkdown(contentDiv.dataset.raw);
                    break;
                case 'aiResponseDone':
                    spinner.style.display = 'none';
                    sparkle.style.display = 'inline-block';
                    statusText.textContent = "${isEs ? 'Respuesta de la IA' : 'AI Response'}";
                    break;
                case 'aiResponseError':
                    spinner.style.display = 'none';
                    statusText.textContent = "${isEs ? 'Error de IA' : 'AI Error'}";
                    contentDiv.innerHTML = '<span style="color: var(--color-high);">' + escapeHtml(message.error) + '</span>';
                    break;
            }
        });

        function formatMarkdown(text) {
            if (!text) return '';
            let html = text;
            
            // Bloques de código
            html = html.replace(new RegExp('\\\\x60\\\\x60\\\\x60[a-zA-Z0-9]*\\\\n([\\\\s\\\\S]*?)\\\\x60\\\\x60\\\\x60', 'g'), (match, code) => {
                return '<pre><code>' + escapeHtml(code.trim()) + '</code></pre>';
            });
            
            // Código inline
            html = html.replace(new RegExp('\\\\x60([^\\\\x60\\\\n]+)\\\\x60', 'g'), '<code>$1</code>');
            
            // Negritas
            html = html.replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>');
            
            // Encabezados
            html = html.replace(/^### (.*)$/gm, '<h4 style="margin: 12px 0 6px 0; color: #a78bfa; font-size: 13.5px;">$1</h4>');
            html = html.replace(/^## (.*)$/gm, '<h3 style="margin: 14px 0 8px 0; color: #a78bfa; font-size: 14px;">$1</h3>');
            html = html.replace(/^# (.*)$/gm, '<h2 style="margin: 16px 0 10px 0; color: #a78bfa; font-size: 15px;">$1</h2>');
            
            // Saltos de línea
            const parts = html.split(/(<pre>[\\s\\S]*?<\\/pre>)/g);
            for (let i = 0; i < parts.length; i++) {
                if (!parts[i].startsWith('<pre>')) {
                    parts[i] = parts[i].replace(/\\n/g, '<br>');
                }
            }
            return parts.join('');
        }

        let activeFilter = 'all';
        let searchQuery = '';

        function setFilter(severity) {
            activeFilter = severity;
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.severity === severity);
            });
            applyFilters();
        }

        document.getElementById('search').addEventListener('input', (e) => {
            searchQuery = e.target.value.toLowerCase();
            applyFilters();
        });

        function applyFilters() {
            const fileCards = document.querySelectorAll('.file-card');
            
            fileCards.forEach(card => {
                const findings = card.querySelectorAll('.finding-row');
                let visibleFindingsCount = 0;
                
                findings.forEach(row => {
                    const isSeverityMatch = activeFilter === 'all' || row.classList.contains('severity-' + activeFilter);
                    
                    const title = row.querySelector('.finding-title').textContent.toLowerCase();
                    const badge = row.querySelector('.finding-badge').textContent.toLowerCase();
                    const desc = row.querySelector('.finding-desc').textContent.toLowerCase();
                    const isSearchMatch = title.includes(searchQuery) || badge.includes(searchQuery) || desc.includes(searchQuery);
                    
                    if (isSeverityMatch && isSearchMatch) {
                        row.style.display = 'block';
                        visibleFindingsCount++;
                    } else {
                        row.style.display = 'none';
                    }
                });
                
                if (visibleFindingsCount > 0) {
                    card.style.display = 'block';
                    card.querySelector('.file-badge').textContent = visibleFindingsCount + ' ' + (visibleFindingsCount === 1 ? '${t.findingSingular}' : '${t.findingPlural}');
                } else {
                    card.style.display = 'none';
                }
            });
        }

        function toggleFile(header) {
            const card = header.parentElement;
            const body = header.nextElementSibling;
            card.classList.toggle('collapsed');
            if (body.style.display === 'none') {
                body.style.display = 'block';
            } else {
                body.style.display = 'none';
            }
        }
    </script>
</body>
</html>`;
}

function deactivate() {
    if (statusBarItem) {
        statusBarItem.dispose();
    }
}

module.exports = {
    activate,
    deactivate
};
