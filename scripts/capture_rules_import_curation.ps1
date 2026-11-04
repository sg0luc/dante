param(
    [string]$OutputFile1 = "docs/screenshots/10-rules-import-modal.png",
    [string]$OutputFile2 = "docs/screenshots/32-rules-import-ai-curation-opinion.png"
)

Write-Host "Iniciando captura de tela automatizada de Importação de Regras com Curadoria e IA..."

# 1. Preparar arquivos de demonstração com regras Loki Ruler
$demoDir = Join-Path $env:TEMP "dante-demo-import"
if (Test-Path $demoDir) {
    Remove-Item -Path $demoDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $demoDir -Force | Out-Null

$adYamlPath = Join-Path $demoDir "ad_privilege_escalation.yaml"
@"
groups:
  - name: active_directory_security
    rules:
      - alert: "AD User Added to Privileged Group"
        expr: 'sum(count_over_time({job="wazuh", ss_groups=~".*windows.*"} | json | win_system_eventID=~"4728" | win_eventdata_targetUserName!="" [5m])) > 0'
        for: 0s
        labels:
          severity: critical
          mitre_tactic: persistence
          mitre_technique: T1098
        annotations:
          summary: "Identifica adição de usuários em grupos de alto privilégio no Active Directory"
          description: "Detecta modificações de permissão sensíveis correlacionando eventos 4728 do log de segurança."
"@ | Set-Content -Path $adYamlPath -Encoding utf8

$fortigateJsonPath = Join-Path $demoDir "fortigate_bruteforce.json"
@"
{
  "groups": [
    {
      "name": "network_perimeter",
      "rules": [
        {
          "alert": "Fortigate Multiple Blocked Exploitation Attempts",
          "expr": "sum(count_over_time({job=\"wazuh\", ss_groups=~\".*fortigate.*\"} | json | data_dstip!=\"\" | data_action=~\"block|deny\" [5m])) > 10",
          "for": "0s",
          "labels": {
            "severity": "high",
            "mitre_tactic": "initial_access",
            "mitre_technique": "T1190"
          },
          "annotations": {
            "summary": "Múltiplas tentativas de exploração barradas no firewall perimetral",
            "description": "Indica sondagem hostil ou tentativa de exploração de vulnerabilidades no perímetro."
          }
        }
      ]
    }
  ]
}
"@ | Set-Content -Path $fortigateJsonPath -Encoding utf8

# 2. Obter cookie de autenticação do portal
$loginResp = curl.exe -s -i -X POST http://localhost:8080/api/auth/login `
    -H "Content-Type: application/json" `
    -H "X-Requested-With: hunter-portal" `
    -d '{\"username\":\"hunter\",\"password\":\"HunterPortal@2026!Pass\"}'

$cookieVal = ""
foreach ($line in ($loginResp -split "`r?`n")) {
    if ($line -match "set-cookie:\s*ghp_session=([^;]+)") {
        $cookieVal = $matches[1]
        break
    }
}

if (-not $cookieVal) {
    Write-Error "Falha ao obter cookie de sessão do portal."
    exit 1
}
Write-Host "Autenticado com sucesso no portal."

# 3. Iniciar Edge Headless com porta de depuração remota
$edgeProfile = Join-Path $env:TEMP "edge-cdp-import-profile"
if (Test-Path $edgeProfile) {
    Remove-Item -Path $edgeProfile -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $edgeProfile -Force | Out-Null

$edgeExe = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$edgeArgs = @(
    "--headless=new",
    "--remote-debugging-port=9222",
    "--remote-allow-origins=*",
    "--user-data-dir=$edgeProfile",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1600,1200",
    "about:blank"
)

$edgeProc = Start-Process -FilePath $edgeExe -ArgumentList $edgeArgs -PassThru
Write-Host "Processo Edge iniciado (PID: $($edgeProc.Id))."

try {
    # Aguarda o endpoint CDP responder
    $cdpReady = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $ver = curl.exe -s http://127.0.0.1:9222/json/version
            if ($ver -and ($ver | ConvertFrom-Json).webSocketDebuggerUrl) {
                $cdpReady = $true
                break
            }
        } catch {}
    }

    if (-not $cdpReady) {
        Write-Error "Edge CDP não respondeu na porta 9222."
        exit 1
    }

    # Obter aba ativa
    $tabs = curl.exe -s http://127.0.0.1:9222/json/list | ConvertFrom-Json
    $tab = $tabs | Where-Object { $_.type -eq "page" } | Select-Object -First 1
    if (-not $tab) {
        $tab = (curl.exe -s -X PUT http://127.0.0.1:9222/json/new | ConvertFrom-Json)
    }

    $wsUrl = $tab.webSocketDebuggerUrl
    Write-Host "Conectando ao WebSocket do CDP ($wsUrl)..."

    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    $cts = New-Object System.Threading.CancellationTokenSource(10000)
    $ws.ConnectAsync([System.Uri]$wsUrl, $cts.Token).Wait()

    $cmdCounter = 0

    function Exec-CDP($method, $params = @{}) {
        $script:cmdCounter++
        $id = $script:cmdCounter
        $payload = @{
            id = $id
            method = $method
            params = $params
        } | ConvertTo-Json -Depth 10 -Compress

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $ws.SendAsync(
            (New-Object System.ArraySegment[byte] -ArgumentList @(,$bytes)),
            [System.Net.WebSockets.WebSocketMessageType]::Text,
            $true,
            [System.Threading.CancellationToken]::None
        ).Wait()

        $timeout = [System.DateTime]::UtcNow.AddSeconds(15)
        while ([System.DateTime]::UtcNow -lt $timeout) {
            $buffer = New-Object byte[] 2097152
            $ms = New-Object System.IO.MemoryStream
            do {
                $seg = New-Object System.ArraySegment[byte] -ArgumentList @(,$buffer)
                $res = $ws.ReceiveAsync($seg, [System.Threading.CancellationToken]::None).Result
                $ms.Write($buffer, 0, $res.Count)
            } while (-not $res.EndOfMessage)

            $ms.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
            $reader = New-Object System.IO.StreamReader($ms, [System.Text.Encoding]::UTF8)
            $text = $reader.ReadToEnd()
            try {
                $parsed = $text | ConvertFrom-Json
                if ($parsed.id -eq $id) {
                    return $parsed
                }
            } catch {}
        }
        return $null
    }

    # Habilitar Network e Page
    Exec-CDP "Network.enable" | Out-Null
    Exec-CDP "Page.enable" | Out-Null
    Exec-CDP "DOM.enable" | Out-Null

    # Injetar cookie de autenticação
    $cookieParams = @{
        name = "ghp_session"
        value = $cookieVal
        domain = "localhost"
        path = "/"
        httpOnly = $true
    }
    Exec-CDP "Network.setCookie" $cookieParams | Out-Null
    Write-Host "Cookie de sessão configurado."

    # Navegar para /rules
    Write-Host "Navegando para http://localhost:8080/rules..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/rules" } | Out-Null
    Start-Sleep -Seconds 3

    # Clicar no botão 'Importar Regras'
    $clickCode = @"
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const importBtn = btns.find(b => b.textContent && b.textContent.includes('Importar Regras'));
    if (importBtn) {
        importBtn.click();
        return 'aberto';
    }
    return 'botao_nao_encontrado';
})()
"@
    $resModal = Exec-CDP "Runtime.evaluate" @{ expression = $clickCode }
    Write-Host "Abertura do modal: $($resModal.result.value)"
    Start-Sleep -Seconds 1

    # Injetar arquivos via DOM.setFileInputFiles
    $doc = Exec-CDP "DOM.getDocument"
    $rootNodeId = $doc.result.root.nodeId
    $queryRes = Exec-CDP "DOM.querySelector" @{ nodeId = $rootNodeId; selector = "input[type='file']" }
    $fileInputNodeId = $queryRes.result.nodeId

    $testFiles = @($adYamlPath, $fortigateJsonPath)
    Write-Host "Injetando arquivos de teste: $($testFiles -join ', ')..."
    Exec-CDP "DOM.setFileInputFiles" @{
        nodeId = $fileInputNodeId
        files = $testFiles
    } | Out-Null

    # Aguardar leitura automática dos arquivos e preview com curadoria / IA
    Write-Host "Aguardando leitura automática, análise de compatibilidade e parecer técnico de IA..."
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        $checkCards = @"
(() => {
    return Array.from(document.querySelectorAll('button')).some(b => b.textContent && b.textContent.includes('Parecer IA'));
})()
"@
        $resCheck = Exec-CDP "Runtime.evaluate" @{ expression = $checkCards }
        if ($resCheck.result.value -eq $true) {
            Write-Host "Regras validadas e botões de Parecer IA visíveis na tela!"
            break
        }
    }
    Start-Sleep -Seconds 1

    # Clicar no botão 'Parecer IA' da primeira regra para emitir o parecer sob demanda
    $aiClickCode = @"
(() => {
    const aiBtns = Array.from(document.querySelectorAll('button')).filter(b => b.textContent && b.textContent.includes('Parecer IA'));
    if (aiBtns.length > 0) {
        aiBtns[0].click();
        return 'clicado_parecer_ia';
    }
    return 'botao_ia_nao_encontrado';
})()
"@
    $resAiClick = Exec-CDP "Runtime.evaluate" @{ expression = $aiClickCode }
    Write-Host "Clique no botão 3 estrelinhas (Parecer IA): $($resAiClick.result.value)"

    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Seconds 1
        $checkDone = @"
(() => {
    return Array.from(document.querySelectorAll('button')).some(b => b.textContent && b.textContent.includes('Parecer IA ✓'));
})()
"@
        $resDone = Exec-CDP "Runtime.evaluate" @{ expression = $checkDone }
        if ($resDone.result.value -eq $true) {
            Write-Host "Parecer por IA gerado e visualizado com sucesso!"
            break
        }
    }
    Start-Sleep -Seconds 1

    # Expandir primeira regra se necessário
    $expandCode = @"
(() => {
    // Garante que o painel da primeira regra esteja expandido
    const detailsButtons = Array.from(document.querySelectorAll('button')).filter(b => b.textContent && (b.textContent.includes('Parecer IA') || b.textContent.includes('Detalhes')));
    if (detailsButtons.length > 0) {
        detailsButtons[0].click();
    }
    return 'expandido';
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $expandCode } | Out-Null
    Start-Sleep -Milliseconds 800

    # Definir viewport para tela cheia e capturar modal completo
    Exec-CDP "Emulation.setDeviceMetricsOverride" @{
        width = 1600
        height = 1200
        deviceScaleFactor = 1
        mobile = $false
    } | Out-Null

    # Capturar screenshot 1: Visão Geral com Dashboard de Curadoria e regras
    Write-Host "Capturando screenshot 1 (Modal de Importação com Métricas de Curadoria)..."
    $screenshotRes1 = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $base64_1 = $screenshotRes1.result.data
    if ($base64_1) {
        $rawBytes1 = [System.Convert]::FromBase64String($base64_1)
        $targetPath1 = [System.IO.Path]::GetFullPath($OutputFile1)
        [System.IO.File]::WriteAllBytes($targetPath1, $rawBytes1)
        Write-Host "Screenshot 1 salvo com sucesso em $targetPath1 ($($rawBytes1.Length) bytes)."
    }

    # Rolar para focar no Parecer Técnico por IA e na Matriz de Compatibilidade de Campos
    $scrollCode = @"
(() => {
    const modalContent = document.querySelector('.modal-content') || document.querySelector('[class*="Modal"]') || document.querySelector('[class*="max-h"]');
    if (modalContent) {
        modalContent.scrollTop = 380;
    }
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $scrollCode } | Out-Null
    Start-Sleep -Milliseconds 600

    # Capturar screenshot 2: Parecer Técnico da IA e Detalhes dos Campos
    Write-Host "Capturando screenshot 2 (Parecer Técnico de IA e Compatibilidade de Campos)..."
    $screenshotRes2 = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $base64_2 = $screenshotRes2.result.data
    if ($base64_2) {
        $rawBytes2 = [System.Convert]::FromBase64String($base64_2)
        $targetPath2 = [System.IO.Path]::GetFullPath($OutputFile2)
        [System.IO.File]::WriteAllBytes($targetPath2, $rawBytes2)
        Write-Host "Screenshot 2 salvo com sucesso em $targetPath2 ($($rawBytes2.Length) bytes)."
    }

    $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "done", [System.Threading.CancellationToken]::None).Wait()
} finally {
    if ($edgeProc -and -not $edgeProc.HasExited) {
        Stop-Process -Id $edgeProc.Id -Force -ErrorAction SilentlyContinue
    }
    # Limpar pasta temporária de demo
    Remove-Item -Path $demoDir -Recurse -Force -ErrorAction SilentlyContinue
}
