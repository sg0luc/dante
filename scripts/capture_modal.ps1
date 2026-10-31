param(
    [string]$OutputFile = "docs/screenshots/10-rules-import-modal.png"
)

Write-Host "Iniciando captura de tela automatizada..."

# 1. Obter cookie de autenticação do portal
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
    Write-Error "Falha ao obter cookie de sessão."
    exit 1
}
Write-Host "Autenticado com sucesso no portal."

# 2. Iniciar Edge Headless com porta de depuração remota
$edgeProfile = "C:\tmp\edge-cdp-profile"
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
    "--window-size=1440,960",
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

        $timeout = [System.DateTime]::UtcNow.AddSeconds(10)
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

    # Simular seleção de múltiplos arquivos (.yaml e .json) via CDP DOM.setFileInputFiles
    $doc = Exec-CDP "DOM.getDocument"
    $rootNodeId = $doc.result.root.nodeId
    $queryRes = Exec-CDP "DOM.querySelector" @{ nodeId = $rootNodeId; selector = "input[type='file']" }
    $fileInputNodeId = $queryRes.result.nodeId

    $testFiles = @(
        (Resolve-Path "C:\tmp\demo-files\ad_privilege_escalation.yaml").Path,
        (Resolve-Path "C:\tmp\demo-files\pfsense_firewall.json").Path
    )

    Write-Host "Injetando arquivos via DOM.setFileInputFiles (nodeId: $fileInputNodeId)..."
    Exec-CDP "DOM.setFileInputFiles" @{
        nodeId = $fileInputNodeId
        files = $testFiles
    } | Out-Null

    # Aguardar leitura automática dos arquivos e resposta da validação preview
    Write-Host "Aguardando leitura automática e preview..."
    Start-Sleep -Seconds 3

    # Rolar o container da lista de regras ou a janela para exibir a regra amarela com botão "Criar Tecnologia"
    $scrollCode = @"
(() => {
    const list = document.getElementById('rules-preview-list-container');
    if (list) {
        list.scrollTop = 220;
    }
    const modalContent = document.querySelector('.modal-content') || document.querySelector('[class*="Modal"]');
    if (modalContent) modalContent.scrollTop = 350;
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $scrollCode } | Out-Null
    Start-Sleep -Milliseconds 800

    # Definir viewport com altura suficiente para exibir as regras
    Exec-CDP "Emulation.setDeviceMetricsOverride" @{
        width = 1440
        height = 1100
        deviceScaleFactor = 1
        mobile = $false
    } | Out-Null

    # Capturar screenshot
    Write-Host "Capturando screenshot..."
    $screenshotRes = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $base64 = $screenshotRes.result.data
    if ($base64) {
        $rawBytes = [System.Convert]::FromBase64String($base64)
        $targetPath = [System.IO.Path]::GetFullPath($OutputFile)
        [System.IO.File]::WriteAllBytes($targetPath, $rawBytes)
        Write-Host "Screenshot salvo com sucesso em $targetPath ($($rawBytes.Length) bytes)."
    } else {
        Write-Error "Falha ao capturar dados de screenshot."
    }

    $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "done", [System.Threading.CancellationToken]::None).Wait()
} finally {
    if ($edgeProc -and -not $edgeProc.HasExited) {
        Stop-Process -Id $edgeProc.Id -Force -ErrorAction SilentlyContinue
    }
}
