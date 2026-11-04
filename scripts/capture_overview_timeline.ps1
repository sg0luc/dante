param(
    [string]$OutputFile24h = "docs/screenshots/overview-alerts-timeline-24h.png",
    [string]$OutputFile7d = "docs/screenshots/overview-alerts-timeline-7d.png",
    [string]$OutputFile1h = "docs/screenshots/overview-alerts-timeline-1h.png"
)

Write-Host "Iniciando captura de tela automatizada da Linha do Tempo de Alertas na Visão Geral..."

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
$edgeProfile = "C:\tmp\edge-cdp-profile-overview-timeline"
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
    "--window-size=1440,1600",
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
        Write-Error "CDP do Edge não respondeu em 7.5s."
        exit 1
    }

    # Obter WebSocket URL da página
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
    Exec-CDP "Runtime.enable" | Out-Null

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

    # Navegar para http://localhost:8080/
    Write-Host "Navegando para http://localhost:8080/ (Visão Geral)..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/" } | Out-Null

    # Aguardar renderização completa
    Start-Sleep -Seconds 5

    # 1. Capturar tela 24 horas (padrão)
    Write-Host "Capturando screenshot da Linha do Tempo (24 horas)..."
    $shot24h = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64 = $shot24h.result.data
    if ($b64) {
        $bytes = [System.Convert]::FromBase64String($b64)
        [System.IO.File]::WriteAllBytes($OutputFile24h, $bytes)
        Write-Host "Screenshot 24h salvo com sucesso em: $OutputFile24h"
    }

    # 2. Clicar no botão '7 dias'
    Write-Host "Alternando para janela '7 dias'..."
    $click7d = @"
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const btn7d = btns.find(b => b.textContent.trim() === '7 dias');
    if (btn7d) {
        btn7d.click();
        return 'clicado';
    }
    return 'nao encontrado';
})()
"@
    $res7d = Exec-CDP "Runtime.evaluate" @{ expression = $click7d }
    Write-Host "Resultado clique 7d: $($res7d.result.value)"
    Start-Sleep -Seconds 2

    # Capturar tela 7 dias
    Write-Host "Capturando screenshot da Linha do Tempo (7 dias)..."
    $shot7d = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64_7d = $shot7d.result.data
    if ($b64_7d) {
        $bytes = [System.Convert]::FromBase64String($b64_7d)
        [System.IO.File]::WriteAllBytes($OutputFile7d, $bytes)
        Write-Host "Screenshot 7d salvo com sucesso em: $OutputFile7d"
    }

    # 3. Clicar no botão '1 hora'
    Write-Host "Alternando para janela '1 hora'..."
    $click1h = @"
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const btn1h = btns.find(b => b.textContent.trim() === '1 hora');
    if (btn1h) {
        btn1h.click();
        return 'clicado';
    }
    return 'nao encontrado';
})()
"@
    $res1h = Exec-CDP "Runtime.evaluate" @{ expression = $click1h }
    Write-Host "Resultado clique 1h: $($res1h.result.value)"
    Start-Sleep -Seconds 2

    # Capturar tela 1 hora
    Write-Host "Capturando screenshot da Linha do Tempo (1 hora)..."
    $shot1h = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64_1h = $shot1h.result.data
    if ($b64_1h) {
        $bytes = [System.Convert]::FromBase64String($b64_1h)
        [System.IO.File]::WriteAllBytes($OutputFile1h, $bytes)
        Write-Host "Screenshot 1h salvo com sucesso em: $OutputFile1h"
    }

    # 4. Navegar para a tela de Alertas (/alerts)
    Write-Host "Navegando para http://localhost:8080/alerts (Alertas)..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/alerts" } | Out-Null
    Start-Sleep -Seconds 3

    Write-Host "Capturando screenshot da tela de Alertas (3 caixas redistribuidas)..."
    $shotAlerts = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64_alerts = $shotAlerts.result.data
    if ($b64_alerts) {
        $bytes = [System.Convert]::FromBase64String($b64_alerts)
        [System.IO.File]::WriteAllBytes("docs/screenshots/07-alerts.png", $bytes)
        Write-Host "Screenshot de Alertas salvo com sucesso em: docs/screenshots/07-alerts.png"
    }

    Write-Host "Todas as capturas foram concluidas com sucesso!"

} finally {
    if ($ws -and $ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
        $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "done", [System.Threading.CancellationToken]::None).Wait()
    }
    if ($edgeProc -and -not $edgeProc.HasExited) {
        Stop-Process -Id $edgeProc.Id -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $edgeProfile) {
        Remove-Item -Path $edgeProfile -Recurse -Force -ErrorAction SilentlyContinue
    }
}

