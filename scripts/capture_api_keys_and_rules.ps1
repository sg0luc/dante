param(
    [string]$OutputApiKeys = "docs/screenshots/26-api-keys-page.png",
    [string]$OutputCuradoria = "docs/screenshots/27-curadoria-no-ai-btn.png",
    [string]$OutputRulesPaused = "docs/screenshots/28-rules-paused-ai-evaluation.png"
)

Write-Host "Iniciando captura de tela automatizada D.A.N.T.E. (API Keys & Regras Pausadas)..."

# 1. Obter cookie de autenticação do portal via backend container
$pyOneLiner = "import http.cookiejar, urllib.request, json, os; jar = http.cookiejar.CookieJar(); opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)); req = urllib.request.Request('http://127.0.0.1:8000/api/auth/login', data=json.dumps({'username': os.environ.get('PORTAL_ADMIN_USER', 'hunter'), 'password': os.environ.get('PORTAL_ADMIN_PASSWORD', '')}).encode(), headers={'Content-Type': 'application/json', 'X-Requested-With': 'hunter-portal'}); opener.open(req); print(next(c.value for c in jar if c.name == 'ghp_session'))"
$cookieVal = (docker exec dante-backend python -c $pyOneLiner).Trim()

if (-not $cookieVal) {
    Write-Error "Falha ao obter cookie de sessão."
    exit 1
}
Write-Host "Autenticado com sucesso no portal."

# 2. Iniciar Edge Headless com porta de depuração remota
$edgeProfile = "C:\tmp\edge-cdp-profile-apikeys"
if (Test-Path $edgeProfile) {
    Remove-Item -Path $edgeProfile -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $edgeProfile -Force | Out-Null

$edgeExe = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$edgeArgs = @(
    "--headless=new",
    "--remote-debugging-port=9225",
    "--remote-allow-origins=*",
    "--user-data-dir=$edgeProfile",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1500,1100",
    "about:blank"
)

$edgeProc = Start-Process -FilePath $edgeExe -ArgumentList $edgeArgs -PassThru
Write-Host "Processo Edge iniciado (PID: $($edgeProc.Id))."

try {
    $cdpReady = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $ver = curl.exe -s http://127.0.0.1:9225/json/version
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

    $tabs = curl.exe -s http://127.0.0.1:9225/json/list | ConvertFrom-Json
    $tab = $tabs | Where-Object { $_.type -eq "page" } | Select-Object -First 1
    if (-not $tab) {
        $tab = (curl.exe -s -X PUT http://127.0.0.1:9225/json/new | ConvertFrom-Json)
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

    Exec-CDP "Network.enable" | Out-Null
    Exec-CDP "Page.enable" | Out-Null
    Exec-CDP "Runtime.enable" | Out-Null

    # Injetar Cookie ghp_session
    Exec-CDP "Network.setCookie" @{
        name = "ghp_session"
        value = $cookieVal
        domain = "localhost"
        path = "/"
        httpOnly = $true
        sameSite = "Strict"
    } | Out-Null

    function Take-Screenshot($outPath) {
        $parent = Split-Path $outPath -Parent
        if ($parent -and -not (Test-Path $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        $ss = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
        if ($ss -and $ss.result -and $ss.result.data) {
            $bytes = [System.Convert]::FromBase64String($ss.result.data)
            [System.IO.File]::WriteAllBytes($outPath, $bytes)
            Write-Host "Screenshot salvo: $outPath ($($bytes.Length) bytes)"
        } else {
            Write-Warning "Falha ao capturar screenshot para $outPath"
        }
    }

    # 1. Capturar Página de API Keys (/api-keys)
    Write-Host "Navegando para /api-keys..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/api-keys" } | Out-Null
    Start-Sleep -Seconds 3
    Take-Screenshot $OutputApiKeys

    # 2. Capturar Página de Curadoria (/curadoria) comprovando remoção do botão Configurar IA
    Write-Host "Navegando para /curadoria..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/curadoria" } | Out-Null
    Start-Sleep -Seconds 3
    Take-Screenshot $OutputCuradoria

    # 3. Pausar uma regra, navegar para /rules e abrir o parecer técnico com telemetria
    Write-Host "Preparando regra para teste em /rules..."
    # Obter UID da primeira regra
    $rulesJson = curl.exe -s -b .tmp/jar.txt http://localhost:8080/api/rules
    $firstUid = ($rulesJson | ConvertFrom-Json)[0].uid
    curl.exe -s -b .tmp/jar.txt -X POST "http://localhost:8080/api/rules/$firstUid/toggle-pause" -H "Content-Type: application/json" -H "X-Requested-With: hunter-portal" -d '{\"paused\": true}' | Out-Null

    Write-Host "Navegando para /rules..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/rules" } | Out-Null
    Start-Sleep -Seconds 3

    # Clica no botão "Parecer IA" da regra pausada para abrir o modal de detalhes com a avaliação
    Exec-CDP "Runtime.evaluate" @{
        expression = "const btn = Array.from(document.querySelectorAll('button')).find(b => b.textContent.includes('Parecer IA') || b.textContent.includes('Detalhes')); if (btn) btn.click();"
    } | Out-Null
    Start-Sleep -Seconds 4
    Take-Screenshot $OutputRulesPaused

    # Restaura regra
    curl.exe -s -b .tmp/jar.txt -X POST "http://localhost:8080/api/rules/$firstUid/toggle-pause" -H "Content-Type: application/json" -H "X-Requested-With: hunter-portal" -d '{\"paused\": false}' | Out-Null

    Write-Host "Capturas de tela concluídas com sucesso!"
} finally {
    if ($edgeProc -and -not $edgeProc.HasExited) {
        Stop-Process -Id $edgeProc.Id -Force -ErrorAction SilentlyContinue
    }
}

