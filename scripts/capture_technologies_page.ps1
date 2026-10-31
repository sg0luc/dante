param(
    [string]$OutputPage = "docs/screenshots/23-technologies-page.png",
    [string]$OutputModal = "docs/screenshots/24-technologies-perimeter-modal.png"
)

Write-Host "Iniciando captura de tela automatizada da página de Tecnologias..."

# 1. Obter cookie de autenticação do portal via backend container
$pyOneLiner = @'
import http.cookiejar, urllib.request, json, os
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
req = urllib.request.Request('http://127.0.0.1:8000/api/auth/login', data=json.dumps({'username': os.environ.get('PORTAL_ADMIN_USER', 'hunter'), 'password': os.environ.get('PORTAL_ADMIN_PASSWORD', '')}).encode(), headers={'Content-Type': 'application/json', 'X-Requested-With': 'hunter-portal'})
opener.open(req)
print(next(c.value for c in jar if c.name == 'ghp_session'))
'@
$cookieVal = ($pyOneLiner | docker exec -i dante-backend python -).Trim()

if (-not $cookieVal) {
    Write-Error "Falha ao obter cookie de sessão."
    exit 1
}
Write-Host "Autenticado com sucesso no portal."

# 2. Iniciar Edge Headless com porta de depuração remota
$edgeProfile = "C:\tmp\edge-cdp-profile-tech-page"
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

    Exec-CDP "Network.setCookie" @{
        name = "ghp_session"
        value = $cookieVal
        domain = "localhost"
        path = "/"
        httpOnly = $true
        secure = $false
        sameSite = "Lax"
    } | Out-Null
    Write-Host "Cookie de sessao configurado."

    Write-Host "Navegando para http://localhost:8080/technologies ..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/technologies" } | Out-Null
    Start-Sleep -Seconds 3

    # Screenshot da página completa
    Write-Host "Capturando screenshot da página de Tecnologias..."
    $ss = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    if ($ss -and $ss.result -and $ss.result.data) {
        $bytes = [System.Convert]::FromBase64String($ss.result.data)
        $dir = Split-Path $OutputPage -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllBytes($OutputPage, $bytes)
        Write-Host "Screenshot da página salvo em: $OutputPage"
    }

    # Clicar em "Nova Tecnologia" para exibir o modal com o Perímetro de Detecção
    Write-Host "Abrindo modal de Nova Tecnologia..."
    $clickEval = Exec-CDP "Runtime.evaluate" @{
        expression = @"
(() => {
    const buttons = Array.from(document.querySelectorAll('button'));
    const btn = buttons.find(b => b.textContent && b.textContent.includes('Nova Tecnologia'));
    if (btn) {
        btn.click();
        return 'clicked';
    }
    return 'not_found';
})()
"@
        returnByValue = $true
    }
    Start-Sleep -Seconds 1

    Write-Host "Capturando screenshot do modal de Tecnologia com Perímetro..."
    $ssModal = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    if ($ssModal -and $ssModal.result -and $ssModal.result.data) {
        $bytes = [System.Convert]::FromBase64String($ssModal.result.data)
        $dir = Split-Path $OutputModal -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllBytes($OutputModal, $bytes)
        Write-Host "Screenshot do modal salvo em: $OutputModal"
    }

    $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Done", [System.Threading.CancellationToken]::None).Wait()
    Write-Host "Capturas de Tecnologias concluídas com sucesso!"
}
finally {
    if ($edgeProc -and -not $edgeProc.HasExited) {
        Stop-Process -Id $edgeProc.Id -Force -ErrorAction SilentlyContinue
    }
}
