param(
    [string]$OutputFile = "docs/screenshots/23-sidebar-logo-authenticated.png"
)

Write-Host "Iniciando captura de tela autenticada para validar a Logo D.A.N.T.E. na Sidebar..."

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
$edgeProfile = "C:\tmp\edge-cdp-profile-sidebar-logo-fix"
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
    Start-Sleep -Seconds 3

    $targetsJson = Invoke-RestMethod -Uri "http://localhost:9222/json"
    $target = $targetsJson | Where-Object { $_.type -eq "page" } | Select-Object -First 1

    if (-not $target) {
        throw "Nenhum alvo de página encontrado no Edge CDP."
    }

    $wsUrl = $target.webSocketDebuggerUrl
    Write-Host "Conectando ao WebSocket CDP: $wsUrl"

    $ws = [System.Net.WebSockets.ClientWebSocket]::new()
    $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(15))
    $ws.ConnectAsync([Uri]$wsUrl, $cts.Token).Wait()

    $script:msgId = 1
    function Exec-CDP([string]$method, [hashtable]$params = @{}) {
        $id = $script:msgId++
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

    # Injeta cookie de autenticação
    $cookieParams = @{
        name = "ghp_session"
        value = $cookieVal
        domain = "localhost"
        path = "/"
        httpOnly = $true
    }
    Exec-CDP "Network.setCookie" $cookieParams | Out-Null
    Write-Host "Cookie configurado com sucesso."

    # Navega para a home (Visão Geral)
    Write-Host "Navegando para http://localhost:8080/..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/" } | Out-Null
    Start-Sleep -Seconds 5

    # Captura screenshot
    Write-Host "Capturando screenshot da tela autenticada..."
    $screenshotRes = Exec-CDP "Page.captureScreenshot" @{ format = "png" }

    if ($screenshotRes.result.data) {
        $imageBytes = [Convert]::FromBase64String($screenshotRes.result.data)
        $outDir = [System.IO.Path]::GetDirectoryName((Resolve-Path .).Path + "/" + $OutputFile)
        if (-not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }
        [System.IO.File]::WriteAllBytes($OutputFile, $imageBytes)
        Write-Host "Screenshot salvo com sucesso em: $OutputFile"
    } else {
        throw "Falha ao obter dados base64 do screenshot."
    }

    $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Done", [System.Threading.CancellationToken]::None).Wait()
}
finally {
    if ($edgeProc -and -not $edgeProc.HasExited) {
        Stop-Process -Id $edgeProc.Id -Force -ErrorAction SilentlyContinue
    }
}

