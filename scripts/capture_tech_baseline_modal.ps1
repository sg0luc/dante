param(
    [string]$OutputFile = "docs/screenshots/14-technologies-implement-baseline.png"
)

Write-Host "Iniciando captura de tela automatizada da tela Tecnologias..."

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
$edgeProfile = "C:\tmp\edge-cdp-profile-tech"
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

    # Navegar para /technologies
    Write-Host "Navegando para http://localhost:8080/technologies..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/technologies" } | Out-Null
    Start-Sleep -Seconds 3

    # Definir viewport
    Exec-CDP "Emulation.setDeviceMetricsOverride" @{
        width = 1440
        height = 960
        deviceScaleFactor = 1
        mobile = $false
    } | Out-Null

    # Clicar no botão 'Implementar baseline' de alguma tecnologia com regras
    Write-Host "Abrindo modal de implementação de baseline..."
    $clickScript = @"
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const implBtn = btns.find(b => b.textContent && b.textContent.includes('Implementar baseline'));
    if (implBtn) {
        implBtn.click();
        return true;
    }
    return false;
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $clickScript } | Out-Null
    Start-Sleep -Milliseconds 1500

    Write-Host "Capturando screenshot do modal de configuração com seletor de evaluation group..."
    $screenshotRes = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $base64 = $screenshotRes.result.data
    if ($base64) {
        $rawBytes = [System.Convert]::FromBase64String($base64)
        $targetPath = [System.IO.Path]::GetFullPath($OutputFile)
        $dir = [System.IO.Path]::GetDirectoryName($targetPath)
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        [System.IO.File]::WriteAllBytes($targetPath, $rawBytes)
        Write-Host "Screenshot do seletor de evaluation group salvo com sucesso em $targetPath."
    }

    # Clicar no botão 'Revisar e implementar' para abrir a confirmação
    $reviewScript = @"
(() => {
    const btns = Array.from(document.querySelectorAll('.modal-footer button, button.btn-primary'));
    const revBtn = btns.find(b => b.textContent && b.textContent.includes('Revisar e implementar'));
    if (revBtn && !revBtn.disabled) {
        revBtn.click();
        return true;
    }
    return false;
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $reviewScript } | Out-Null
    Start-Sleep -Milliseconds 1500

    Write-Host "Capturando screenshot do modal de confirmação..."
    $screenshotRes2 = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $base64_2 = $screenshotRes2.result.data
    if ($base64_2) {
        $rawBytes2 = [System.Convert]::FromBase64String($base64_2)
        $confirmPath = [System.IO.Path]::Combine((Split-Path $OutputFile), "15-technologies-implement-baseline-confirm.png")
        $targetPath2 = [System.IO.Path]::GetFullPath($confirmPath)
        [System.IO.File]::WriteAllBytes($targetPath2, $rawBytes2)
        Write-Host "Screenshot da confirmação salvo com sucesso em $targetPath2."
    }

} finally {
    if ($edgeProc -and -not $edgeProc.HasExited) {
        Stop-Process -Id $edgeProc.Id -Force -ErrorAction SilentlyContinue
    }
}
