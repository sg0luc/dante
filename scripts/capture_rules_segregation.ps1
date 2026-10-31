param(
    [string]$OutputFile = "docs/screenshots/25-rules-create-client-segregation.png"
)

Write-Host "Iniciando captura de tela da criação de regra com segregação de ambientes..."

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

# 2. Iniciar Edge Headless
$edgeProfile = "C:\tmp\edge-cdp-rules-profile"
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
    "--window-size=1440,1050",
    "about:blank"
)

$edgeProc = Start-Process -FilePath $edgeExe -ArgumentList $edgeArgs -PassThru

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

    $tabs = curl.exe -s http://127.0.0.1:9222/json/list | ConvertFrom-Json
    $tab = $tabs | Where-Object { $_.type -eq "page" } | Select-Object -First 1
    if (-not $tab) {
        $tab = (curl.exe -s -X PUT http://127.0.0.1:9222/json/new | ConvertFrom-Json)
    }

    $wsUrl = $tab.webSocketDebuggerUrl
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

        $timeout = [System.DateTime]::UtcNow.AddSeconds(12)
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
    Exec-CDP "DOM.enable" | Out-Null

    $cookieParams = @{
        name = "ghp_session"
        value = $cookieVal
        domain = "localhost"
        path = "/"
        httpOnly = $true
    }
    Exec-CDP "Network.setCookie" $cookieParams | Out-Null

    # Navegar para /rules
    Write-Host "Navegando para http://localhost:8080/rules..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/rules" } | Out-Null
    Start-Sleep -Seconds 3

    Exec-CDP "Emulation.setDeviceMetricsOverride" @{
        width = 1440
        height = 1050
        deviceScaleFactor = 1
        mobile = $false
    } | Out-Null

    # Abrir modal "Criar Regra"
    $openModalCode = @"
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const btn = btns.find(b => b.textContent && (b.textContent.includes('Criar Regra') || b.textContent.includes('Nova Regra')));
    if (btn) {
        btn.click();
        return 'modal_aberto';
    }
    return 'botao_nao_encontrado';
})()
"@
    $resOpen = Exec-CDP "Runtime.evaluate" @{ expression = $openModalCode }
    Write-Host "Abrindo modal de criar regra: $($resOpen.result.value)"
    Start-Sleep -Seconds 1

    # Interagir no modal: selecionar escopo "Cliente", escolher primeiro cliente, preencher query e clicar em "Validar Logs (Run)"
    $fillAndRunCode = @"
(() => {
    // 1. Clicar no radio Cliente
    const clientRadio = document.querySelector('input[type="radio"][value="client"]');
    if (clientRadio) {
        clientRadio.click();
    }

    // 2. Selecionar o cliente no dropdown
    const selectClient = document.querySelector('select');
    if (selectClient && selectClient.options.length > 1) {
        selectClient.selectedIndex = 1;
        selectClient.dispatchEvent(new Event('change', { bubbles: true }));
    }

    // 3. Clicar no botão Validar Logs (Run)
    const runBtns = Array.from(document.querySelectorAll('button'));
    const runBtn = runBtns.find(b => b.textContent && b.textContent.includes('Validar Logs (Run)'));
    if (runBtn) {
        runBtn.click();
        return 'run_clicado';
    }
    return 'run_nao_encontrado';
})()
"@
    $resRun = Exec-CDP "Runtime.evaluate" @{ expression = $fillAndRunCode }
    Write-Host "Executando ação no modal: $($resRun.result.value)"
    Start-Sleep -Seconds 3

    # Capturar screenshot do modal com resultados segregados
    Write-Host "Capturando screenshot do modal com resultados segregados..."
    $screenshotRes = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $base64 = $screenshotRes.result.data
    if ($base64) {
        $rawBytes = [System.Convert]::FromBase64String($base64)
        $targetPath = [System.IO.Path]::GetFullPath($OutputFile)
        $dir = [System.IO.Path]::GetDirectoryName($targetPath)
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllBytes($targetPath, $rawBytes)
        Write-Host "Screenshot salvo com sucesso em $targetPath ($($rawBytes.Length) bytes)."
    }

    $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "done", [System.Threading.CancellationToken]::None).Wait()
} finally {
    if ($edgeProc -and -not $edgeProc.HasExited) {
        Stop-Process -Id $edgeProc.Id -Force -ErrorAction SilentlyContinue
    }
}

