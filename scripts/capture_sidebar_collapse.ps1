param(
    [string]$ExpandedFile = "docs/screenshots/sidebar-expanded.png",
    [string]$CollapsedFile = "docs/screenshots/sidebar-collapsed.png",
    [string]$ReopenedFile = "docs/screenshots/sidebar-reopened.png"
)

Write-Host "Iniciando teste visual e captura de tela para demonstrar adaptacao de layout com menu aberto e colapsado..."

# 1. Obter cookie de autenticacao do portal
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
    Write-Error "Falha ao obter cookie de sessao."
    exit 1
}
Write-Host "Autenticado com sucesso no portal."

# 2. Iniciar Edge Headless com porta de depuracao remota
$edgeProfile = "C:\tmp\edge-cdp-profile-sidebar-collapse"
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
        throw "Nenhum alvo de pagina encontrado no Edge CDP."
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

    function Save-Screenshot([string]$filePath) {
        $res = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
        if ($res.result.data) {
            $bytes = [Convert]::FromBase64String($res.result.data)
            $dir = [System.IO.Path]::GetDirectoryName((Resolve-Path .).Path + "/" + $filePath)
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            [System.IO.File]::WriteAllBytes($filePath, $bytes)
            Write-Host "Screenshot salvo: $filePath"
        } else {
            throw "Falha ao capturar screenshot: dados vazios"
        }
    }

    Exec-CDP "Network.enable" | Out-Null
    Exec-CDP "Page.enable" | Out-Null
    Exec-CDP "Runtime.enable" | Out-Null

    # Injeta cookie de autenticacao
    $cookieParams = @{
        name = "ghp_session"
        value = $cookieVal
        domain = "localhost"
        path = "/"
        httpOnly = $true
    }
    Exec-CDP "Network.setCookie" $cookieParams | Out-Null
    Write-Host "Cookie configurado com sucesso."

    # 1. Navega para a home (Visao Geral) com sidebar aberta
    Write-Host "Navegando para http://localhost:8080/..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/" } | Out-Null
    Start-Sleep -Seconds 4

    Write-Host "1. Capturando tela com menu expandido..."
    Save-Screenshot $ExpandedFile

    # 2. Clicar no botao para colapsar a barra lateral
    Write-Host "2. Clicando no botao para colapsar o menu lateral..."
    $collapseJs = @'
(() => {
    const btn = document.querySelector('button[title*="Recolher"]');
    if (btn) {
        btn.click();
        return 'clicked';
    }
    return 'not found';
})()
'@
    $evalClickCollapse = Exec-CDP "Runtime.evaluate" @{ expression = $collapseJs }
    Write-Host "Resultado do clique de colapso: $($evalClickCollapse.result.value)"
    Start-Sleep -Seconds 2

    Write-Host "Capturando tela com menu colapsado (visualizacoes adaptadas ao espaco extra)..."
    Save-Screenshot $CollapsedFile

    # 3. Clicar no botao para expandir novamente
    Write-Host "3. Clicando no botao para reabrir o menu lateral..."
    $expandJs = @'
(() => {
    const btn = document.querySelector('button[title*="Expandir"]');
    if (btn) {
        btn.click();
        return 'clicked';
    }
    return 'not found';
})()
'@
    $evalClickExpand = Exec-CDP "Runtime.evaluate" @{ expression = $expandJs }
    Write-Host "Resultado do clique de expansao: $($evalClickExpand.result.value)"
    Start-Sleep -Seconds 2

    Write-Host "Capturando tela com menu reaberto (visualizacoes readaptadas)..."
    Save-Screenshot $ReopenedFile

    $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Done", [System.Threading.CancellationToken]::None).Wait()
}
finally {
    if ($edgeProc -and -not $edgeProc.HasExited) {
        Stop-Process -Id $edgeProc.Id -Force -ErrorAction SilentlyContinue
    }
}
