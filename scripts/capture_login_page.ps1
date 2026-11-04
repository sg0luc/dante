param(
    [string]$OutputFile = "docs/screenshots/22-login-page-redesign.png"
)

Write-Host "Capturando tela de login redesign..."

$edgeProfile = "C:\tmp\edge-cdp-login-profile"
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
    "http://localhost:8080/login"
)

$edgeProc = Start-Process -FilePath $edgeExe -ArgumentList $edgeArgs -PassThru
Write-Host "Processo Edge iniciado (PID: $($edgeProc.Id))."

try {
    Start-Sleep -Seconds 3

    # Obter lista de alvos CDP
    $targetsJson = Invoke-RestMethod -Uri "http://localhost:9222/json"
    $target = $targetsJson | Where-Object { $_.type -eq "page" -and $_.url -like "*login*" } | Select-Object -First 1

    if (-not $target) {
        $target = $targetsJson | Where-Object { $_.type -eq "page" } | Select-Object -First 1
    }

    if (-not $target) {
        throw "Nenhum alvo de página encontrado no Edge CDP."
    }

    $wsUrl = $target.webSocketDebuggerUrl
    Write-Host "Conectando ao WebSocket CDP: $wsUrl"

    $ws = [System.Net.WebSockets.ClientWebSocket]::new()
    $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(15))
    $ws.ConnectAsync([Uri]$wsUrl, $cts.Token).Wait()

    function Send-CdpCommand($ws, [string]$method, [hashtable]$params = @{}, [int]$id = 1) {
        $cmd = @{
            id = $id
            method = $method
            params = $params
        } | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($cmd)
        $segment = [ArraySegment[byte]]::new($bytes)
        $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [System.Threading.CancellationToken]::None).Wait()

        $buffer = [byte[]]::new(4194304)
        $memStream = [System.IO.MemoryStream]::new()
        do {
            $recvSegment = [ArraySegment[byte]]::new($buffer)
            $res = $ws.ReceiveAsync($recvSegment, [System.Threading.CancellationToken]::None).Result
            $memStream.Write($buffer, 0, $res.Count)
        } while (-not $res.EndOfMessage)

        $respJson = [System.Text.Encoding]::UTF8.GetString($memStream.ToArray())
        return ($respJson | ConvertFrom-Json)
    }

    Send-CdpCommand $ws "Page.enable" @{} 1 | Out-Null
    Start-Sleep -Seconds 2

    # Captura screenshot
    Write-Host "Capturando screenshot da tela de Login..."
    $screenshotRes = Send-CdpCommand $ws "Page.captureScreenshot" @{ format = "png" } 2

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

