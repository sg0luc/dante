param(
    [string]$OutputRuleDetail = "docs/screenshots/29-rule-detail-grafana-blocks-and-ai.png"
)

Write-Host "Iniciando captura de tela automatizada D.A.N.T.E. (Pop-up Amplo: Blocos Grafana A, B, C & Parecer IA)..."

# 1. Obter cookie de autenticação do portal via backend container
$pyOneLiner = "import http.cookiejar, urllib.request, json, os; jar = http.cookiejar.CookieJar(); opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)); req = urllib.request.Request('http://127.0.0.1:8000/api/auth/login', data=json.dumps({'username': os.environ.get('PORTAL_ADMIN_USER', 'hunter'), 'password': os.environ.get('PORTAL_ADMIN_PASSWORD', '')}).encode(), headers={'Content-Type': 'application/json', 'X-Requested-With': 'hunter-portal'}); opener.open(req); print(next(c.value for c in jar if c.name == 'ghp_session'))"
$cookieVal = (docker exec dante-backend python -c $pyOneLiner).Trim()

if (-not $cookieVal) {
    Write-Error "Falha ao obter cookie de sessão."
    exit 1
}
Write-Host "Autenticado com sucesso no portal."

# 2. Iniciar Edge Headless com resolução de 1800x1100
$edgeProfile = "C:\tmp\edge-cdp-profile-rule-modal"
if (Test-Path $edgeProfile) {
    Remove-Item -Path $edgeProfile -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $edgeProfile -Force | Out-Null

$edgeExe = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$edgeArgs = @(
    "--headless=new",
    "--remote-debugging-port=9226",
    "--remote-allow-origins=*",
    "--user-data-dir=$edgeProfile",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1800,1100",
    "about:blank"
)

$edgeProc = Start-Process -FilePath $edgeExe -ArgumentList $edgeArgs -PassThru
Write-Host "Processo Edge iniciado (PID: $($edgeProc.Id))."

try {
    $cdpReady = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $ver = curl.exe -s http://127.0.0.1:9226/json/version
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

    $tabs = curl.exe -s http://127.0.0.1:9226/json/list | ConvertFrom-Json
    $tab = $tabs | Where-Object { $_.type -eq "page" } | Select-Object -First 1
    if (-not $tab) {
        $tab = (curl.exe -s -X PUT http://127.0.0.1:9226/json/new | ConvertFrom-Json)
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

        $timeout = [System.DateTime]::UtcNow.AddSeconds(12)
        while ([System.DateTime]::UtcNow -lt $timeout) {
            $buffer = New-Object byte[] 4194304
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

    Write-Host "Navegando para /rules..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/rules" } | Out-Null
    Start-Sleep -Seconds 4

    # Clica na regra NTDS ou na primeira regra na tabela para abrir o pop-up de detalhes
    Write-Host "Abrindo pop-up de detalhes da regra..."
    Exec-CDP "Runtime.evaluate" @{
        expression = @"
(() => {
    // Procura linha com NTDS ou primeira linha
    const rows = Array.from(document.querySelectorAll('tbody tr'));
    const targetRow = rows.find(r => r.innerText.toLowerCase().includes('ntdsutil')) || rows[0];
    if (targetRow) {
        const ruleTitle = targetRow.querySelector('button');
        if (ruleTitle) {
            ruleTitle.click();
            return 'clicked_title_button';
        }
        targetRow.click();
        return 'clicked_row';
    }
    return 'no_rows_found';
})()
"@
    } | Out-Null

    # Aguarda a conclusao da avaliacao da IA (quando nao ha mais o spinner de progresso ou ate 18s)
    Write-Host "Aguardando conclusao da avaliacao da IA..."
    for ($waitCount = 0; $waitCount -lt 15; $waitCount++) {
        Start-Sleep -Seconds 1
        $evalDone = Exec-CDP "Runtime.evaluate" @{
            expression = "document.body.innerText.includes('Veredito') || document.body.innerText.includes('Telemetria Real');"
        }
        if ($evalDone -and $evalDone.result -and $evalDone.result.value -eq $true) {
            Write-Host "Avaliacao da IA concluida!"
            break
        }
    }
    Start-Sleep -Seconds 1
    Take-Screenshot $OutputRuleDetail

    # Scroll para capturar a seção de implementação com o botão 'Implementar Sugestões'
    Write-Host "Rolando modal para capturar o botão de implementação..."
    Exec-CDP "Runtime.evaluate" @{
        expression = @"
(() => {
    const modalContent = document.querySelector('.modal-content');
    if (modalContent) {
        modalContent.scrollTop = modalContent.scrollHeight;
        return 'scrolled_modal_content';
    }
    const modalBody = document.querySelector('.modal-body');
    if (modalBody) {
        modalBody.scrollTop = modalBody.scrollHeight;
        return 'scrolled_modal_body';
    }
    window.scrollTo(0, document.body.scrollHeight);
    return 'scrolled_window';
})()
"@
    } | Out-Null
    Start-Sleep -Seconds 1
    Take-Screenshot "docs/screenshots/31-rule-ai-evaluation-implement-button.png"

    Write-Host "Captura do modal concluída com sucesso!"
} finally {
    if ($edgeProc -and -not $edgeProc.HasExited) {
        Stop-Process -Id $edgeProc.Id -Force -ErrorAction SilentlyContinue
    }
}
