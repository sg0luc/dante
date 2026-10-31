param(
    [string]$OutputPage = "docs/screenshots/17-curadoria-page.png",
    [string]$OutputTable = "docs/screenshots/21-curadoria-table.png",
    [string]$OutputModal = "docs/screenshots/18-curadoria-implement-modal.png",
    [string]$OutputConfirm = "docs/screenshots/19-curadoria-implement-confirm.png",
    [string]$OutputCompleteView = "docs/screenshots/20-curadoria-complete-view-modal.png",
    [string]$OutputAIModal = "docs/screenshots/22-curadoria-ai-modal.png",
    [string]$OutputClearConfirm = "docs/screenshots/23-curadoria-clear-confirm.png"
)

Write-Host "Iniciando captura de tela automatizada da página de Curadoria..."

# 1. Obter cookie de autenticação do portal via backend container
$pyOneLiner = "import http.cookiejar, urllib.request, json, os; jar = http.cookiejar.CookieJar(); opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)); req = urllib.request.Request('http://127.0.0.1:8000/api/auth/login', data=json.dumps({'username': os.environ.get('PORTAL_ADMIN_USER', 'hunter'), 'password': os.environ.get('PORTAL_ADMIN_PASSWORD', '')}).encode(), headers={'Content-Type': 'application/json', 'X-Requested-With': 'hunter-portal'}); opener.open(req); print(next(c.value for c in jar if c.name == 'ghp_session'))"
$cookieVal = (docker exec dante-backend python -c $pyOneLiner).Trim()

if (-not $cookieVal) {
    Write-Error "Falha ao obter cookie de sessão."
    exit 1
}
Write-Host "Autenticado com sucesso no portal."

# 2. Iniciar Edge Headless com porta de depuração remota
$edgeProfile = "C:\tmp\edge-cdp-profile-curadoria"
if (Test-Path $edgeProfile) {
    Remove-Item -Path $edgeProfile -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $edgeProfile -Force | Out-Null

$edgeExe = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$edgeArgs = @(
    "--headless=new",
    "--remote-debugging-port=9224",
    "--remote-allow-origins=*",
    "--user-data-dir=$edgeProfile",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1500,1200",
    "about:blank"
)

$edgeProc = Start-Process -FilePath $edgeExe -ArgumentList $edgeArgs -PassThru
Write-Host "Processo Edge iniciado (PID: $($edgeProc.Id))."

try {
    $cdpReady = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $ver = curl.exe -s http://127.0.0.1:9224/json/version
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

    $tabs = curl.exe -s http://127.0.0.1:9224/json/list | ConvertFrom-Json
    $tab = $tabs | Where-Object { $_.type -eq "page" } | Select-Object -First 1
    if (-not $tab) {
        $tab = (curl.exe -s -X PUT http://127.0.0.1:9224/json/new | ConvertFrom-Json)
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

    $cookieParams = @{
        name = "ghp_session"
        value = $cookieVal
        domain = "localhost"
        path = "/"
        httpOnly = $true
    }
    Exec-CDP "Network.setCookie" $cookieParams | Out-Null
    Write-Host "Cookie de sessão configurado."

    Write-Host "Navegando para http://localhost:8080/curadoria ..."
    Exec-CDP "Page.navigate" @{ url = "http://localhost:8080/curadoria" } | Out-Null

    Start-Sleep -Seconds 4

    # 1. Capturar página de Curadoria
    Write-Host "Capturando screenshot da página de Curadoria..."
    $shotPage = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64Page = $shotPage.result.data
    if ($b64Page) {
        $bytes = [System.Convert]::FromBase64String($b64Page)
        [System.IO.File]::WriteAllBytes($OutputPage, $bytes)
        Write-Host "Screenshot da página salvo em: $OutputPage"
    }

    # 1.1. Abrir Modal de Configurações de IA
    Write-Host "Clicando em 'Configurar IA'..."
    $clickAI = @"
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const aiBtn = btns.find(b => b.textContent.includes('Configurar IA'));
    if (aiBtn) {
        aiBtn.click();
        return 'clicado';
    }
    return 'nao encontrado';
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $clickAI } | Out-Null
    Start-Sleep -Seconds 2

    Write-Host "Capturando screenshot do modal de Configurações de IA..."
    $shotAI = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64AI = $shotAI.result.data
    if ($b64AI) {
        $bytes = [System.Convert]::FromBase64String($b64AI)
        [System.IO.File]::WriteAllBytes($OutputAIModal, $bytes)
        Write-Host "Screenshot do modal de IA salvo em: $OutputAIModal"
    }

    # Fechar Modal de IA
    $closeAI = @"
(() => {
    const closeBtn = document.querySelector('.modal-close');
    if (closeBtn) {
        closeBtn.click();
        return 'fechado';
    }
    return 'nao encontrado';
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $closeAI } | Out-Null
    Start-Sleep -Seconds 1

    # 1.15. Abrir ConfirmModal de Limpar Curadoria
    Write-Host "Clicando em 'Limpar Curadoria' para abrir ConfirmModal..."
    $clickClear = @"
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const clearBtn = btns.find(b => b.textContent.includes('Limpar Curadoria'));
    if (clearBtn) {
        clearBtn.click();
        return 'clicado';
    }
    return 'nao encontrado';
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $clickClear } | Out-Null
    Start-Sleep -Seconds 2

    Write-Host "Capturando screenshot do ConfirmModal de Limpar Curadoria..."
    $shotClear = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64Clear = $shotClear.result.data
    if ($b64Clear) {
        $bytes = [System.Convert]::FromBase64String($b64Clear)
        [System.IO.File]::WriteAllBytes($OutputClearConfirm, $bytes)
        Write-Host "Screenshot do ConfirmModal de limpeza salvo em: $OutputClearConfirm"
    }

    # Fechar / Cancelar ConfirmModal de Limpeza
    $cancelClear = @"
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const cancelBtn = btns.find(b => b.textContent.includes('Cancelar'));
    if (cancelBtn) {
        cancelBtn.click();
        return 'cancelado';
    }
    return 'nao encontrado';
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $cancelClear } | Out-Null
    Start-Sleep -Seconds 1

    # 1.2. Scrollar para a tabela e capturar
    Write-Host "Scrollando para a tabela de regras..."
    Exec-CDP "Runtime.evaluate" @{ expression = "window.scrollTo(0, 680)" } | Out-Null
    Start-Sleep -Milliseconds 600
    $shotTable = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64Table = $shotTable.result.data
    if ($b64Table) {
        $bytes = [System.Convert]::FromBase64String($b64Table)
        [System.IO.File]::WriteAllBytes($OutputTable, $bytes)
        Write-Host "Screenshot da tabela salvo em: $OutputTable"
    }
    Exec-CDP "Runtime.evaluate" @{ expression = "window.scrollTo(0, 0)" } | Out-Null
    Start-Sleep -Milliseconds 400

    # 1.5. Clicar na primeira linha da tabela para abrir a Visualização Completa da Regra Curada
    Write-Host "Clicando na primeira linha da tabela para abrir a Visualização Completa..."
    $clickRow = @"
(() => {
    const row = document.querySelector('tbody tr');
    if (row) {
        row.click();
        return 'clicado';
    }
    return 'nao encontrado';
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $clickRow } | Out-Null
    Start-Sleep -Seconds 2

    Write-Host "Capturando screenshot da Visualização Completa da Regra Curada..."
    $shotComplete = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64Complete = $shotComplete.result.data
    if ($b64Complete) {
        $bytes = [System.Convert]::FromBase64String($b64Complete)
        [System.IO.File]::WriteAllBytes($OutputCompleteView, $bytes)
        Write-Host "Screenshot da visualização completa salvo em: $OutputCompleteView"
    }

    # Fechar o modal de Visualização Completa
    $closeModal = @"
(() => {
    const closeBtn = document.querySelector('.modal-close');
    if (closeBtn) {
        closeBtn.click();
        return 'fechado';
    }
    return 'nao encontrado';
})()
"@
    Exec-CDP "Runtime.evaluate" @{ expression = $closeModal } | Out-Null
    Start-Sleep -Seconds 1

    # 2. Clicar no primeiro botão 'Implementar'
    Write-Host "Clicando no botão 'Implementar'..."
    $clickImpl = @"
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const implBtn = btns.find(b => b.textContent.trim() === 'Implementar' && !b.disabled);
    if (implBtn) {
        implBtn.click();
        return 'clicado';
    }
    return 'nao encontrado';
})()
"@
    $resImpl = Exec-CDP "Runtime.evaluate" @{ expression = $clickImpl }
    Write-Host "Resultado clique Implementar: $($resImpl.result.value)"
    Start-Sleep -Seconds 2

    # Capturar modal de Implementação
    Write-Host "Capturando screenshot do modal Implementar..."
    $shotModal = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64Modal = $shotModal.result.data
    if ($b64Modal) {
        $bytes = [System.Convert]::FromBase64String($b64Modal)
        [System.IO.File]::WriteAllBytes($OutputModal, $bytes)
        Write-Host "Screenshot do modal salvo em: $OutputModal"
    }

    # 3. Clicar em 'Avançar para Confirmação' para abrir o ConfirmModal
    Write-Host "Clicando em 'Avançar para Confirmação'..."
    $clickConfirm = @"
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const nextBtn = btns.find(b => b.textContent.includes('Prosseguir para') && !b.disabled);
    if (nextBtn) {
        nextBtn.click();
        return 'clicado';
    }
    return 'nao encontrado';
})()
"@
    $resConfirm = Exec-CDP "Runtime.evaluate" @{ expression = $clickConfirm }
    Write-Host "Resultado clique ConfirmModal: $($resConfirm.result.value)"
    Start-Sleep -Seconds 2

    # Capturar ConfirmModal
    Write-Host "Capturando screenshot do ConfirmModal..."
    $shotConfirm = Exec-CDP "Page.captureScreenshot" @{ format = "png" }
    $b64Confirm = $shotConfirm.result.data
    if ($b64Confirm) {
        $bytes = [System.Convert]::FromBase64String($b64Confirm)
        [System.IO.File]::WriteAllBytes($OutputConfirm, $bytes)
        Write-Host "Screenshot do ConfirmModal salvo em: $OutputConfirm"
    }

    Write-Host "Capturas da Curadoria concluídas com sucesso!"

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
