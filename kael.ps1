# ===============================
# KAELL TOOL - POWER VERSION
# ===============================

# 🔥 AUTO ADMIN
if (-not ([Security.Principal.WindowsPrincipal] `
[Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Pause {
    Read-Host "`nPressione ENTER para voltar ao menu"
}

# ===============================
# FIX PING / NETWORK
# ===============================
function FixPing {
    Clear-Host
    Write-Host "Otimizando rede..." -ForegroundColor Yellow
    Clear-DnsClientCache
    netsh winsock reset
    netsh int ip reset
    netsh int ipv6 reset
    ipconfig /flushdns
    Write-Host "`nRede otimizada!" -ForegroundColor Green
    Pause
}

# ===============================
# OTIMIZAÇÕES WINDOWS
# ===============================
function OptimizeWindows {
    Clear-Host
    Write-Host "Aplicando otimizações..." -ForegroundColor Yellow

   Stop-Service SysMain -Force -ErrorAction SilentlyContinue
    Set-Service SysMain -StartupType Disabled -ErrorAction SilentlyContinue

    powercfg -setactive SCHEME_MIN

    Write-Host "`nWindows otimizado!" -ForegroundColor Green
    Pause
}

# ===============================
# PRIORIDADE PARA JOGOS
# ===============================
function OptimizeGames {

    Clear-Host
    Write-Host "Aplicando prioridade alta..." -ForegroundColor Yellow

    $games = @(
        "FortniteClient-Win64-Shipping.exe",
        "VALORANT-Win64-Shipping.exe",
        "cs2.exe"
    )

    foreach ($g in $games) {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$g\PerfOptions"
        New-Item $path -Force | Out-Null
        New-ItemProperty $path CpuPriorityClass -Value 3 -PropertyType DWord -Force | Out-Null
    }

    Write-Host "`nJogos priorizados!" -ForegroundColor Green
    Pause
}

# ===============================
# LIMPEZA DE TEMP
# ===============================
function CleanTemp {
    Clear-Host
    Write-Host "Limpando arquivos temporários..." -ForegroundColor Yellow
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "`nLimpeza concluída!" -ForegroundColor Green
    Pause
}

function DebloatWindows {
    Clear-Host
    Write-Host "Removendo apps desnecessários..." -ForegroundColor Yellow

    Get-AppxPackage *xbox* | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage *bing* | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage *skype* | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage *zune* | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage *solitaire* | Remove-AppxPackage -ErrorAction SilentlyContinue

    Write-Host "`nDebloat concluído!" -ForegroundColor Green
    Pause
}

function DisableTelemetry {

    Clear-Host
    Write-Host "Desativando telemetria..." -ForegroundColor Yellow

    Stop-Service DiagTrack -ErrorAction SilentlyContinue
    Set-Service DiagTrack -StartupType Disabled

    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
    /v AllowTelemetry /t REG_DWORD /d 0 /f

    Write-Host "`nTelemetria desativada!" -ForegroundColor Green
    Pause
}

function ReduceInputLag {

    Clear-Host
    Write-Host "Otimizando latência do sistema..." -ForegroundColor Yellow

    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" `
    /v NetworkThrottlingIndex /t REG_DWORD /d 0xffffffff /f

    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" `
    /v SystemResponsiveness /t REG_DWORD /d 0 /f

    Write-Host "`nInput lag reduzido!" -ForegroundColor Green
    Pause
}

function GamerBoost {

    Clear-Host
    Write-Host "Aplicando modo gamer..." -ForegroundColor Yellow

    powercfg -setactive SCHEME_MIN

    Stop-Service SysMain -ErrorAction SilencedContinue

    reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f

    Write-Host "`nModo gamer ativado!" -ForegroundColor Green
    Pause
}

function CreateRestorePoint {

    Clear-Host
    Write-Host "Criando ponto de restauração..." -ForegroundColor Yellow

    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" `
    /v SystemRestorePointCreationFrequency /t REG_DWORD /d 0 /f | Out-Null

    Checkpoint-Computer -Description "KaellTool Restore" -RestorePointType MODIFY_SETTINGS

    Write-Host "`nBackup criado!" -ForegroundColor Green
    Pause
}

function SafeModeRestore {

    Clear-Host
    Write-Host "Restaurando configurações padrão..." -ForegroundColor Yellow

    powercfg -setactive SCHEME_BALANCED

    Set-Service SysMain -StartupType Automatic
    Start-Service SysMain

    Write-Host "`nSistema restaurado!" -ForegroundColor Green
    Pause
}

function DetectHardware {

    Clear-Host
    Write-Host "Detectando hardware..." -ForegroundColor Yellow

    $cpu = (Get-CimInstance Win32_Processor).Name
    $gpu = (Get-CimInstance Win32_VideoController).Name
    $ram = [math]::round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)

    Write-Host ""
    Write-Host "CPU: $cpu"
    Write-Host "GPU: $gpu"
    Write-Host "RAM: $ram GB"
    Write-Host ""

    Pause
}

function OptimizeGPU {

    $gpu = (Get-CimInstance Win32_VideoController).Name

    if ($gpu -match "NVIDIA|AMD|Radeon|RTX|GTX") {
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" `
        /v HwSchMode /t REG_DWORD /d 2 /f
        Write-Host "GPU compatível → otimização aplicada" -ForegroundColor Green
    }
    else {
        Write-Host "GPU não compatível → ignorado" -ForegroundColor Red
    }

    Pause
}

function GamerAutoMode {

    Clear-Host
    Write-Host "Aplicando modo gamer automático..." -ForegroundColor Yellow

    FixPing | Out-Null
    ReduceInputLag | Out-Null
    OptimizeGames | Out-Null
    OptimizeGPU | Out-Null
    powercfg -setactive SCHEME_MIN

    Write-Host "`nModo gamer automático concluído!" -ForegroundColor Green
    Pause
}

function UpdateTool {

    Clear-Host
    Write-Host "Atualizando ferramenta..." -ForegroundColor Yellow

    $url = "https://raw.githubusercontent.com/mikaelfernandosilvalopesalmeid-hash/kaell-tool/main/kael.ps1"
    
   Invoke-Expression (Invoke-RestMethod $url)

    Write-Host "Atualizado!" -ForegroundColor Green
    Pause
}

# ===============================
# MENU
# ===============================
function ShowMenu {
    Clear-Host
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host "        KAELL TOOL           " -ForegroundColor Cyan
    Write-Host "============================="
    Write-Host ""
    Write-Host "1 - Fix Ping / Rede"
    Write-Host "2 - Otimizar Windows"
    Write-Host "3 - Prioridade para Jogos"
    Write-Host "4 - Limpar Arquivos Temporários"
    Write-Host "5 - Debloat Windows"
    Write-Host "6 - Desativar Telemetria"
    Write-Host "7 - Reduzir Input Lag"
    Write-Host "8 - Modo Gamer Avançado"
    Write-Host "9 - Otimizar GPU"
    Write-Host "10 - Criar Backup do Sistema"
    Write-Host "11 - Restaurar Configurações"
    Write-Host "12 - Detectar Hardware"
    Write-Host "13 - Modo Gamer Automático"
    Write-Host "14 - Atualizar Ferramenta"
    Write-Host "0 - Sair"
    Write-Host ""
}

do {
    ShowMenu
    $op = Read-Host "Escolha"

    switch ($op) {
        "1" { FixPing }
        "2" { OptimizeWindows }
        "3" { OptimizeGames }
        "4" { CleanTemp }
        "5" { DebloatWindows }
        "6" { DisableTelemetry }
        "7" { ReduceInputLag }
        "8" { GamerBoost }
        "9" { OptimizeGPU }
        "10" { CreateRestorePoint }
        "11" { SafeModeRestore }
        "12" { DetectHardware }
        "13" { GamerAutoMode }
        "14" { UpdateTool }
        "0" { exit }
        default {
            Write-Host "Opção inválida!" -ForegroundColor Red
            Start-Sleep 1
        }
    }

} while ($true)


