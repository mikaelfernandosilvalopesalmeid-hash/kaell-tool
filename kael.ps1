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
    Set-Service SysMain -StartupType Disabled

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
        "0" { exit }
        default {
            Write-Host "Opção inválida!" -ForegroundColor Red
            Start-Sleep 1
        }
    }

} while ($true)
