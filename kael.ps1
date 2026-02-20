Write-Host "Aplicando ajustes..." -ForegroundColor Cyan

Clear-DnsClientCache
netsh winsock reset

Write-Host "Finalizado!" -ForegroundColor Green
