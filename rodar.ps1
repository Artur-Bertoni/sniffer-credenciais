param(
    [ValidateSet("http", "https", "selftest")]
    [string]$Modo = "selftest",
    [int]$Porta = 8000,
    [string]$IP = "",
    [string]$Iface = "\Device\NPF_Loopback"
)

$ErrorActionPreference = "Continue"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$sniffer = Join-Path $scriptDir "sniffer_credenciais.py"

$python = $null
foreach ($cmd in (Get-Command python -All -ErrorAction SilentlyContinue)) {
    if ($cmd.Source -and $cmd.Source -notlike "*WindowsApps*") { $python = $cmd.Source; break }
}

if (-not $python) {
    $padrao = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    if (Test-Path $padrao) { $python = $padrao }
}

if (-not $python -and (Get-Command py -ErrorAction SilentlyContinue)) { $python = "py" }
if (-not $python) {
    Write-Error "Python nao encontrado. Instale o Python 3 (python.org) e tente de novo."
    exit 1
}
Write-Host "[*] Python: $python"

if ($Modo -ne "selftest") {
    & $python -c "import scapy" 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[*] Instalando scapy..."
        & $python -m pip install scapy
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Falha ao instalar o scapy. Verifique sua conexao/pip."
            exit 1
        }
    } else {
        Write-Host "[*] scapy ja instalado."
    }
}

$argsSniffer = @($sniffer, $Modo)
if ($Modo -ne "selftest") {
    $argsSniffer += @("--port", $Porta)
    if ($Iface) { $argsSniffer += @("--iface", $Iface) }
    if ($IP)    { $argsSniffer += @("--host", $IP) }
}

if ($Modo -eq "selftest") {
    Write-Host "[*] Rodando selftest...`n"
    & $python @argsSniffer
    exit $LASTEXITCODE
}

$ehAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $ehAdmin) {
    Write-Host "[*] Captura exige Administrador. Reabrindo elevado..."
    $passar = "-Modo $Modo -Porta $Porta"
    if ($Iface) { $passar += " -Iface `"$Iface`"" }
    if ($IP)    { $passar += " -IP `"$IP`"" }
    Start-Process powershell -Verb RunAs -ArgumentList `
        "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$($MyInvocation.MyCommand.Path)`"", $passar
    exit 0
}

Write-Host "[*] Rodando captura ($Modo) na porta $Porta...`n"
& $python @argsSniffer
