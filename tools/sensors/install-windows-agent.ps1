#Requires -RunAsAdministrator
param([string]$Manager = '100.99.80.84')
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$resultPath = Join-Path $taskRoot '.artifacts/windows-agent-result.json'
try {
    $installer = Join-Path $taskRoot 'wazuh/wazuh-agent-4.14.5-1.msi'
    if ((Get-AuthenticodeSignature -LiteralPath $installer).Status -ne 'Valid') {
        throw 'Wazuh MSI signature did not validate; installation stopped.'
    }
    if (-not (Get-Service WazuhSvc -ErrorAction SilentlyContinue)) {
        $arguments = '/i "' + $installer + '" /qn /norestart WAZUH_MANAGER="' + $Manager + '" WAZUH_REGISTRATION_SERVER="' + $Manager + '" WAZUH_AGENT_NAME="llm-server-windows" /l*v "' + (Join-Path $taskRoot '.artifacts/wazuh-install.log') + '"'
        $process = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -notin @(0, 3010)) { throw "Wazuh installer exited $($process.ExitCode)" }
    }
    $configPath = 'C:/Program Files (x86)/ossec-agent/ossec.conf'
    $config = Get-Content -LiteralPath $configPath -Raw
    if (-not $config.Contains('C:\ProgramData\EdgeGuard\edr-self-test')) {
        Copy-Item -LiteralPath $configPath -Destination ($configPath + '.pre-edgeguard') -ErrorAction Stop
        New-Item -ItemType Directory -Path 'C:/ProgramData/EdgeGuard/edr-self-test' -Force | Out-Null
        $config = $config.Replace('<syscheck>', '<syscheck>' + [Environment]::NewLine + '    <directories realtime="yes" check_all="yes">C:\ProgramData\EdgeGuard\edr-self-test</directories>')
        [IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))
    }
    Restart-Service WazuhSvc
    @{ ok = $true; service = (Get-Service WazuhSvc).Status.ToString(); manager = $Manager } | ConvertTo-Json | Set-Content -LiteralPath $resultPath
} catch {
    @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json | Set-Content -LiteralPath $resultPath
    exit 1
}
