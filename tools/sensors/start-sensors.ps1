# Boots Ubuntu; enabled systemd services start the IDS, EDR and bridge.
$ErrorActionPreference = 'Stop'
wsl.exe -d Ubuntu -u root -- /bin/true
if ($LASTEXITCODE -ne 0) { throw 'Ubuntu sensor environment did not start' }
