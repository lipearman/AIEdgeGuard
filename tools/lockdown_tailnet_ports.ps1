# EdgeGuard — force tailnet traffic through the published hostname (EdgeGuard)
#
# Problem: some services publish host ports on the tailnet interface
# (0.0.0.0 / 100.99.80.84). Any device in the tailnet can then reach
# http://llm-server.tail923b9a.ts.net:<port> directly and bypass the
# EdgeGuard hostname path (WAF + Basic auth).
#
# This script blocks inbound TCP from the Tailscale CGNAT range
# (100.64.0.0/10) to those ports. Tailscale Serve ports are NOT in the list
# (443, 10000, 8443, 8445) — they must stay reachable for
# https://llm-server.tail923b9a.ts.net/... to work.
#
# Services covered:
#   3100  forgemind-web          (WAF bypass; use https://...:8443/forgemind)
#   8101  forgemind demo portal  (WAF bypass; use https://...:8443/demo/ or :10000/demo)
#   9000  portal (sanuk-traefik) (WAF bypass; use https://llm-server.../)
#   8085  CrowdSec LAPI          (key-protected, but not needed from tailnet)
#   8086  CrowdSec AppSec        (key-protected)
#
# Port 8099 (edge-ai API) is already bound to 127.0.0.1 in
# edge-ai/docker-compose.yml — no firewall rule needed for it.
#
# Usage (must be an elevated PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\lockdown_tailnet_ports.ps1
#   powershell -ExecutionPolicy Bypass -File tools\lockdown_tailnet_ports.ps1 -Remove
#
# Optional: block LAN access too (only the hostname remains reachable):
#   ... -ExtraRemoteRanges 192.168.0.0/16,10.0.0.0/8
#
# NOTE: testing from the SAME machine is not a valid test. Connecting to your own
# tailnet IP (100.99.80.84) is loopback traffic, and Windows Firewall does not
# filter loopback — the port will still answer 200/404 locally even while the
# rule correctly blocks every real remote peer. Verify from another device
# (phone with Tailscale, or another PC in the tailnet).
#
#Requires -RunAsAdministrator
param(
    [switch]$Remove,
    [string[]]$ExtraRemoteRanges = @(),
    [int[]]$Ports = @(3100, 8101, 9000, 8085, 8086)
)

$rulePrefix = "EdgeGuard: block direct access"
$remote = @("100.64.0.0/10") + $ExtraRemoteRanges

if ($Remove) {
    $rules = Get-NetFirewallRule -DisplayName "$rulePrefix*" -ErrorAction SilentlyContinue
    if (-not $rules) { Write-Host "No rules to remove."; exit 0 }
    $rules | Remove-NetFirewallRule
    Write-Host "Removed $($rules.Count) rule(s)."
    exit 0
}

foreach ($p in $Ports) {
    $name = "$rulePrefix (TCP $p)"
    Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule `
        -DisplayName $name `
        -Direction Inbound `
        -Action Block `
        -Protocol TCP `
        -LocalPort $p `
        -RemoteAddress $remote `
        -Profile Any | Out-Null
    Write-Host "Blocked inbound TCP $p from $($remote -join ', ')"
}

Write-Host ""
Write-Host "Verify (expect 000 / timeout):"
foreach ($p in $Ports) { Write-Host "  curl http://llm-server.tail923b9a.ts.net:$p/" }
Write-Host "Verify (expect 200/401, still allowed):"
Write-Host "  curl https://llm-server.tail923b9a.ts.net/index.html"
Write-Host "  curl https://llm-server.tail923b9a.ts.net:8443/AIEdgeGuard/health"
