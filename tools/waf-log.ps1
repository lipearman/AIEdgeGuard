<#
.SYNOPSIS
  EdgeGuard WAF log viewer — ดูว่า request ที่เข้ามาผ่าน hostname ถูก WAF ตัดสินอย่างไร

.DESCRIPTION
  รวม 3 แหล่งข้อมูลที่ต้องดูคู่กัน:
    1) Traefik access log  = ทุก request (path, status, router)  -> "มีคนเรียกเข้ามาไหม"
    2) CrowdSec alerts     = WAF ตัดสินว่าอะไร (rule family + score) -> "บล็อกถูกหรือเปล่า"
    3) CrowdSec decisions  = IP ที่ถูกแบนจริง (bouncer ใช้ค่านี้)

.EXAMPLES
  .\waf-log.ps1                   # 30 request ล่าสุด (ทุกสถานะ)
  .\waf-log.ps1 -Blocked 50       # 50 ครั้งล่าสุดที่ตอบ 403
  .\waf-log.ps1 -Port 8443        # เฉพาะพอร์ต 8443
  .\waf-log.ps1 -Alerts 10        # 10 WAF alerts ล่าสุด
  .\waf-log.ps1 -Inspect 438      # รายละเอียด alert 438 (rule/zones/score)
  .\waf-log.ps1 -Decisions        # IP ที่ถูกแบนอยู่ตอนนี้
  .\waf-log.ps1 -Metrics          # สรุป: อ่านกี่บรรทัด / alert อะไรบ้าง
  .\waf-log.ps1 -Watch            # ตาม access log สด (Ctrl+C เพื่อหยุด)
#>
param(
    [int]$Last = 30,
    [switch]$Blocked,
    [int]$Alerts = 0,
    [string]$Inspect,
    [switch]$Decisions,
    [switch]$Metrics,
    [switch]$Watch,
    [int]$Port = 0
)

$ErrorActionPreference = 'SilentlyContinue'

function Get-AccessLines([int]$tail) {
    docker exec traefik sh -c "tail -n $tail /var/log/traefik/access.log" 2>$null
}

function Show-Requests {
    param([int]$Count, [switch]$OnlyBlocked, [int]$OnlyPort)
    $need = if ($OnlyBlocked) { [Math]::Max($Count * 20, 2000) } else { [Math]::Max($Count * 5, 200) }
    $rows = Get-AccessLines $need | ForEach-Object {
        try { $_ | ConvertFrom-Json } catch { }
    }
    if ($OnlyBlocked) { $rows = $rows | Where-Object { $_.DownstreamStatus -eq 403 } }
    if ($OnlyPort -gt 0) { $rows = $rows | Where-Object { $_.RequestPort -eq "$OnlyPort" } }
    $rows | Select-Object -Last $Count |
        Select-Object @{n='เวลา (UTC)';e={ ([datetime]$_.StartUTC).ToString('HH:mm:ss') }},
                      @{n='พอร์ต';e={$_.RequestPort}},
                      @{n='path';e={$_.RequestPath}},
                      @{n='status';e={$_.DownstreamStatus}},
                      @{n='router';e={$_.RouterName}},
                      @{n='client';e={$_.ClientHost}} |
        Format-Table -AutoSize
}

if ($Watch) {
    Write-Host "ตาม access log สด (Ctrl+C เพื่อหยุด) — ดู DownstreamStatus: 403 = WAF บล็อก" -ForegroundColor Cyan
    docker exec traefik sh -c "tail -f -n 0 /var/log/traefik/access.log"
    return
}

if ($Inspect) {
    docker exec gateway-crowdsec cscli alerts inspect $Inspect
    return
}

if ($Decisions) {
    Write-Host "=== IP ที่ถูกแบนอยู่ตอนนี้ (bouncer ใช้ค่านี้) ===" -ForegroundColor Cyan
    docker exec gateway-crowdsec cscli decisions list
    return
}

if ($Metrics) {
    docker exec gateway-crowdsec cscli metrics
    return
}

if ($Alerts -gt 0) {
    Write-Host "=== WAF alerts (kind=waf = AppSec/CRS ตัดสิน; reason = rule family + score) ===" -ForegroundColor Cyan
    docker exec gateway-crowdsec cscli alerts list -l $Alerts
    Write-Host ""
    Write-Host "ดูรายละเอียดของ alert: .\waf-log.ps1 -Inspect <ID>" -ForegroundColor DarkGray
    return
}

Show-Requests -Count $Last -OnlyBlocked:$Blocked -OnlyPort $Port
Write-Host ""
Write-Host ("แสดง {0} request{1} — 'status 403' คือถูกบล็อก (WAF หรือ app เอง)" -f $Last, $(if ($Blocked) { ' ที่ตอบ 403' } else { '' })) -ForegroundColor DarkGray
Write-Host "  ดูว่า WAF ตัดสินด้วย rule อะไร : .\waf-log.ps1 -Alerts 10" -ForegroundColor DarkGray
Write-Host "  ตามสด                          : .\waf-log.ps1 -Watch" -ForegroundColor DarkGray
