<# Defend-AD-QuickGUI.ps1
   Minimal GUI for one-click AD hardening + baseline + monitor (CCDC)
   Now includes: LDAP hardening, NTP (PDCe), Firewall via GPO, CoreSec GPO, DNS hardening,
   and richer evidence export. Auto-detects domain/DC and uses a string FQDN for -Server.
#>

$ErrorActionPreference='SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Config (edit if needed) ---
$BannerText  = "Authorized use only. Activity may be monitored."
$NTPServer   = "time.windows.com"
$AllowFWPort = 80
$BaseDir     = Join-Path $env:USERPROFILE 'DefendAD_AIO'
$BaselineDir = Join-Path $BaseDir 'Baseline'
$ReportDir   = Join-Path $BaseDir 'Reports'
$LogFile     = Join-Path $BaseDir 'AIO.log'
$MonJobName  = 'CCDC_ADMon_AIO'
New-Item $BaseDir,$BaselineDir,$ReportDir -ItemType Directory -Force | Out-Null

# --- Modules ---
$HasAD=$false;$HasGP=$false
try{ Import-Module ActiveDirectory -ErrorAction Stop; $HasAD=$true }catch{}
try{ Import-Module GroupPolicy     -ErrorAction Stop; $HasGP=$true }catch{}

# --- Domain context autodetect (PreferredDC is a clean string) ---
function Get-DomainContext {
    $ctx = [ordered]@{
        IsDomainJoined = $false
        IsDC           = $false
        DomainDN       = $null
        NetBIOS        = $null
        FQDN           = $null
        PreferredDC    = $null
        Reason         = $null
    }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $ctx.IsDomainJoined = [bool]$cs.PartOfDomain
        if (-not $ctx.IsDomainJoined) { $ctx.Reason = "Workgroup host"; return [pscustomobject]$ctx }

        if ($HasAD) {
            try {
                $ad = Get-ADDomain
                $ctx.DomainDN = $ad.DistinguishedName
                $ctx.NetBIOS  = $ad.NetBIOSName
                $ctx.FQDN     = $ad.DNSRoot
                try {
                    $dc = Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop
                    $ctx.PreferredDC = [string]$dc.HostName
                } catch {
                    $ctx.PreferredDC = [string]((Get-ADDomainController -Filter * | Select-Object -First 1 -ExpandProperty HostName))
                }
            } catch { $ctx.Reason = "AD query failed: $($_.Exception.Message)" }
        }

        try { if (Get-Service -Name NTDS -ErrorAction Stop) { $ctx.IsDC = $true } } catch {}
        if (-not $ctx.DomainDN) {
            try {
                $nl = nltest /dsgetdc:. 2>$null
                if ($nl) {
                    $ctx.FQDN        = ($nl | Select-String 'Domain Name:(.+)$').Matches.Groups[1].Value.Trim()
                    $ctx.PreferredDC = ($nl | Select-String 'DC:(.+)$').Matches.Groups[1].Value.Trim()
                }
            } catch { $ctx.Reason = "nltest fallback failed" }
        }
    } catch { $ctx.Reason = "Detection error: $($_.Exception.Message)" }
    return [pscustomobject]$ctx
}

# --- Logging helper (writes to UI + file) ---
function Log([string]$m){
  $ts=Get-Date -Format 'HH:mm:ss'
  "$ts  $m" | Tee-Object -FilePath $LogFile -Append | Out-Host
  if ($script:txtLog) {
    $txtLog.AppendText("$ts  $m`r`n")
    $txtLog.SelectionStart=$txtLog.Text.Length; $txtLog.ScrollToCaret()
  }
}

# ---------- LDAP hardening ----------
function Invoke-LDAPHardening {
  if (-not $ctx.IsDomainJoined) { Log "LDAP: host not domain-joined; skipping."; return }
  Log "LDAP: Enforcing signing (LDAPServerIntegrity=2)…"
  New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -Value 2 -PropertyType DWord -Force | Out-Null

  Log "LDAP: Enforcing channel binding (LdapEnforceChannelBinding=2)…"
  New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -Value 2 -PropertyType DWord -Force | Out-Null

  Log "LDAP: Disabling simple binds over cleartext (LDAPServerRequireStrongAuth=2)…"
  New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerRequireStrongAuth -Value 2 -PropertyType DWord -Force | Out-Null

  try { Restart-Service ADWS -Force; Log "LDAP: Restarted ADWS to apply settings." } catch { Log "LDAP: ADWS restart warning: $($_.Exception.Message)" }
}
function Show-LDAPStatus {
  try {
    $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    Log ("LDAP status -> Signing:{0}  ChannelBinding:{1}  StrongAuth:{2}" -f $v.LDAPServerIntegrity,$v.LdapEnforceChannelBinding,$v.LDAPServerRequireStrongAuth)
  } catch {
    Log "LDAP status read failed: $($_.Exception.Message)"
  }
}

# ---------- Core Security GPO (NTLM/SMB signing) ----------
function Deploy-CoreSec-GPO {
  if(-not $HasAD -or -not $HasGP){ Log "CoreSec GPO: AD/GPO not available."; return }
  $gName = "CCDC_Core_Security"
  try{
    $gpo = Get-GPO -Name $gName -Server $ctx.PreferredDC -ErrorAction SilentlyContinue
    if(-not $gpo){ $gpo = New-GPO -Name $gName }

    # LmCompatibilityLevel = 5 (Send NTLMv2 only; refuse LM & NTLM)
    Set-GPRegistryValue -Name $gName `
      -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
      -ValueName "LmCompatibilityLevel" -Type DWord -Value 5

    # SMB signing required (client & server)
    Set-GPRegistryValue -Name $gName `
      -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
      -ValueName "RequireSecuritySignature" -Type DWord -Value 1
    Set-GPRegistryValue -Name $gName `
      -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
      -ValueName "RequireSecuritySignature" -Type DWord -Value 1

    New-GPLink -Name $gName -Target $ctx.DomainDN -LinkEnabled Yes -Server $ctx.PreferredDC -ErrorAction SilentlyContinue | Out-Null
    Log "Core Security GPO deployed & linked: $gName"
  }catch{ Log "CoreSec GPO error: $($_.Exception.Message)" }
}

# ---------- DNS hardening on DC ----------
function Harden-DNS {
  if (-not $ctx.IsDC) { return }
  try{
    Import-Module DnsServer -ErrorAction Stop
    $zones = Get-DnsServerZone -ErrorAction Stop | Where-Object { $_.IsDsIntegrated -eq $true }
    foreach($z in $zones){
      Set-DnsServerPrimaryZone -Name $z.ZoneName -DynamicUpdate Secure -ErrorAction SilentlyContinue
      Set-DnsServerPrimaryZone -Name $z.ZoneName -SecureSecondaries NoXfr -ErrorAction SilentlyContinue
    }
    Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval (New-TimeSpan -Days 7) -ApplyOnAllZones $true -ErrorAction SilentlyContinue
    Log "DNS hardened: secure updates, no transfers, scavenging on."
  }catch{ Log "DNS hardening skipped/failed: $($_.Exception.Message)" }
}

# ---------- Core hardening (calls LDAP, CoreSec, DNS) ----------
function Invoke-ADCoreHardening {
  if (-not $ctx.IsDomainJoined -or -not $HasAD) { Log "Hardening: AD not available on this host."; return }
  Log "Applying core AD hardening…"

  Invoke-LDAPHardening
  Deploy-CoreSec-GPO
  Harden-DNS

  try{
    Set-ADDefaultDomainPasswordPolicy -Identity $ctx.DomainDN -Server $ctx.PreferredDC `
      -ComplexityEnabled $true -MinPasswordLength 12 -PasswordHistoryCount 3 -LockoutThreshold 5 -ErrorAction Stop
    Log "Password policy set on $($ctx.FQDN)."
  } catch { Log "Password policy: $($_.Exception.Message)" }

  auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
  auditpol /set /category:"DS Access"           /success:enable /failure:enable | Out-Null
  try{ Disable-LocalUser -Name Guest -ErrorAction Stop; Log "Guest account disabled." }catch{}

  Log "Core hardening complete."
}

# ---------- Baseline ----------
function Save-Baseline {
  if (-not $ctx.IsDomainJoined -or -not $HasAD) { Log "Baseline: AD not available."; return }
  Log "Capturing baseline…"
  try {
    Get-ADGroupMember 'Domain Admins' -Recursive -Server $ctx.PreferredDC |
      Select Name,SamAccountName,ObjectClass |
      Export-CliXml (Join-Path $BaselineDir 'DomainAdmins.xml')
  } catch { Log "Baseline DA: $($_.Exception.Message)" }

  if($HasGP){
    try{
      $gpos=Get-GPO -All -Server $ctx.PreferredDC
      $gpos | Export-CliXml (Join-Path $BaselineDir 'GPOs.xml')
      $hdir = Join-Path $BaselineDir 'GPOHashes'; New-Item $hdir -ItemType Directory -Force | Out-Null
      foreach($g in $gpos){
        try{
          $xml=Get-GPOReport -Guid $g.Id -ReportType Xml -Server $ctx.PreferredDC
          $hs=[BitConverter]::ToString((New-Object Security.Cryptography.SHA256Managed).ComputeHash([Text.Encoding]::UTF8.GetBytes($xml))) -replace '-',''
          Set-Content (Join-Path $hdir "$($g.DisplayName).sha256") $hs
        }catch{}
      }
    } catch { Log "Baseline GPO: $($_.Exception.Message)" }
  }

  if($HasAD){
    try{
      $out = foreach($dc in (Get-ADDomainController -Filter * -Server $ctx.PreferredDC).HostName){
        try{ Invoke-Command -ComputerName $dc -ScriptBlock { [PSCustomObject]@{ComputerName=$env:COMPUTERNAME; NTP=(w32tm /query /configuration) -join "`n"; FirewallCount=(Get-NetFirewallRule -ErrorAction SilentlyContinue).Count } } }
        catch{ [PSCustomObject]@{ComputerName=$dc; Error=$_.Exception.Message} }
      }
      $out | Export-CliXml (Join-Path $BaselineDir 'HostsSnapshot.xml')
    } catch { Log "Baseline hosts: $($_.Exception.Message)" }
  }
  Log "Baseline saved to $BaselineDir"
}

# ---------- Monitor (simple, reliable) ----------
function Start-Monitor {
  if (-not $ctx.IsDomainJoined -or -not $HasAD) { Log "Monitor: AD not available."; return }
  if(Get-Job -Name $MonJobName -ErrorAction SilentlyContinue){ Log "Monitor already running."; return }
  Log "Starting monitor…"
  Start-Job -Name $MonJobName -ScriptBlock {
    param($BaseDir,$Server)
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    $mon = Join-Path $BaseDir 'monitor.log'
    $admFile = Join-Path (Join-Path $BaseDir 'Baseline') 'DomainAdmins.xml'
    while($true){
      try{
        $base=@(); if(Test-Path $admFile){ $base=(Import-CliXml $admFile).SamAccountName }
        $curr=@(); try{ $curr=(Get-ADGroupMember 'Domain Admins' -Recursive -Server $Server | Select -Expand SamAccountName) }catch{}
        $added=$curr | Where-Object { $_ -notin $base }
        if($added){ Add-Content $mon ("{0} ALERT: New Domain Admins: {1}" -f (Get-Date), ($added -join ',')) }
        $ids=4720,4722,4723,4724,4728,4732,4672,4625,4740
        Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids; StartTime=(Get-Date).AddMinutes(-2)} |
          ForEach-Object{ Add-Content $mon ("{0} EVENT {1} {2}" -f (Get-Date), $_.Id, ($_.Message -split "`n")[0]) }
      }catch{}
      Start-Sleep 20
    }
  } -ArgumentList $BaseDir,$ctx.PreferredDC | Out-Null
  Log "Monitor running (20s interval). Log: $BaseDir\monitor.log"
}

# ---------- Inject helpers ----------
function Set-NTP {
  if(-not $ctx.IsDomainJoined -or -not $HasAD){ Log "NTP: AD not available."; return }
  try{
    $pdc = (Get-ADDomain -Server $ctx.PreferredDC).PDCEmulator
    Log "NTP: PDC Emulator is $pdc"
    Invoke-Command -ComputerName $pdc -ScriptBlock {
      param($ntp)
      w32tm /config /syncfromflags:manual /manualpeerlist:$ntp /update | Out-Null
      Restart-Service w32time -Force
    } -ArgumentList $NTPServer
    Log "NTP configured on PDCe $pdc -> $NTPServer"
  }catch{ Log "NTP failed: $($_.Exception.Message)" }
}

function Push-Banner {
  if(-not $ctx.IsDomainJoined -or -not $HasAD -or -not $HasGP){ Log "Banner: AD/GPO not available."; return }
  $g='CCDC_Login_Banner'
  try{
    $gpo=Get-GPO -Name $g -Server $ctx.PreferredDC -ErrorAction SilentlyContinue; if(-not $gpo){ $gpo=New-GPO -Name $g }
    Set-GPRegistryValue -Name $g -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ValueName 'legalnoticecaption' -Type String -Value 'Authorized Access Only'
    Set-GPRegistryValue -Name $g -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ValueName 'legalnoticetext' -Type String -Value $BannerText
    New-GPLink -Name $g -Target $ctx.DomainDN -LinkEnabled Yes -Server $ctx.PreferredDC -ErrorAction SilentlyContinue | Out-Null
    Log "Banner GPO pushed & linked."
  }catch{ Log "Banner error: $($_.Exception.Message)" }
}

# Firewall via GPO (works even if WinRM is disabled)
function Push-FirewallRule-GPO {
  if(-not $HasAD -or -not $HasGP){ Log "FW GPO: AD/GPO not available."; return }
  $gName = "CCDC_Host_Firewall"
  try{
    $gpo = Get-GPO -Name $gName -Server $ctx.PreferredDC -ErrorAction SilentlyContinue
    if(-not $gpo){ $gpo = New-GPO -Name $gName }
    # Allow inbound TCP on $AllowFWPort
    Set-GPRegistryValue -Name $gName `
      -Key "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
      -ValueName "CCDC-Allow-TCP-$AllowFWPort" -Type String `
      -Value "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=$AllowFWPort|App=|Name=CCDC-Allow-TCP-$AllowFWPort|Edge=FALSE|"
    New-GPLink -Name $gName -Target $ctx.DomainDN -LinkEnabled Yes -Server $ctx.PreferredDC -ErrorAction SilentlyContinue | Out-Null
    Log "FW GPO linked: $gName (port $AllowFWPort)"
  }catch{ Log "FW GPO error: $($_.Exception.Message)" }
}

# ---------- Evidence export ----------
function Export-Evidence {
  $mon = Join-Path $BaseDir 'monitor.log'
  # Export monitor CSV
  if(Test-Path $mon){
    $out = Join-Path $ReportDir ("Monitor_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))
    Get-Content $mon | ForEach-Object{ $t=$_ -split "`t",2; [PSCustomObject]@{Timestamp=$t[0];Message=$t[1]} } | Export-Csv $out -NoTypeInformation
    Log "Exported monitor CSV -> $out"
  } else { Log "No monitor.log yet." }

  # LDAP status proof
  try {
    $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    Set-Content (Join-Path $ReportDir "LDAP_Status.txt") ("Signing={0}  ChannelBinding={1}  StrongAuth={2}" -f $v.LDAPServerIntegrity,$v.LdapEnforceChannelBinding,$v.LDAPServerRequireStrongAuth)
  } catch {}

  # Core Security GPO proof
  try {
    $g = Get-GPO -Name "CCDC_Core_Security" -Server $ctx.PreferredDC -ErrorAction SilentlyContinue
    if($g){ [IO.File]::WriteAllText((Join-Path $ReportDir "CoreSecGPO.txt"), "Present and linked: $($g.DisplayName)") }
  } catch {}
}

# ---------- GUI ----------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Defend-AD Quick GUI (CCDC)"
$form.Size = New-Object System.Drawing.Size(840,580)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI",9)

$btnHarden = New-Object System.Windows.Forms.Button
$btnHarden.Text="One-Click Hardening"
$btnHarden.Size=New-Object System.Drawing.Size(180,36)
$btnHarden.Location=New-Object System.Drawing.Point(20,20)

$btnLDAP = New-Object System.Windows.Forms.Button
$btnLDAP.Text="Harden LDAP"
$btnLDAP.Size=New-Object System.Drawing.Size(140,36)
$btnLDAP.Location=New-Object System.Drawing.Point(210,20)

$btnLDAPStatus = New-Object System.Windows.Forms.Button
$btnLDAPStatus.Text="Check LDAP Status"
$btnLDAPStatus.Size=New-Object System.Drawing.Size(160,36)
$btnLDAPStatus.Location=New-Object System.Drawing.Point(360,20)

$btnBaseline = New-Object System.Windows.Forms.Button
$btnBaseline.Text="Create Baseline"
$btnBaseline.Size=New-Object System.Drawing.Size(160,36)
$btnBaseline.Location=New-Object System.Drawing.Point(530,20)

$btnMonitor = New-Object System.Windows.Forms.Button
$btnMonitor.Text="Start Monitor"
$btnMonitor.Size=New-Object System.Drawing.Size(140,36)
$btnMonitor.Location=New-Object System.Drawing.Point(20,66)

$btnBanner = New-Object System.Windows.Forms.Button
$btnBanner.Text="Push Banner (GPO)"
$btnBanner.Size=New-Object System.Drawing.Size(160,36)
$btnBanner.Location=New-Object System.Drawing.Point(170,66)

$btnNTP = New-Object System.Windows.Forms.Button
$btnNTP.Text="Set NTP on PDCe"
$btnNTP.Size=New-Object System.Drawing.Size(140,36)
$btnNTP.Location=New-Object System.Drawing.Point(340,66)

$btnFW = New-Object System.Windows.Forms.Button
$btnFW.Text="Push FW Port (GPO)"
$btnFW.Size=New-Object System.Drawing.Size(160,36)
$btnFW.Location=New-Object System.Drawing.Point(490,66)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text="Export Evidence"
$btnExport.Size=New-Object System.Drawing.Size(160,36)
$btnExport.Location=New-Object System.Drawing.Point(20,112)

$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Multiline=$true; $txtLog.ScrollBars="Vertical"; $txtLog.ReadOnly=$true
$txtLog.Location=New-Object System.Drawing.Point(20,160)
$txtLog.Size=New-Object System.Drawing.Size(780,360)
$txtLog.Font = New-Object System.Drawing.Font("Consolas",9)

$form.Controls.AddRange(@(
  $btnHarden,$btnLDAP,$btnLDAPStatus,$btnBaseline,$btnMonitor,$btnBanner,$btnNTP,$btnFW,$btnExport,$txtLog
))

# Detect domain now, log, and gate buttons if not domain-joined
$script:ctx = Get-DomainContext
Log ("BaseDir: {0}" -f $BaseDir)
if ($ctx.IsDomainJoined) {
  Log ("Domain: {0}  NetBIOS: {1}  Preferred DC: {2}  IsDC: {3}" -f $ctx.FQDN,$ctx.NetBIOS,$ctx.PreferredDC,$ctx.IsDC)
} else {
  Log ("Not domain-joined. Reason: {0}" -f $ctx.Reason)
  foreach($b in @($btnHarden,$btnLDAP,$btnLDAPStatus,$btnBaseline,$btnMonitor,$btnBanner,$btnNTP,$btnFW)){ $b.Enabled = $false }
  [System.Windows.Forms.MessageBox]::Show("This host is not domain-joined. AD features are disabled.","Info","OK","Information") | Out-Null
}

# Button handlers
$btnHarden.Add_Click({ Invoke-ADCoreHardening })
$btnLDAP.Add_Click({ Invoke-LDAPHardening; Show-LDAPStatus })
$btnLDAPStatus.Add_Click({ Show-LDAPStatus })
$btnBaseline.Add_Click({ Save-Baseline })
$btnMonitor.Add_Click({ Start-Monitor })
$btnBanner.Add_Click({ Push-Banner })
$btnNTP.Add_Click({ Set-NTP })
$btnFW.Add_Click({ Push-FirewallRule-GPO })
$btnExport.Add_Click({ Export-Evidence })

[void]$form.ShowDialog()
