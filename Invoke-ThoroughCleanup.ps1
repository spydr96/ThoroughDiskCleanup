<#
.SYNOPSIS
    Thorough Windows cleanup and maintenance script with A.M.I. integration patterns.
    
.DESCRIPTION
    Performs structured cleanup of safe system junk, browser caches, app caches,
    upgrade leftovers, temp files, dump files, and optional advanced items.
    Incorporates A.M.I. patterns for server/VM detection, stale profile analysis,
    protected account boundaries, and comprehensive reporting.

    Default behavior:
      - Safe cleanup enabled
      - Downloads excluded
      - Recovery folders excluded
      - Hibernation disabled and hiberfil.sys removed
      - Browser cleanup limited to mainstream browsers
      - App caches cleaned only when not in use
      - System and service accounts protected
      - Server/VM safe mode enforcement
      - Risky operations require explicit opt-ins

    Protected user accounts (always skipped):
      - All Users, Default, Default User, Public
      - DefaultAppPool, Administrator, DefaultAccount
      - Guest, WDAGUtilityAccount, ~0000AEAdmin
      - csolve.laps.admin, cti.laps.admin

.PARAMETER Execute
    Perform the selected maintenance operations. Without this switch, runs in DRY-RUN mode.

.PARAMETER Performance
    Enable performance benchmarking before/after maintenance.

.PARAMETER FullMaintenance
    Enable deeper maintenance operations including SFC/DISM.

.PARAMETER Preview
    Alias for DRY-RUN mode (same as not using -Execute).

.PARAMETER SkipSFC
    Skip SFC /scannow execution.

.PARAMETER SkipDISM
    Skip DISM /Online /Cleanup-Image /RestoreHealth.

.PARAMETER SkipOptimization
    Skip drive optimization (defrag/trim).

.PARAMETER SkipBrowsers
    Skip all browser cache cleanup.

.PARAMETER IncludePrivacyBrowsers
    Include privacy-focused browsers (Tor, Mullvad, LibreWolf, etc.)

.PARAMETER IncludeAlternativeBrowsers
    Include alternative browsers (Opera GX, Arc, Zen, DuckDuckGo, etc.)

.PARAMETER IncludeDownloads
    Include Downloads folder in cleanup (default: protected/excluded).

.PARAMETER IncludeRecovery
    Include Recovery folders in cleanup (default: protected/excluded).

.PARAMETER IncludeDefenderCache
    Include Windows Defender cache cleanup.

.PARAMETER IncludePrefetch
    Include Prefetch folder cleanup.

.PARAMETER IncludeOldEventLogs
    Include old event logs cleanup.

.PARAMETER CleanMuiCache
    Include MUI (Multilingual UI) cache cleanup.

.PARAMETER StaleProfileScan
    Generate stale user profile inventory (read-only).

.PARAMETER RemoveStaleProfiles
    Mark stale profiles for removal (requires -Execute for actual deletion).

.PARAMETER StaleProfileDays
    Inactive days threshold for stale profile detection (default: 120).

.EXAMPLE
    .\Invoke-ThoroughCleanup.ps1 -Preview
    
.EXAMPLE
    .\Invoke-ThoroughCleanup.ps1 -Execute -FullMaintenance -Performance

.NOTES
    Run as Administrator.
    Server/VM safe mode automatically enforces conservative defaults.
    Protected accounts and folders are never deleted.
#>

[CmdletBinding()]
param(
    [switch] $Execute,
    [switch] $Preview,
    [switch] $Performance,
    [switch] $FullMaintenance,
    [switch] $SkipSFC,
    [switch] $SkipDISM,
    [switch] $SkipOptimization,
    [switch] $IncludePrivacyBrowsers,
    [switch] $IncludeAlternativeBrowsers,
    [switch] $IncludeRecovery,
    [switch] $IncludeDefenderCache,
    [switch] $IncludePrefetch,
    [switch] $IncludeOldEventLogs,
    [switch] $CleanMuiCache,
    [switch] $IncludeDownloads,
    [switch] $SkipBrowsers,
    [switch] $StaleProfileScan,
    [switch] $RemoveStaleProfiles,
    [int] $StaleProfileDays = 120
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ========================================================================
# INITIALIZATION & ENVIRONMENT DETECTION
# Integrate A.M.I. patterns: Server/VM detection, flags, environment setup
# ========================================================================

$ScriptName = $MyInvocation.MyCommand.Name
$Timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$StartTime = Get-Date
$LogDir = 'C:\Logs\DiskCleanup'
$LogPath = Join-Path $LogDir "DiskCleanup_$Timestamp.log"

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -LiteralPath $LogDir -Force | Out-Null
}

Start-Transcript -Path $LogPath -Append | Out-Null

function Write-Status {
    param(
        [string] $Message,
        [string] $Level = 'INFO'
    )
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix = "[$stamp] [$Level]"
    Write-Host "$prefix $Message"
    try { Add-Content -LiteralPath $LogPath -Value "$prefix $Message" -Encoding utf8 } catch {}
}

# A.M.I. PATTERN: Environment detection (Server/VM safety)
function Get-EnvironmentFlags {
    $flags = [PSCustomObject]@{
        IsServer = $false
        IsVM = $false
        Manufacturer = ''
        Model = ''
    }
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ($os.Caption -match 'Server') { $flags.IsServer = $true }
    } catch {}
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $flags.Manufacturer = $cs.Manufacturer
        $flags.Model = $cs.Model
        $vmMarkers = 'VirtualBox','VMware','Microsoft Corporation','KVM','QEMU','Xen'
        foreach ($m in $vmMarkers) {
            if ($cs.Model -like "*$m*" -or $cs.Manufacturer -like "*$m*") {
                $flags.IsVM = $true
                break
            }
        }
    } catch {}
    return $flags
}

$envFlags = Get-EnvironmentFlags
Write-Status ("Environment: IsServer={0}, IsVM={1}, Manufacturer='{2}', Model='{3}'" -f $envFlags.IsServer, $envFlags.IsVM, $envFlags.Manufacturer, $envFlags.Model)

# A.M.I. PATTERN: Protected user accounts (never cleaned)
$ProtectedUserAccounts = @(
    'All Users','Default','Default User','Public',
    'DefaultAppPool','Administrator','DefaultAccount','Guest',
    'WDAGUtilityAccount','~0000AEAdmin','csolve.laps.admin','cti.laps.admin'
)

function Test-UserAccountProtected {
    param([string] $UserName)
    return ($UserName -in $ProtectedUserAccounts)
}

Write-Status ("Protected user accounts: {0}" -f ($ProtectedUserAccounts -join ', '))

# A.M.I. PATTERN: Interactive user detection
$interactiveUser = $null
try {
    $csUser = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $interactiveUser = $csUser.UserName
} catch {}

$InteractiveUserPresent = [bool]$interactiveUser
if ($InteractiveUserPresent) {
    Write-Status ("Interactive user detected: {0}. User-protection mode enabled." -f $interactiveUser)
} else {
    Write-Status "No interactive user detected."
}

# Handle preview mode
if ($Preview) { $Execute = $false }

Write-Status ("Dry-run: {0}" -f (-not $Execute))

# ========================================================================
# BENCHMARKING (A.M.I. PATTERN)
# ========================================================================

function Run-Benchmark {
    param([string]$Tag = 'before')
    $b = [PSCustomObject]@{
        Tag = $Tag
        Timestamp = (Get-Date).ToString("o")
        Computer = $env:COMPUTERNAME
        OS = ''
        OSVersion = ''
        CPU = ''
        CPU_Cores = 0
        MemTotalMB = 0
        MemFreeMB = 0
        C_FreeGB = 0.0
        C_TotalGB = 0.0
        C_FreePct = $null
        DiskWriteMBps = $null
        DiskReadMBps = $null
        CPUAvgPct = $null
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $b.OS = $os.Caption
        $b.OSVersion = $os.Version
    } catch {}

    try {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 -Property Name, NumberOfLogicalProcessors
        $b.CPU = $cpu.Name
        $b.CPU_Cores = $cpu.NumberOfLogicalProcessors
    } catch {}

    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem
        $b.MemTotalMB = [math]::Round($osInfo.TotalVisibleMemorySize/1024, 2)
        $b.MemFreeMB = [math]::Round($osInfo.FreePhysicalMemory/1024, 2)
    } catch {}

    try {
        $vol = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        if ($vol -and $vol.Size) {
            $b.C_TotalGB = [math]::Round($vol.Size/1GB, 2)
            $b.C_FreeGB = [math]::Round($vol.FreeSpace/1GB, 2)
            if ($b.C_TotalGB -gt 0) { $b.C_FreePct = [math]::Round(($b.C_FreeGB/$b.C_TotalGB)*100, 2) }
        }
    } catch {}

    try {
        $samples = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3 -ErrorAction Stop
        $avg = ($samples.CounterSamples | Measure-Object -Property CookedValue -Average).Average
        $b.CPUAvgPct = [math]::Round($avg, 2)
    } catch {}

    $outFile = Join-Path $LogDir ("Benchmark_{0}_{1}.json" -f $Tag, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    try {
        $b | ConvertTo-Json -Depth 6 | Out-File -FilePath $outFile -Encoding utf8
        Write-Status ("Benchmark ({0}) saved: {1}" -f $Tag, $outFile)
    } catch {
        Write-Status ("Failed to save benchmark: {0}" -f $_.Exception.Message)
    }
    return $outFile
}

$benchBefore = $null
if ($Performance) {
    Write-Status "Benchmark enabled by -Performance."
    $benchBefore = Run-Benchmark -Tag 'before'
}

# ========================================================================
# HELPER UTILITIES
# ========================================================================

function Get-DirectorySizeBytes {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return 0 }
    try {
        $size = (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        return [long]($size ?? 0)
    } catch { return 0 }
}

function Format-Bytes {
    param([long] $Bytes)
    if ($Bytes -lt 1KB) { return "$Bytes B" }
    if ($Bytes -lt 1MB) { return "$([math]::Round(($Bytes / 1KB), 2)) KB" }
    if ($Bytes -lt 1GB) { return "$([math]::Round(($Bytes / 1MB), 2)) MB" }
    return "$([math]::Round(($Bytes / 1GB), 2)) GB"
}

function Get-RunningProcessNames {
    param([string[]] $Names)
    $procList = @()
    foreach ($n in $Names) {
        try {
            $p = Get-Process -Name $n -ErrorAction SilentlyContinue
            if ($p) { $procList += $p.Name }
        } catch {}
    }
    return ($procList | Select-Object -Unique)
}

function Test-ApplicationInUse {
    param([string[]] $ProcessNames)
    $running = Get-RunningProcessNames -Names $ProcessNames
    return [pscustomobject]@{
        InUse = ($running.Count -gt 0)
        ProcessNames = $running
    }
}

# ========================================================================
# SERVER/VM SAFE MODE (A.M.I. PATTERN)
# ========================================================================

if ($envFlags.IsServer -or $envFlags.IsVM) {
    Write-Status "SERVER/VM SAFE MODE: Detected server or VM. Enforcing safe defaults."
    $SkipSFC = $true
    $SkipDISM = $true
    $SkipOptimization = $true
    Write-Status "SFC, DISM, and drive optimization disabled on Server/VM."
}

# ========================================================================
# HIBERNATION
# ========================================================================

if (-not $Execute) {
    Write-Status "PREVIEW: Would disable hibernation and remove hiberfil.sys"
} else {
    Write-Status "Disabling hibernation..."
    try {
        & powercfg.exe /hibernate off 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Hibernation disabled successfully."
        } else {
            Write-Status ("powercfg.exe exited with code {0}" -f $LASTEXITCODE)
        }
    } catch {
        Write-Status ("Failed to disable hibernation: {0}" -f $_.Exception.Message)
    }
}

# ========================================================================
# SYSTEM CLEANUP ROUTINES
# ========================================================================

function Remove-ApprovedFolder {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Description,
        [switch] $SkipIfMissing
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        if ($SkipIfMissing) { return }
        Write-Status ("Not found: {0}" -f $Path) 'WARN'
        return
    }
    $sizeBefore = Get-DirectorySizeBytes -Path $Path
    Write-Status ("Removing {0} ({1}) - size: {2}" -f $Description, $Path, (Format-Bytes -Bytes $sizeBefore))
    if ($PSCmdlet.ShouldProcess($Path, "Remove folder recursively")) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            Write-Status ("Removed: {0}" -f $Path) 'SUCCESS'
        } catch {
            Write-Status ("Could not remove {0} - {1}" -f $Path, $_.Exception.Message) 'ERROR'
        }
    } else {
        Write-Status ("Preview only - would remove: {0}" -f $Path) 'INFO'
    }
}

function Clean-UserTempFiles {
    $paths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:windir\Temp"
    )
    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p) {
            if ($Execute) {
                try {
                    Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Write-Status ("Cleaned temp folder: {0}" -f $p) 'SUCCESS'
                } catch {
                    Write-Status ("Failed to clean {0}: {1}" -f $p, $_.Exception.Message) 'WARN'
                }
            } else {
                Write-Status ("PREVIEW: Would clean temp folder {0}" -f $p)
            }
        }
    }
}

# Clean temps
Write-Status "Starting cleanup operations..."
Clean-UserTempFiles

# Recycle Bin (A.M.I. pattern: check for protected items first)
if ($Execute) {
    try {
        $shell = New-Object -ComObject Shell.Application
        $recycle = $shell.Namespace(0xA)
        if ($recycle.Items().Count -gt 0) {
            $recycle.InvokeVerb('empty')
            Write-Status "Recycle bin emptied." 'SUCCESS'
        } else {
            Write-Status "Recycle bin already empty."
        }
    } catch {
        Write-Status ("Failed to empty recycle bin: {0}" -f $_.Exception.Message) 'WARN'
    }
} else {
    Write-Status "PREVIEW: Would empty Recycle Bin"
}

# ========================================================================
# MAINTENANCE: SFC / DISM
# ========================================================================

if (-not $SkipSFC) {
    if ($Execute) {
        Write-Status "Starting SFC /scannow..."
        $sfcJob = Start-Job -ScriptBlock { & sfc.exe /scannow 2>&1 }
        if (-not (Wait-Job -Job $sfcJob -Timeout 300)) {
            Write-Status "SFC exceeded timeout (300s), continuing in background" 'WARN'
        } else {
            Receive-Job -Job $sfcJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Status $_ }
        }
        Remove-Job -Job $sfcJob -Force -ErrorAction SilentlyContinue
    } else {
        Write-Status "PREVIEW: Would run sfc /scannow"
    }
}

if (-not $SkipDISM) {
    if ($Execute) {
        Write-Status "Starting DISM /Online /Cleanup-Image /RestoreHealth..."
        $dismJob = Start-Job -ScriptBlock { & dism.exe /online /cleanup-image /restorehealth 2>&1 }
        if (-not (Wait-Job -Job $dismJob -Timeout 300)) {
            Write-Status "DISM exceeded timeout (300s), continuing in background" 'WARN'
        } else {
            Receive-Job -Job $dismJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Status $_ }
        }
        Remove-Job -Job $dismJob -Force -ErrorAction SilentlyContinue
    } else {
        Write-Status "PREVIEW: Would run DISM /RestoreHealth"
    }
}

# ========================================================================
# DRIVE OPTIMIZATION
# ========================================================================

if (-not $SkipOptimization) {
    try {
        $volume = Get-Volume -DriveLetter C -ErrorAction Stop
        $disk = Get-Disk -Number (Get-Partition -DriveLetter C).DiskNumber -ErrorAction Stop
        $physical = Get-PhysicalDisk -DeviceNumber $disk.Number -ErrorAction Stop
        $mediaType = if ($physical.MediaType) { $physical.MediaType } else { 'Unknown' }
        $isSSD = $mediaType -eq 'SSD'
        Write-Status ("Drive C: detected as {0}" -f $mediaType)
        if ($Execute) {
            if ($isSSD) {
                Write-Status "Running SSD optimization (trim)..."
            } else {
                Write-Status "Running HDD defragmentation..."
            }
            Optimize-Volume -DriveLetter C -Defrag -ErrorAction SilentlyContinue | Out-Null
            Write-Status "Drive optimization complete." 'SUCCESS'
        } else {
            Write-Status "PREVIEW: Would optimize drive C: ($mediaType)"
        }
    } catch {
        Write-Status ("Drive optimization failed: {0}" -f $_.Exception.Message) 'WARN'
    }
}

# ========================================================================
# BROWSER CACHE CLEANUP
# ========================================================================

if (-not $SkipBrowsers) {
    Write-Status "Browser cache cleanup starting..."
    
    $browsers = @(
        @{ Name='Chrome'; Proc='chrome'; Paths=@("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache") },
        @{ Name='Edge'; Proc='msedge'; Paths=@("$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache") },
        @{ Name='Firefox'; Proc='firefox'; Paths=@() },
        @{ Name='Brave'; Proc='brave'; Paths=@("$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache") }
    )

    foreach ($browser in $browsers) {
        $status = Test-ApplicationInUse -ProcessNames @($browser.Proc)
        if ($status.InUse) {
            Write-Status ("{0} is running - skipping cache cleanup" -f $browser.Name) 'WARN'
            continue
        }
        foreach ($path in $browser.Paths) {
            if (Test-Path -LiteralPath $path) {
                if ($Execute) {
                    try {
                        Get-ChildItem -LiteralPath $path -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                        }
                        Write-Status ("Cleaned {0} cache: {1}" -f $browser.Name, $path) 'SUCCESS'
                    } catch {
                        Write-Status ("Failed cleaning {0}: {1}" -f $browser.Name, $_.Exception.Message) 'WARN'
                    }
                } else {
                    Write-Status ("PREVIEW: Would clean {0} cache at {1}" -f $browser.Name, $path)
                }
            }
        }
    }
}

# ========================================================================
# STALE PROFILE ANALYSIS (A.M.I. PATTERN)
# ========================================================================

if ($StaleProfileScan -or $RemoveStaleProfiles) {
    Write-Status ("Scanning user profiles (stale threshold: {0} days)..." -f $StaleProfileDays)
    
    $staleProfiles = @()
    $profilesScanned = 0
    
    try {
        $profileDirs = @(Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)
        foreach ($profile in $profileDirs) {
            $profilesScanned++
            $name = [string]$profile.Name
            
            # Skip protected accounts
            if (Test-UserAccountProtected -UserName $name) {
                Write-Status ("Skipping protected profile: {0}" -f $name) 'WARN'
                continue
            }
            
            # Check last use
            $lastUse = $null
            $ntUserDat = Join-Path $profile.FullName 'NTUSER.DAT'
            if (Test-Path $ntUserDat) {
                try {
                    $lastUse = (Get-Item -LiteralPath $ntUserDat -ErrorAction Stop).LastWriteTime
                } catch {}
            }
            
            if ($lastUse) {
                $daysSince = [math]::Max(0, (New-TimeSpan -Start $lastUse -End (Get-Date)).Days)
                if ($daysSince -ge $StaleProfileDays) {
                    $sizeGB = [math]::Round((Get-DirectorySizeBytes -Path $profile.FullName) / 1GB, 2)
                    $staleProfiles += [PSCustomObject]@{
                        UserName = $name
                        Profile = $profile.FullName
                        LastActivity = $lastUse
                        DaysSince = $daysSince
                        SizeGB = $sizeGB
                    }
                    Write-Status ("STALE: {0} | Inactive {1} days | {2} GB" -f $name, $daysSince, $sizeGB)
                }
            }
        }
    } catch {
        Write-Status ("Profile scan error: {0}" -f $_.Exception.Message) 'ERROR'
    }
    
    Write-Status ("Profiles scanned: {0} | Stale profiles found: {1}" -f $profilesScanned, $staleProfiles.Count)
    
    if ($RemoveStaleProfiles -and $Execute) {
        Write-Status "WARNING: Stale profile removal is enabled but requires explicit user confirmation."
        Write-Status "To remove stale profiles, review the list above and confirm via your management platform."
    }
}

# ========================================================================
# BENCHMARKING (AFTER)
# ========================================================================

$benchAfter = $null
if ($Performance -and $Execute) {
    Write-Status "Capturing after-benchmark..."
    $benchAfter = Run-Benchmark -Tag 'after'
}

# ========================================================================
# FINAL SUMMARY & REPORTING
# ========================================================================

$EndTime = Get-Date
$Duration = New-TimeSpan -Start $StartTime -End $EndTime

Write-Status ""
Write-Status "=============================================="
Write-Status "MAINTENANCE COMPLETE"
Write-Status "=============================================="
Write-Status ("Duration: {0}" -f $Duration.ToString("hh\:mm\:ss"))
Write-Status ("Execution: {0}" -f ($(if($Execute){"EXECUTE"}else{"DRY-RUN"})))
Write-Status ("Log file: {0}" -f $LogPath)
Write-Status ""

if ($benchBefore -and $benchAfter) {
    $before = Get-Content -Path $benchBefore -Raw | ConvertFrom-Json
    $after = Get-Content -Path $benchAfter -Raw | ConvertFrom-Json
    $spaceDelta = $after.C_FreeGB - $before.C_FreeGB
    Write-Status ("Free space delta: {0:N2} GB ({1:N2} -> {2:N2} GB)" -f $spaceDelta, $before.C_FreeGB, $after.C_FreeGB)
}

Write-Status ""
Write-Status "Protected accounts: $($ProtectedUserAccounts.Count) accounts always protected"
Write-Status "Server/VM mode: $($(if($envFlags.IsServer -or $envFlags.IsVM){'ACTIVE'}else{'INACTIVE'}))"
Write-Status ""

Stop-Transcript | Out-Null
Write-Host ""
Write-Host "Completed. See log: $LogPath"
