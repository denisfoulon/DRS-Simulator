<#
.SYNOPSIS
    DRS Simulator Script - Version 1.39

.DESCRIPTION
    DRS-Simulator - Custom DRS Implementation for VMware vSphere

.NOTES
    Version: 1.39
    AUTHOR : Denis Foulon
    Date: 2026-06-29

    BUGFIXES (1.39 corrected):
      [FIX-1] @() wrapping on Read-AffinityList / Read-AntiAffinityList / Read-VmToHostList
              assignments in BOTH $shouldCheckRules blocks.
              PS 5.1 unwraps a single-element pipeline to a bare PSObject; without @() the
              resulting variable has no .Count → Enforce-* is never called when exactly
              1 group / 1 rule exists.  Confirmed by the log: "reloaded ( groups)".

      [FIX-2] Enforce-AffinityGroups call in the evacuation-path $shouldCheckRules block
              was missing -NameBlacklistPatterns / -TagBlacklistNames / -IncludeNetwork /
              -DryRun.  The trailing backtick on the last present parameter caused PS to
              silently swallow the closing brace of the if-block.

      [FIX-3] $hostsFromQueue += $host -> $hostsFromQueue += $esxHost in
              Get-HostsNeedingEvacuation.  $host is an automatic variable pointing to the
              Windows machine running PowerShell, not the ESXi host.

      [FIX-4] Malformed Write-Log calls where " -Level Warning" was accidentally
              embedded inside the -Message string instead of being a separate parameter.
              Affected: Read-AffinityList, Enforce-AffinityGroups (x3),
              Read-AntiAffinityList, Enforce-AntiAffinityGroups (x2), Read-VmToHostList.

.ABOUT
    This script simulates DRS-like behavior for VMware vSphere environments.
    It is an independent project created for learning, automation, and lab use.

.AFFILIATION DISCLAIMER
    This project is NOT affiliated, endorsed, or supported by VMware, Inc.
    "VMware" and "DRS" are registered trademarks of VMware, Inc.
    This script is an independent implementation inspired by DRS behavior.

.DISCLAIMER
    This script is provided AS-IS, without warranty of any kind.
    Use at your own risk.
    Always test in a non-production environment first.
    The author assumes no liability for any damage caused by using this script.

.REQUIREMENTS
    - PowerShell 5.1 or later
    - VMware PowerCLI module installed
    - Appropriate permissions on vCenter Server
    - Pre-configured credential file (use Export-Clixml)

.CONFIGURATION BEFORE USE
    1. Update the vCenter parameter with your vCenter FQDN
    2. Update the ClusterName parameter with your cluster name
    3. Create credential file: Get-Credential | Export-Clixml -Path "C:\Scripts\DRS\vcenter_credentials.xml"
    4. Adjust paths to rule files (affinity, anti-affinity, VM-to-Host)
    5. Configure Syslog server parameters if using centralized logging
    6. Adjust thresholds and limits according to your environment

================================================================================
#>

param(
    [string]$VCenter = "vcenter.example.com",
    [string]$ClusterName = "production_cluster",

    # Timing parameters
    [int]$NormalLoopSleepSeconds = 60,
    [int]$EvacLoopSleepSeconds = 20,

    # Migration limits
    [int]$MaxMigrationsBalancePerLoop = 3,
    [int]$MaxMigrationsEvacTotal = 8,
    [int]$MaxMigrationsAffinityPerLoop = 5,
    [int]$MaxMigrationsAntiAffinityPerLoop = 5,
    [int]$MaxMigrationsVmToHostPerLoop = 5,

    # CPU/Memory thresholds (kept for reference; balance logic now uses delta-based triggers below)
    [int]$HighCpuPercent = 75,
    [int]$LowCpuPercent = 40,
    [int]$HighMemPercent = 80,
    [int]$LowMemPercent = 50,

    # Delta-based balancing thresholds (v1.37)
    # A host is a source/target when it deviates by this many points from the cluster average.
    # Lower values = more aggressive balancing. Recommended range: 10-20.
    [int]$DeltaTriggerCpu = 15,
    [int]$DeltaTriggerMem = 15,

    # Blacklists
    [string[]]$NameBlacklistPatterns = @("vCLS", "NOMOVE"),
    [string[]]$TagBlacklistNames = @("No-DRS"),

    # Rule files
    [string]$AffinityListPath = "C:\scripts\DRS\affinity_list.txt",
    [int]$AffinityCheckIntervalSeconds = 300,
    [string]$AntiAffinityListPath = "C:\scripts\DRS\anti_affinity_list.txt",
    [int]$AntiAffinityCheckIntervalSeconds = 300,
    [string]$VmToHostListPath = "C:\scripts\DRS\vm_to_host_list.txt",
    [int]$VmToHostCheckIntervalSeconds = 300,

    # SYSLOG parameters (new in v1.31)
    [string]$SyslogServer = "syslog.example.com",
    [int]$SyslogPort = 514,
    [int]$SyslogFacility = 16,
    [switch]$EnableSyslog = $true,

    # Options
    [switch]$IncludeNetwork,
    [switch]$DryRun
)

# Rules check frequency - check rules every X loops instead of every loop
# Example: 23 = check every 23 minutes (with 60s loop), reducing CPU/IO load
$RulesCheckEveryXLoops = 23

# Loop counter for throttling
$script:loopCounter = 0

# Last check time variables (using file LastWriteTime instead of timer)
$script:lastAffinityLoad = $null
$script:lastAntiAffinityLoad = $null
$script:lastVmToHostLoad = $null

# Rule storage (cached between checks)
$script:affinityGroups = @()
$script:antiAffinityGroups = @()
$script:vmToHostRules = @()

#region Memory Management Tracking Variables
$script:lastGarbageCollection = Get-Date
$script:lastVCenterRecycle = Get-Date
$script:lastMemoryMonitor = Get-Date
$script:gcIntervalHours = 1
$script:vcRecycleIntervalHours = 2
$script:memoryMonitorIntervalHours = 1
#endregion


#region Syslog Function (new in v1.31)
function Send-SyslogMessage {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateRange(0,7)]
        [int]$Severity = 6,

        [switch]$AlsoWriteHost
    )

    if (-not $script:EnableSyslog) {
        if ($AlsoWriteHost) {
            Write-Host $Message
        }
        return
    }

    try {
        $Priority = ($script:SyslogFacility * 8) + $Severity
        $Timestamp = Get-Date -Format "MMM dd HH:mm:ss"
        $Hostname = $env:COMPUTERNAME
        $SyslogMsg = "<$Priority>$Timestamp $Hostname DRS_SimulatorE: $Message"

        $UdpClient = New-Object System.Net.Sockets.UdpClient
        $UdpClient.Connect($script:SyslogServer, $script:SyslogPort)

        $Encoding = [System.Text.Encoding]::UTF8
        $BytesSyslogMessage = $Encoding.GetBytes($SyslogMsg)

        if ($BytesSyslogMessage.Length -gt 1024) {
            $BytesSyslogMessage = $BytesSyslogMessage[0..1023]
        }

        $null = $UdpClient.Send($BytesSyslogMessage, $BytesSyslogMessage.Length)
        $UdpClient.Close()
        $UdpClient.Dispose()

    } catch {
        Write-Warning "Syslog send error: $($_.Exception.Message)"
    }

    if ($AlsoWriteHost) {
        Write-Host $Message
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet('Info','Warning','Error','Debug')]
        [string]$Level = 'Info'
    )

    $SeverityMap = @{
        'Error'   = 3
        'Warning' = 4
        'Info'    = 6
        'Debug'   = 7
    }

    $Severity = $SeverityMap[$Level]

    Send-SyslogMessage -Message $Message -Severity $Severity -AlsoWriteHost

    if ($Level -eq 'Warning') {
        Write-Host $Message -ForegroundColor Yellow
    } elseif ($Level -eq 'Error') {
        Write-Host $Message -ForegroundColor Red
    }
}
#endregion


#region Memory Management Functions (v1.32)
function Invoke-MemoryCleanup {
    param(
        [switch]$Force
    )

    try {
        $beforeMem = [System.GC]::GetTotalMemory($false) / 1MB

        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()

        $afterMem = [System.GC]::GetTotalMemory($false) / 1MB
        $freed = $beforeMem - $afterMem

        Write-Log -Message "[MEMORY] Garbage collection performed: ${freed:F2} MB freed (before: ${beforeMem:F2} MB, after: ${afterMem:F2} MB)" -Level Info

        $script:lastGarbageCollection = Get-Date
    }
    catch {
        Write-Log -Message "[MEMORY] Error during garbage collection: $_" -Level Warning
    }
}

function Invoke-VCenterRecycle {
    param(
        [Parameter(Mandatory)]
        [string]$VCenter,

        [Parameter(Mandatory)]
        $Credential
    )

    try {
        Write-Log -Message "[VCENTER] Recycling vCenter connection..." -Level Info

        $currentConnections = $global:DefaultVIServers
        if ($currentConnections) {
            foreach ($conn in $currentConnections) {
                Disconnect-VIServer -Server $conn -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log -Message "[VCENTER] Disconnected from $($conn.Name)" -Level Info
            }
        }

        Start-Sleep -Seconds 5

        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        Write-Log -Message "[VCENTER] Reconnecting to $VCenter..." -Level Info
        Connect-VIServer -Server $VCenter -Credential $Credential -ErrorAction Stop | Out-Null

        Write-Log -Message "[VCENTER] Reconnection successful" -Level Info
        $script:lastVCenterRecycle = Get-Date

        return $true
    }
    catch {
        Write-Log -Message "[VCENTER] Error during recycling: $_" -Level Error
        Write-Log -Message "[VCENTER] Attempting to reconnect..." -Level Warning

        try {
            Connect-VIServer -Server $VCenter -Credential $Credential -ErrorAction Stop | Out-Null
            Write-Log -Message "[VCENTER] Emergency reconnection successful" -Level Info
            return $true
        }
        catch {
            Write-Log -Message "[VCENTER] Emergency reconnection failed: $_" -Level Error
            return $false
        }
    }
}

function Show-MemoryUsage {
    try {
        $process = Get-Process -Id $PID
        $memoryMB = $process.WorkingSet64 / 1MB
        $peakMemoryMB = $process.PeakWorkingSet64 / 1MB
        $privateMemoryMB = $process.PrivateMemorySize64 / 1MB

        Write-Log -Message "[MEMORY] Current memory usage: ${memoryMB:F2} MB (peak: ${peakMemoryMB:F2} MB, private: ${privateMemoryMB:F2} MB)" -Level Info

        if ($memoryMB -gt 2048) {
            Write-Log -Message "[MEMORY] WARNING: High memory usage (>${memoryMB:F2} MB)" -Level Warning
            Invoke-MemoryCleanup
        }

        $script:lastMemoryMonitor = Get-Date
    }
    catch {
        Write-Log -Message "[MEMORY] Error during memory monitoring: $_" -Level Warning
    }
}

function Clear-StatisticsCache {
    try {
        if (Get-Command Clear-Variable -ErrorAction SilentlyContinue) {
            Get-Variable -Scope Global | Where-Object {
                $_.Name -like '*Stat*' -or $_.Name -like '*Metric*'
            } | ForEach-Object {
                try {
                    Remove-Variable -Name $_.Name -Scope Global -ErrorAction SilentlyContinue
                }
                catch {}
            }
        }

        Write-Log -Message "[MEMORY] Statistics cache cleared" -Level Debug
    }
    catch {
        Write-Log -Message "[MEMORY] Error during cache cleanup: $_" -Level Warning
    }
}
#endregion


#region vCenter Connection
Write-Log -Message "Connecting to $VCenter ..."

$credential = Import-Clixml -Path C:\scripts\cred_op
Connect-VIServer -Server $vCenter -Credential $credential | Out-Null

$clusterNameLocal = $ClusterName
Write-Log -Message "Starting pseudo-DRS on cluster '$clusterNameLocal' (Ctrl+C to stop)."

$script:wasInEvacuationMode = $false
$script:evacuationQueue = @{}
$script:lastAffinityLoad = $null
$script:lastAntiAffinityLoad = $null
$script:lastVmToHostLoad = $null
$script:affinityGroups = @()
$script:antiAffinityGroups = @()
$script:vmToHostRules = @()
#endregion


# ---------- Affinity file management ----------

function Read-AffinityList {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        # FIX-4: -Level Warning was previously embedded inside the message string
        Write-Log -Message "Affinity file not found: $FilePath" -Level Warning
        return @()
    }

    $groups = @()
    $lines = Get-Content -Path $FilePath -ErrorAction SilentlyContinue

    foreach ($line in $lines) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $vmNames = $line -split '\s+' | Where-Object { $_ -ne '' }
        if ($vmNames.Count -gt 1) {
            $groups += ,@($vmNames)
        }
    }

    Write-Log -Message "Affinity file loaded: $($groups.Count) group(s) detected"
    return $groups
}

function Get-AffinityTargetHost {
    param(
        [string]$VMName,
        [array]$AffinityGroups,
        [Parameter(Mandatory)]
        [string]$ClusterName,
        [Parameter(Mandatory)]
        $VM
    )

    if (-not $AffinityGroups -or $AffinityGroups.Count -eq 0) {
        return $null
    }

    $groupVMs = $null
    foreach ($group in $AffinityGroups) {
        if ($group -contains $VMName) {
            $groupVMs = $group
            break
        }
    }

    if (-not $groupVMs) { return $null }

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction SilentlyContinue
    if (-not $clusterObj) { return $null }

    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue

    $candidateHosts = @()

    foreach ($vmNameInGroup in $groupVMs) {
        if ($vmNameInGroup -eq $VMName) { continue }

        $groupVM = $allClusterVMs | Where-Object { $_.Name -eq $vmNameInGroup -and $_.PowerState -eq 'PoweredOn' }

        if ($groupVM -and $groupVM.VMHost) {
            if (Test-StorageCompatible -VM $VM -TargetHost $groupVM.VMHost) {
                $candidateHosts += $groupVM.VMHost
            }
        }
    }

    if ($candidateHosts.Count -eq 0) { return $null }

    $bestHost = $candidateHosts | Group-Object -Property Name |
                Sort-Object Count -Descending |
                Select-Object -First 1 -ExpandProperty Name

    return ($candidateHosts | Where-Object { $_.Name -eq $bestHost } | Select-Object -First 1)
}

function Enforce-AffinityGroups {
    param(
        [string]$ClusterName,
        [array]$AffinityGroups,
        [int]$MaxMigrations,
        [string[]]$NameBlacklistPatterns,
        [string[]]$TagBlacklistNames,
        [switch]$IncludeNetwork,
        [switch]$DryRun
    )

    if (-not $AffinityGroups -or $AffinityGroups.Count -eq 0) {
        return
    }

    Write-Log -Message "[AFFINITY] Checking and grouping VMs according to affinity rules..."

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $allHosts = Get-VMHost -Location $clusterObj | Where-Object { $_.ConnectionState -eq 'Connected' }
    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue

    $movesDone = 0

    foreach ($group in $AffinityGroups) {
        if ($movesDone -ge $MaxMigrations) {
            Write-Log -Message "[AFFINITY] Migration limit reached ($MaxMigrations), continuing next cycle."
            return
        }

        $groupVMs = @()
        foreach ($vmName in $group) {
            $vm = $allClusterVMs | Where-Object { $_.Name -eq $vmName -and $_.PowerState -eq 'PoweredOn' }

            if ($vm -and -not (Test-VmBlacklisted -VM $vm `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames)) {
                $groupVMs += $vm
            }
        }

        if ($groupVMs.Count -le 1) { continue }

        $hostCandidates = @{}

        foreach ($vm in $groupVMs) {
            $currentHost = $vm.VMHost.Name
            if (-not $hostCandidates.ContainsKey($currentHost)) {
                $compatibleCount = 0
                foreach ($testVM in $groupVMs) {
                    if (Test-StorageCompatible -VM $testVM -TargetHost $vm.VMHost) {
                        $compatibleCount++
                    }
                }
                $hostCandidates[$currentHost] = @{
                    Host = $vm.VMHost
                    CurrentVMCount = 1
                    CompatibleVMCount = $compatibleCount
                }
            } else {
                $hostCandidates[$currentHost].CurrentVMCount++
            }
        }

        $bestCandidate = $hostCandidates.GetEnumerator() |
            Sort-Object -Property @{Expression={$_.Value.CompatibleVMCount}; Descending=$true},
                                  @{Expression={$_.Value.CurrentVMCount}; Descending=$true} |
            Select-Object -First 1

        if (-not $bestCandidate) {
            # FIX-4: -Level Warning was previously embedded inside the message string
            Write-Log -Message "[AFFINITY] Cannot find compatible host for group [$($group -join ', ')]" -Level Warning
            continue
        }

        $targetHost = $bestCandidate.Value.Host
        $targetHostName = $bestCandidate.Key

        Write-Log -Message "[AFFINITY] Group [$($group -join ', ')] - Target host: $targetHostName ($($bestCandidate.Value.CompatibleVMCount)/$($groupVMs.Count) compatible VMs)"

        foreach ($vm in $groupVMs) {
            if ($movesDone -ge $MaxMigrations) {
                Write-Log -Message "[AFFINITY] Migration limit reached, continuing next cycle."
                return
            }

            if ($vm.VMHost.Name -eq $targetHostName) { continue }

            if (Test-VmMigrating -VM $vm) {
                Write-Log -Message "[AFFINITY] VM '$($vm.Name)' already migrating, skipped."
                continue
            }

            if (-not (Test-StorageCompatible -VM $vm -TargetHost $targetHost)) {
                # FIX-4: -Level Warning was previously embedded inside the message string
                Write-Log -Message "[AFFINITY] VM '$($vm.Name)' storage-incompatible with $targetHostName. Searching for alternative host..." -Level Warning

                $alternativeHost = $null
                foreach ($testHost in $allHosts) {
                    if ($testHost.Name -eq $vm.VMHost.Name) { continue }

                    if (Test-StorageCompatible -VM $vm -TargetHost $testHost) {
                        $vmsOnHost = $groupVMs | Where-Object { $_.VMHost.Name -eq $testHost.Name }
                        if ($vmsOnHost.Count -gt 0) {
                            $alternativeHost = $testHost
                            break
                        }
                    }
                }

                if (-not $alternativeHost) {
                    foreach ($testHost in $allHosts) {
                        if ($testHost.Name -eq $vm.VMHost.Name) { continue }
                        if (Test-StorageCompatible -VM $vm -TargetHost $testHost) {
                            $alternativeHost = $testHost
                            break
                        }
                    }
                }

                if ($alternativeHost) {
                    $targetHost = $alternativeHost
                    $targetHostName = $alternativeHost.Name
                } else {
                    # FIX-4: -Level Warning was previously embedded inside the message string
                    Write-Log -Message "[AFFINITY] No compatible host found for '$($vm.Name)'. Migration skipped." -Level Warning
                    continue
                }
            }

            $msg = "[AFFINITY] Grouping VM '$($vm.Name)' : $($vm.VMHost.Name) -> $targetHostName"

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            } else {
                Write-Host $msg
                Move-VM -VM $vm -Destination $targetHost -RunAsync | Out-Null
            }

            $movesDone++
        }
    }

    if ($movesDone -eq 0) {
        Write-Log -Message "[AFFINITY] All groups are already properly grouped."
    }
}

# ---------- Anti-affinity file management ----------

function Read-AntiAffinityList {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        # FIX-4: -Level Warning was previously embedded inside the message string
        Write-Log -Message "Anti-affinity file not found: $FilePath" -Level Warning
        return @()
    }

    $groups = New-Object System.Collections.ArrayList
    $lines = Get-Content -Path $FilePath -ErrorAction SilentlyContinue

    foreach ($line in $lines) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $vmNames = $line -split '\s+' | Where-Object { $_ -ne '' }
        if ($vmNames.Count -gt 1) {
            $groupObj = [PSCustomObject]@{
                VMs = $vmNames
            }
            [void]$groups.Add($groupObj)
            Write-Log -Message "[ANTI-AFFINITY] Group loaded: [$($vmNames -join ', ')] ($($vmNames.Count) VMs)"
        } elseif ($vmNames.Count -eq 1) {
            Write-Log -Message "[ANTI-AFFINITY] Line skipped (single VM): $($vmNames[0])" -Level Warning
        }
    }

    Write-Log -Message "Anti-affinity file loaded: $($groups.Count) group(s) detected"

    return @($groups.ToArray())
}

function Enforce-AntiAffinityGroups {
    param(
        [string]$ClusterName,
        [array]$AntiAffinityGroups,
        [int]$MaxMigrations,
        [string[]]$NameBlacklistPatterns,
        [string[]]$TagBlacklistNames,
        [switch]$IncludeNetwork,
        [switch]$DryRun
    )

    if (-not $AntiAffinityGroups -or $AntiAffinityGroups.Count -eq 0) {
        return
    }

    Write-Log -Message "[ANTI-AFFINITY] Checking and separating VMs according to anti-affinity rules..."

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $allHosts = Get-VMHost -Location $clusterObj | Where-Object { $_.ConnectionState -eq 'Connected' }
    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue

    if ($allHosts.Count -lt 2) {
        # FIX-4: -Level Warning was previously embedded inside the message string
        Write-Log -Message "[ANTI-AFFINITY] Less than 2 hosts available, cannot apply rules." -Level Warning
        return
    }

    $movesDone = 0
    $groupIndex = 0

    foreach ($groupObj in $AntiAffinityGroups) {
        $groupIndex++

        if ($movesDone -ge $MaxMigrations) {
            Write-Log -Message "[ANTI-AFFINITY] Migration limit reached ($MaxMigrations), continuing next cycle."
            return
        }

        $group = $groupObj.VMs

        Write-Log -Message "[ANTI-AFFINITY] ========================================="
        Write-Log -Message "[ANTI-AFFINITY] Processing group $groupIndex/$($AntiAffinityGroups.Count)"
        Write-Log -Message "[ANTI-AFFINITY] Expected VMs: [$($group -join ', ')]"

        $groupVMs = @()
        foreach ($vmName in $group) {
            $matchingVMs = $allClusterVMs | Where-Object {
                $_.Name -eq $vmName -and $_.PowerState -eq 'PoweredOn'
            }

            if ($matchingVMs) {
                $vm = $matchingVMs | Select-Object -First 1

                if (-not (Test-VmBlacklisted -VM $vm `
                        -NameBlacklistPatterns $NameBlacklistPatterns `
                        -TagBlacklistNames $TagBlacklistNames)) {
                    $groupVMs += $vm
                }
            }
        }

        if ($groupVMs.Count -le 1) {
            Write-Log -Message "[ANTI-AFFINITY] Group skipped (less than 2 active VMs)"
            continue
        }

        $vmsByHost = $groupVMs | Group-Object -Property { $_.VMHost.Name }
        $violations = $vmsByHost | Where-Object { $_.Count -gt 1 }

        if (-not $violations) {
            Write-Log -Message "[ANTI-AFFINITY] OK - All VMs are on different hosts"
            continue
        }

        Write-Log -Message "[ANTI-AFFINITY] VIOLATION DETECTED!"

        foreach ($violation in $violations) {
            if ($movesDone -ge $MaxMigrations) { return }

            $vmsOnSameHost = $violation.Group
            $vmsToMove = $vmsOnSameHost | Select-Object -Skip 1

            foreach ($vm in $vmsToMove) {
                if ($movesDone -ge $MaxMigrations) { return }
                if (Test-VmMigrating -VM $vm) { continue }

                $hostsWithGroupVMs = $groupVMs | Where-Object { $_.Name -ne $vm.Name } |
                                     Select-Object -ExpandProperty VMHost -Unique

                $candidateHosts = $allHosts | Where-Object {
                    $candidateHost = $_

                    if ($candidateHost.Name -eq $vm.VMHost.Name) { return $false }
                    if ($hostsWithGroupVMs.Name -contains $candidateHost.Name) { return $false }

                    return (Test-StorageCompatible -VM $vm -TargetHost $candidateHost)
                }

                if (-not $candidateHosts) { continue }

                $bestTarget = Get-BestTargetHost -ESXHosts $candidateHosts -IncludeNetwork:$IncludeNetwork

                $msg = "[ANTI-AFFINITY] Migrating VM '$($vm.Name)' : $($vm.VMHost.Name) -> $($bestTarget.ESXHost.Name)"

                if ($DryRun) {
                    Write-Log -Message "[DRYRUN] $msg"
                } else {
                    Write-Host $msg
                    try {
                        Move-VM -VM $vm -Destination $bestTarget.ESXHost -RunAsync -ErrorAction Stop | Out-Null
                    } catch {
                        # FIX-4: -Level Warning was previously embedded inside the message string
                        Write-Log -Message "[ANTI-AFFINITY] Migration error: $_" -Level Warning
                        continue
                    }
                }

                $movesDone++
            }
        }
    }

    if ($movesDone -eq 0) {
        Write-Log -Message "[ANTI-AFFINITY] All anti-affinity rules are respected"
    }
}

function Get-AntiAffinityCompatibleHosts {
    param(
        [Parameter(Mandatory)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [Parameter(Mandatory)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl[]]$TargetHosts,
        [array]$AntiAffinityGroups,
        [string]$ClusterName
    )

    if (-not $AntiAffinityGroups -or $AntiAffinityGroups.Count -eq 0) {
        return $TargetHosts
    }

    $vmGroup = $null
    foreach ($groupObj in $AntiAffinityGroups) {
        $group = $groupObj.VMs
        foreach ($vmNameInGroup in $group) {
            if ($vmNameInGroup -eq $VM.Name) {
                $vmGroup = $group
                break
            }
        }
        if ($vmGroup) { break }
    }

    if (-not $vmGroup) { return $TargetHosts }

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction SilentlyContinue
    if (-not $clusterObj) { return $TargetHosts }

    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue

    $hostsToExclude = @()
    foreach ($vmNameInGroup in $vmGroup) {
        if ($vmNameInGroup -eq $VM.Name) { continue }

        $matchingVMs = $allClusterVMs | Where-Object {
            $_.Name -eq $vmNameInGroup -and $_.PowerState -eq 'PoweredOn'
        }

        if ($matchingVMs) {
            $groupVM = $matchingVMs | Select-Object -First 1
            if ($groupVM.VMHost) {
                $hostsToExclude += $groupVM.VMHost.Name
            }
        }
    }

    $compatibleHosts = $TargetHosts | Where-Object {
        $hostsToExclude -notcontains $_.Name
    }

    return $compatibleHosts
}

# ---------- VM-to-Host file management ----------

function Read-VmToHostList {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        # FIX-4: -Level Warning was previously embedded inside the message string
        Write-Log -Message "VM-to-Host file not found: $FilePath" -Level Warning
        return @()
    }

    $rules = New-Object System.Collections.ArrayList
    $lines = Get-Content -Path $FilePath -ErrorAction SilentlyContinue

    foreach ($line in $lines) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $elements = $line -split '\s+' | Where-Object { $_ -ne '' }
        if ($elements.Count -lt 2) { continue }

        $vms = @()
        $hosts = @()

        foreach ($elem in $elements) {
            if ($elem -match 'esx|host|-mgt|\.') {
                $hosts += $elem
            } else {
                $vms += $elem
            }
        }

        if ($vms.Count -eq 0 -or $hosts.Count -eq 0) { continue }

        $ruleObj = [PSCustomObject]@{
            VMs = $vms
            Hosts = $hosts
        }

        [void]$rules.Add($ruleObj)
        Write-Log -Message "[VM-TO-HOST] Rule loaded: VMs=[$($vms -join ', ')] -> Hosts=[$($hosts -join ', ')]"
    }

    Write-Log -Message "VM-to-Host file loaded: $($rules.Count) rule(s) detected"

    return @($rules.ToArray())
}

function Get-VmToHostTargetHost {
    param(
        [string]$VMName,
        [array]$VmToHostRules,
        [Parameter(Mandatory)]
        [string]$ClusterName,
        [Parameter(Mandatory)]
        $VM
    )

    if (-not $VmToHostRules -or $VmToHostRules.Count -eq 0) {
        return $null
    }

    $matchingRule = $null
    foreach ($ruleObj in $VmToHostRules) {
        if ($ruleObj.VMs -contains $VMName) {
            $matchingRule = $ruleObj
            break
        }
    }

    if (-not $matchingRule) { return $null }

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction SilentlyContinue
    if (-not $clusterObj) { return $null }

    $allClusterHosts = Get-VMHost -Location $clusterObj -ErrorAction SilentlyContinue
    $allowedHosts = @()

    foreach ($hostName in $matchingRule.Hosts) {
        $matchingHost = $allClusterHosts | Where-Object {
            $_.Name -eq $hostName -or $_.Name -like "*$hostName*"
        } | Select-Object -First 1

        if ($matchingHost -and $matchingHost.ConnectionState -eq 'Connected') {
            if (Test-StorageCompatible -VM $VM -TargetHost $matchingHost) {
                $allowedHosts += $matchingHost
            }
        }
    }

    if ($allowedHosts.Count -eq 0) { return $null }
    if ($allowedHosts.Name -contains $VM.VMHost.Name) { return $null }

    $bestHost = $allowedHosts | ForEach-Object {
        Get-HostLoad -ESXHost $_ -IncludeNetwork:$false
    } | Sort-Object LoadScore | Select-Object -First 1

    return $bestHost.ESXHost
}

function Enforce-VmToHostRules {
    param(
        [string]$ClusterName,
        [array]$VmToHostRules,
        [int]$MaxMigrations,
        [string[]]$NameBlacklistPatterns,
        [string[]]$TagBlacklistNames,
        [switch]$IncludeNetwork,
        [switch]$DryRun
    )

    if (-not $VmToHostRules -or $VmToHostRules.Count -eq 0) {
        return
    }

    Write-Log -Message "[VM-TO-HOST] Checking and applying VM-to-Host rules..."

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue
    $allClusterHosts = Get-VMHost -Location $clusterObj | Where-Object { $_.ConnectionState -eq 'Connected' }

    $movesDone = 0
    $ruleIndex = 0

    foreach ($ruleObj in $VmToHostRules) {
        $ruleIndex++

        if ($movesDone -ge $MaxMigrations) {
            Write-Log -Message "[VM-TO-HOST] Migration limit reached ($MaxMigrations)"
            return
        }

        $vms = $ruleObj.VMs
        $hosts = $ruleObj.Hosts

        Write-Log -Message "[VM-TO-HOST] Rule $ruleIndex : VMs=[$($vms -join ', ')] -> Hosts=[$($hosts -join ', ')]"

        $allowedHostObjects = @()
        foreach ($hostName in $hosts) {
            $matchingHost = $allClusterHosts | Where-Object {
                $_.Name -eq $hostName -or $_.Name -like "*$hostName*"
            } | Select-Object -First 1

            if ($matchingHost) {
                $allowedHostObjects += $matchingHost
            }
        }

        if ($allowedHostObjects.Count -eq 0) { continue }

        foreach ($vmName in $vms) {
            if ($movesDone -ge $MaxMigrations) { return }

            $vm = $allClusterVMs | Where-Object {
                $_.Name -eq $vmName -and $_.PowerState -eq 'PoweredOn'
            } | Select-Object -First 1

            if (-not $vm) { continue }
            if (Test-VmBlacklisted -VM $vm -NameBlacklistPatterns $NameBlacklistPatterns -TagBlacklistNames $TagBlacklistNames) { continue }

            $currentHost = $vm.VMHost
            if ($allowedHostObjects.Name -contains $currentHost.Name) { continue }

            if (Test-VmMigrating -VM $vm) { continue }

            $compatibleHosts = $allowedHostObjects | Where-Object {
                Test-StorageCompatible -VM $vm -TargetHost $_
            }

            if ($compatibleHosts.Count -eq 0) { continue }

            $bestTarget = $compatibleHosts | ForEach-Object {
                Get-HostLoad -ESXHost $_ -IncludeNetwork:$IncludeNetwork
            } | Sort-Object LoadScore | Select-Object -First 1

            $msg = "[VM-TO-HOST] $($vm.Name) : $($currentHost.Name) -> $($bestTarget.ESXHost.Name)"

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            } else {
                Write-Host $msg
                try {
                    Move-VM -VM $vm -Destination $bestTarget.ESXHost -RunAsync -ErrorAction Stop | Out-Null
                } catch {
                    continue
                }
            }

            $movesDone++
        }
    }

    if ($movesDone -eq 0) {
        Write-Log -Message "[VM-TO-HOST] All VM-to-Host rules are respected"
    }
}

# ---------- Host load helpers ----------

function Get-HostLoad {
    param(
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]$ESXHost,
        [switch]$IncludeNetwork
    )

    $summary = $ESXHost.ExtensionData.Summary

    # v1.38: OverallCpuUsage is total MHz across ALL cores; divide by (CpuMhz * NumCpuCores)
    # to get a real percentage. The old formula (/ CpuMhz alone) gave values like 300-700%
    # on multi-core hosts, which silently broke threshold comparisons and delta balancing.
    $numCpuCores = $summary.Hardware.NumCpuCores
    if (-not $numCpuCores -or $numCpuCores -le 0) { $numCpuCores = 1 }
    $cpuUsagePct = [math]::Min(100, [int](
        $summary.QuickStats.OverallCpuUsage * 100 /
        ($summary.Hardware.CpuMhz * $numCpuCores)
    ))
    $memUsagePct = [int](
        $summary.QuickStats.OverallMemoryUsage * 100 /
        ($summary.Hardware.MemorySize / 1MB)
    )

    $netUsageKbps = 0
    if ($IncludeNetwork) {
        $stat = Get-Stat -Entity $ESXHost `
                         -Stat 'net.usage.average' `
                         -Realtime -MaxSamples 1 `
                         -ErrorAction SilentlyContinue
        if ($stat) {
            $netUsageKbps = [int]($stat.Value | Measure-Object -Average).Average
        }

        if ($stat) {
            Remove-Variable -Name stat -ErrorAction SilentlyContinue
        }
    }

    $normNet = [int]($netUsageKbps / 100)
    # v1.37: memory-weighted score (0.25 CPU / 0.65 Mem / 0.10 Net)
    $score = [int](
        (0.25 * $cpuUsagePct) +
        (0.65 * $memUsagePct) +
        (0.10 * $normNet)
    )

    [PSCustomObject]@{
        ESXHost      = $ESXHost
        CpuPct       = $cpuUsagePct
        MemPct       = $memUsagePct
        NetKbps      = $netUsageKbps
        LoadScore    = $score
        PoweredOnVMs = ($ESXHost | Get-VM | Where-Object {$_.PowerState -eq 'PoweredOn'}).Count
    }
}

function Get-BestTargetHost {
    param(
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl[]]$ESXHosts,
        [switch]$IncludeNetwork
    )

    $ESXHosts | ForEach-Object {
        Get-HostLoad -ESXHost $_ -IncludeNetwork:$IncludeNetwork
    } | Sort-Object LoadScore | Select-Object -First 1
}

# ---------- VM blacklist helpers ----------

function Test-VmBlacklisted {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [string[]]$NameBlacklistPatterns,
        [string[]]$TagBlacklistNames
    )

    if ($NameBlacklistPatterns) {
        foreach ($pat in $NameBlacklistPatterns) {
            if ($VM.Name -match $pat) { return $true }
        }
    }

    if ($TagBlacklistNames) {
        $tags = Get-TagAssignment -Entity $VM -ErrorAction SilentlyContinue
        if ($tags) {
            $vmTagNames = $tags.Tag.Name
            foreach ($t in $TagBlacklistNames) {
                if ($vmTagNames -contains $t) { return $true }
            }
        }
    }

    return $false
}

# ---------- Check VM migration in progress ----------

function Test-VmMigrating {
    param(
        [Parameter(Mandatory)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    $tasks = Get-Task -Status Running,Queued -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.DescriptionId -match "VirtualMachine.relocate" -or
             $_.DescriptionId -match "VirtualMachine.migrate") -and
            $_.Entity.Id -eq $VM.Id
        }

    if ($tasks) { return $true }

    $vmView = Get-View -Id $VM.Id -ErrorAction SilentlyContinue
    if ($vmView -and $vmView.Runtime.PowerState -eq 'poweredOn') {
        $recentTasks = $vmView.RecentTask
        if ($recentTasks) {
            foreach ($taskMoRef in $recentTasks) {
                $taskView = Get-View -Id $taskMoRef -ErrorAction SilentlyContinue
                if ($taskView -and
                    ($taskView.Info.State -eq 'running' -or $taskView.Info.State -eq 'queued') -and
                    ($taskView.Info.DescriptionId -match 'VirtualMachine.relocate' -or
                     $taskView.Info.DescriptionId -match 'VirtualMachine.migrate')) {
                    return $true
                }
            }
        }
    }

    return $false
}

# ---------- VM / target host storage compatibility ----------

function Test-StorageCompatible {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]$TargetHost
    )

    $targetDsNames = ($TargetHost | Get-Datastore | Select-Object -ExpandProperty Name)

    $vmDsNames = $VM.ExtensionData.Layout.Disk | ForEach-Object {
        ($_.DiskFile | ForEach-Object {
            ($_ -split '\]')[0].TrimStart('[').Trim()
        })
    } | Sort-Object -Unique

    foreach ($ds in $vmDsNames) {
        if ($ds -like 'SHARED_DS*') { continue }

        if ($targetDsNames -notcontains $ds) {
            return $false
        }
    }

    return $true
}

# ---------- vMotion count in progress ----------

function Get-CurrentVmotionCount {
    param([string]$ClusterName)

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction SilentlyContinue
    if (-not $clusterObj) { return 0 }

    $clusterVms = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue
    if (-not $clusterVms) { return 0 }

    $tasks = Get-Task -Status Running,Queued -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.DescriptionId -match "VirtualMachine.relocate" -or
             $_.DescriptionId -match "VirtualMachine.migrate") -and
            $clusterVms -contains $_.Entity
        }

    return ($tasks | Measure-Object).Count
}

# ---------- Detection of hosts to evacuate ----------

function Get-HostsNeedingEvacuation {
    param(
        [string]$ClusterName,
        [int]$RecentMinutes = 120
    )

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $allHosts   = Get-VMHost -Location $clusterObj

    # 1. Direct detection: hosts already in Maintenance or NotResponding state
    $hostsMaintenance = $allHosts | Where-Object {
        $_.ConnectionState -eq 'Maintenance' -or
        $_.ConnectionState -eq 'NotResponding'
    }

    # 2. Detection via running tasks
    $enterTasks = Get-Task -Status Running,Queued -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DescriptionId -match "HostSystem.enterMaintenanceMode"
        }

    $hostsFromTasks = @()
    foreach ($t in $enterTasks) {
        if ($t.Entity -and $t.Entity -is [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]) {
            $hostsFromTasks += $t.Entity
        } elseif ($t.Entity -and $t.Entity.Name) {
            $h = Get-VMHost -Name $t.Entity.Name -ErrorAction SilentlyContinue
            if ($h) { $hostsFromTasks += $h }
        }
    }

    # 3. Event-based detection (with extended time window)
    $startEvt = (Get-Date).AddMinutes(-$RecentMinutes)
    $maintenanceEvents = Get-VIEvent -Start $startEvt -Entity $allHosts -MaxSamples 1000 -ErrorAction SilentlyContinue |
        Where-Object {
            $_ -is [VMware.Vim.EnteredMaintenanceModeEvent] -or
            $_ -is [VMware.Vim.EnteringMaintenanceModeEvent] -or
            $_ -is [VMware.Vim.ExitMaintenanceModeEvent] -or
            $_.FullFormattedMessage -match "Enter maintenance mode" -or
            $_.FullFormattedMessage -match "entered Maintenance Mode" -or
            $_.FullFormattedMessage -match "exited Maintenance Mode"
        }

    $hostsFromEvents = $maintenanceEvents |
        Sort-Object -Property CreatedTime |
        Group-Object -Property {
            if ($_.Host -and $_.Host.Name) {
                $_.Host.Name
            } elseif ($_.HostName) {
                $_.HostName
            } else {
                $null
            }
        } | ForEach-Object {
            if (-not $_.Name) { return }
            $hostName = $_.Name
            $lastEvt = $_.Group[-1]

            if ($lastEvt -is [VMware.Vim.ExitMaintenanceModeEvent] -or
                $lastEvt.FullFormattedMessage -match "exited Maintenance Mode") {
                return
            }

            if ($lastEvt.CreatedTime -ge $startEvt) {
                if ($lastEvt -is [VMware.Vim.EnteredMaintenanceModeEvent] -or
                    $lastEvt -is [VMware.Vim.EnteringMaintenanceModeEvent] -or
                    $lastEvt.FullFormattedMessage -match "Enter maintenance mode" -or
                    $lastEvt.FullFormattedMessage -match "entered Maintenance Mode") {

                    $h = Get-VMHost -Name $hostName -ErrorAction SilentlyContinue
                    if ($h) { $h }
                }
            }
        }

    # 4. Also check the persistent evacuation queue
    $hostsFromQueue = @()
    foreach ($hostName in $script:evacuationQueue.Keys) {
        $esxHost = Get-VMHost -Name $hostName -ErrorAction SilentlyContinue
        if ($esxHost) {
            # FIX-3: was "$host" (automatic variable = the Windows host), must be $esxHost
            $hostsFromQueue += $esxHost
        }
    }

    # Aggregation of all sources
    $allCandidates = @()
    $allCandidates += $hostsMaintenance
    $allCandidates += $hostsFromTasks
    $allCandidates += $hostsFromEvents
    $allCandidates += $hostsFromQueue

    $allCandidates = $allCandidates |
        Where-Object { $_ -is [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl] } |
        Select-Object -Unique

    return $allCandidates
}


function Evacuate-Hosts {
    param(
        [Parameter(Mandatory)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl[]]$HostsToEvacuate,
        [string]$ClusterName,
        [int]$MaxMigrationsEvacTotal,
        [string[]]$NameBlacklistPatterns,
        [string[]]$TagBlacklistNames,
        [array]$AffinityGroups,
        [array]$AntiAffinityGroups,
        [array]$VmToHostRules,
        [switch]$IncludeNetwork,
        [switch]$DryRun
    )

    if (-not $HostsToEvacuate) { return }

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop

    foreach ($mmESX in $HostsToEvacuate) {
        if (-not $script:evacuationQueue.ContainsKey($mmESX.Name)) {

            Write-Log -Message "[EVACUATION] New host detected in maintenance: $($mmESX.Name)"
            Write-Log -Message "[EVACUATION] Initializing the evacuation queue..."

            $allVMsOnHost = $mmESX | Get-VM | Where-Object {
                -not (Test-VmBlacklisted -VM $_ `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames)
            }

            $vmsPoweredOn = $allVMsOnHost | Where-Object { $_.PowerState -eq 'PoweredOn' }
            $vmsPoweredOff = $allVMsOnHost | Where-Object { $_.PowerState -eq 'PoweredOff' }

            $script:evacuationQueue[$mmESX.Name] = @{
                VMs = @($vmsPoweredOn) + @($vmsPoweredOff)
                VMsInitialCount = $vmsPoweredOn.Count + $vmsPoweredOff.Count
                VMsPoweredOnCount = $vmsPoweredOn.Count
                VMsPoweredOffCount = $vmsPoweredOff.Count
                StartTime = Get-Date
                Host = $mmESX
            }

            Write-Log -Message "[EVACUATION] Queue initialized: $($vmsPoweredOn.Count) VM(s) ON + $($vmsPoweredOff.Count) VM(s) OFF = $($vmsPoweredOn.Count + $vmsPoweredOff.Count) total"
        }
    }

    $nbEnCours = Get-CurrentVmotionCount -ClusterName $ClusterName
    $slotsDispoInitial = $MaxMigrationsEvacTotal - $nbEnCours

    if ($slotsDispoInitial -le 0) {
        Write-Log -Message "[EVACUATION] No vMotion slot available ($nbEnCours in progress / $MaxMigrationsEvacTotal max), waiting for next loop."
        return
    }

    $movesThisLoop = 0

    foreach ($hostName in @($script:evacuationQueue.Keys)) {

        $queueEntry = $script:evacuationQueue[$hostName]
        $mmESX = $queueEntry.Host

        $mmESX = Get-VMHost -Name $mmESX.Name -ErrorAction SilentlyContinue
        if (-not $mmESX) {
            Write-Log -Message "[EVACUATION] Host '$hostName' not found, removing from queue" -Level Warning
            $script:evacuationQueue.Remove($hostName)
            continue
        }

        Write-Log -Message "=========================================="
        Write-Log -Message "[EVACUATION] Processing host: $($mmESX.Name)"
        Write-Log -Message "[EVACUATION] State: $($mmESX.ConnectionState)"

        $targetHosts = Get-VMHost -Location $clusterObj |
            Where-Object { $_.ConnectionState -eq 'Connected' -and $_.Name -ne $mmESX.Name }

        if (-not $targetHosts) {
            Write-Log -Message "[EVACUATION] No target host available for $($mmESX.Name)" -Level Warning
            continue
        }

        $vmsInQueue = $queueEntry.VMs

        if (-not $vmsInQueue -or $vmsInQueue.Count -eq 0) {
            Write-Log -Message "[EVACUATION] Queue empty for $($mmESX.Name)"

            if ($mmESX.ConnectionState -eq 'Connected') {
                Write-Log -Message "[EVACUATION] Host $($mmESX.Name) exited maintenance mode AND queue empty -> Cleanup"
                $script:evacuationQueue.Remove($hostName)
            } else {
                Write-Log -Message "[EVACUATION] Host $($mmESX.Name) still in $($mmESX.ConnectionState), queue empty, monitoring maintained"
            }
            continue
        }

        $vmsStillOnHost = @()
        foreach ($vm in $vmsInQueue) {
            $refreshedVM = Get-VM -Name $vm.Name -ErrorAction SilentlyContinue

            if ($refreshedVM) {
                if ($refreshedVM.VMHost.Name -eq $mmESX.Name) {
                    $vmsStillOnHost += $refreshedVM
                } else {
                    Write-Log -Message "[EVACUATION] VM '$($vm.Name)' has been migrated to $($refreshedVM.VMHost.Name)"
                }
            } else {
                Write-Log -Message "[EVACUATION] VM '$($vm.Name)' not found (deleted?)" -Level Warning
            }
        }

        $queueEntry.VMs = $vmsStillOnHost

        $elapsed = (Get-Date) - $queueEntry.StartTime
        Write-Log -Message "[EVACUATION] Progress: $($queueEntry.VMsInitialCount - $vmsStillOnHost.Count)/$($queueEntry.VMsInitialCount) VMs evacuated (duration: $($elapsed.ToString('hh\:mm\:ss')))"
        Write-Log -Message "[EVACUATION] Remaining VMs: $($vmsStillOnHost.Count)"

        if ($vmsStillOnHost.Count -eq 0) {
            if ($mmESX.ConnectionState -eq 'Connected') {
                Write-Log -Message "[EVACUATION] EVACUATION COMPLETE for $($mmESX.Name) - Host exited maintenance mode"
                $script:evacuationQueue.Remove($hostName)
            }
            continue
        }

        $vmsPoweredOn = $vmsStillOnHost | Where-Object { $_.PowerState -eq 'PoweredOn' }
        $vmsPoweredOff = $vmsStillOnHost | Where-Object { $_.PowerState -eq 'PoweredOff' }

        Write-Log -Message "[EVACUATION] VMs to process: $($vmsPoweredOn.Count) ON, $($vmsPoweredOff.Count) OFF"

        foreach ($vm in $vmsPoweredOn) {

            if ($movesThisLoop -ge $MaxMigrationsEvacTotal) {
                Write-Log -Message "[EVACUATION] Migration limit reached ($MaxMigrationsEvacTotal), moving to next host."
                break
            }

            if ($movesThisLoop % 3 -eq 0) {
                $nbEnCours = Get-CurrentVmotionCount -ClusterName $ClusterName
                $slotsDispo = $MaxMigrationsEvacTotal - $nbEnCours - $movesThisLoop

                if ($slotsDispo -le 0) {
                    Write-Log -Message "[EVACUATION] vMotion slots saturated ($nbEnCours in progress + $movesThisLoop started = $($nbEnCours + $movesThisLoop)/$MaxMigrationsEvacTotal)"
                    break
                }
            }

            if (Test-VmMigrating -VM $vm) {
                Write-Log -Message "[EVACUATION] VM '$($vm.Name)' already migrating, skipped."
                continue
            }

            $compatibleTargets = $targetHosts | Where-Object {
                Test-StorageCompatible -VM $vm -TargetHost $_
            }

            if (-not $compatibleTargets -or $compatibleTargets.Count -eq 0) {
                Write-Log -Message "[EVACUATION|STORAGE] No storage-compatible target host for '$($vm.Name)' (Mem: $($vm.MemoryGB)GB). VM NOT MIGRABLE!" -Level Error
                continue
            }

            Write-Log -Message "[EVACUATION|STORAGE] VM '$($vm.Name)' has $($compatibleTargets.Count) storage-compatible host(s)" -Level Debug

            $bestTarget = $null
            $migrationReason = "STORAGE-FALLBACK"

            $vmToHostTarget = Get-VmToHostTargetHost -VMName $vm.Name -VmToHostRules $VmToHostRules -ClusterName $ClusterName -VM $vm
            if ($vmToHostTarget -and $compatibleTargets.Name -contains $vmToHostTarget.Name) {
                $bestTarget = Get-HostLoad -ESXHost $vmToHostTarget -IncludeNetwork:$IncludeNetwork
                $migrationReason = "VM-TO-HOST"
                Write-Log -Message "[EVACUATION|VM-TO-HOST] VM '$($vm.Name)' -> $($vmToHostTarget.Name) (rule respected)" -Level Debug
            }

            if (-not $bestTarget) {
                $affinityHost = Get-AffinityTargetHost -VMName $vm.Name -AffinityGroups $AffinityGroups -ClusterName $ClusterName -VM $vm
                if ($affinityHost -and $compatibleTargets.Name -contains $affinityHost.Name) {
                    $bestTarget = Get-HostLoad -ESXHost $affinityHost -IncludeNetwork:$IncludeNetwork
                    $migrationReason = "AFFINITY"
                    Write-Log -Message "[EVACUATION|AFFINITY] VM '$($vm.Name)' -> $($affinityHost.Name) (group respected)" -Level Debug
                }
            }

            if (-not $bestTarget) {
                $antiAffinityTargets = Get-AntiAffinityCompatibleHosts -VM $vm -TargetHosts $compatibleTargets -AntiAffinityGroups $AntiAffinityGroups -ClusterName $ClusterName
                if ($antiAffinityTargets -and $antiAffinityTargets.Count -gt 0) {
                    $bestTarget = Get-BestTargetHost -ESXHosts $antiAffinityTargets -IncludeNetwork:$IncludeNetwork
                    $migrationReason = "ANTI-AFFINITY"
                    Write-Log -Message "[EVACUATION|ANTI-AFFINITY] VM '$($vm.Name)' (anti-affinity respected)" -Level Debug
                }
            }

            if (-not $bestTarget) {
                $bestTarget = Get-BestTargetHost -ESXHosts $compatibleTargets -IncludeNetwork:$IncludeNetwork
                $migrationReason = "STORAGE-FALLBACK"
                Write-Log -Message "[EVACUATION|STORAGE-FALLBACK] VM '$($vm.Name)' -> $($bestTarget.ESXHost.Name) (no applicable rule, storage priority)" -Level Debug
            }

            if (-not $bestTarget -or -not $bestTarget.ESXHost) {
                Write-Log -Message "[EVACUATION|ERROR] Unable to select a host for '$($vm.Name)' (storage incompatible on ALL hosts?)" -Level Error
                continue
            }

            $msg = "[EVACUATION|$migrationReason] VM '$($vm.Name)' (PoweredOn, Mem: $($vm.MemoryGB)GB): $($vm.VMHost.Name) -> $($bestTarget.ESXHost.Name) (load: $($bestTarget.LoadScore))"

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            } else {
                Write-Host $msg
                try {
                    Move-VM -VM $vm -Destination $bestTarget.ESXHost -RunAsync -ErrorAction Stop | Out-Null
                    Write-Log -Message "[EVACUATION] Migration successfully started"
                    $movesThisLoop++
                } catch {
                    Write-Log -Message "[EVACUATION] Error during migration of '$($vm.Name)': $_" -Level Warning
                    continue
                }
            }
        }

        foreach ($vm in $vmsPoweredOff) {

            if ($movesThisLoop -ge $MaxMigrationsEvacTotal) {
                Write-Log -Message "[EVACUATION] Migration limit reached, PoweredOff VMs postponed."
                break
            }

            if (Test-VmMigrating -VM $vm) {
                Write-Log -Message "[EVACUATION] VM '$($vm.Name)' (PoweredOff) already migrating, skipped."
                continue
            }

            $compatibleTarget = $null
            foreach ($targetHost in $targetHosts) {
                if (Test-StorageCompatible -VM $vm -TargetHost $targetHost) {
                    $compatibleTarget = $targetHost
                    break
                }
            }

            if (-not $compatibleTarget) {
                Write-Log -Message "[EVACUATION] No storage-compatible target host for '$($vm.Name)' (PoweredOff). vMotion skipped." -Level Warning
                continue
            }

            $msg = "[EVACUATION|SIMPLE] VM '$($vm.Name)' (PoweredOff): $($vm.VMHost.Name) -> $($compatibleTarget.Name)"

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            } else {
                Write-Host $msg
                try {
                    Move-VM -VM $vm -Destination $compatibleTarget -RunAsync -ErrorAction Stop | Out-Null
                    Write-Log -Message "[EVACUATION] Migration successfully started"
                    $movesThisLoop++
                } catch {
                    Write-Log -Message "[EVACUATION] Error during migration of PoweredOff VM '$($vm.Name)': $_" -Level Warning
                    continue
                }
            }
        }

        Write-Log -Message "=========================================="
    }

    if ($movesThisLoop -gt 0) {
        Write-Log -Message "[EVACUATION] $movesThisLoop migration(s) started for evacuation"
    }
}


# ---------- Cluster rebalancing ----------

function Balance-Cluster {
    param(
        [string]$ClusterName,
        [int]$MaxMigrations,
        [int]$HighCpuPercent,    # Legacy - kept for backward compat, not used by balance logic
        [int]$LowCpuPercent,     # Legacy - kept for backward compat, not used by balance logic
        [int]$HighMemPercent,    # Legacy - kept for backward compat, not used by balance logic
        [int]$LowMemPercent,     # Legacy - kept for backward compat, not used by balance logic
        [int]$DeltaTriggerCpu = 15,
        [int]$DeltaTriggerMem = 15,
        [string[]]$NameBlacklistPatterns,
        [string[]]$TagBlacklistNames,
        [array]$AffinityGroups,
        [array]$AntiAffinityGroups,
        [array]$VmToHostRules,
        [switch]$IncludeNetwork,
        [switch]$DryRun
    )

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop

    $esxHosts = Get-VMHost -Location $clusterObj |
                Where-Object { $_.ConnectionState -eq 'Connected' }

    if ($esxHosts.Count -lt 2) { return }

    $hostLoads = $esxHosts | ForEach-Object {
        Get-HostLoad -ESXHost $_ -IncludeNetwork:$IncludeNetwork
    }

    # v1.37: delta-based balancing
    $avgCpu = [math]::Round(($hostLoads | Measure-Object -Property CpuPct -Average).Average, 1)
    $avgMem = [math]::Round(($hostLoads | Measure-Object -Property MemPct -Average).Average, 1)

    $overloaded = $hostLoads | Where-Object {
        ($_.CpuPct - $avgCpu) -ge $DeltaTriggerCpu -or
        ($_.MemPct - $avgMem) -ge $DeltaTriggerMem
    } | Sort-Object LoadScore -Descending

    $underloaded = $hostLoads | Where-Object {
        ($avgCpu - $_.CpuPct) -ge $DeltaTriggerCpu -or
        ($avgMem - $_.MemPct) -ge $DeltaTriggerMem
    } | Sort-Object LoadScore

    Write-Log -Message "[BALANCE] Cluster avg: CPU=$avgCpu% / Mem=$avgMem% -- Sources: $($overloaded.Count) / Targets: $($underloaded.Count) (delta: CPU=${DeltaTriggerCpu}% / Mem=${DeltaTriggerMem}%)"

    if (-not $overloaded -or -not $underloaded) {
        Write-Log -Message "[BALANCE] No significant imbalance detected."
        return
    }

    $movesDone = 0

    foreach ($src in $overloaded) {
        $vmCandidates = $src.ESXHost | Get-VM | Where-Object {
            $_.PowerState -eq 'PoweredOn' -and
            -not (Test-VmBlacklisted -VM $_ `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames)
        }

        if (-not $vmCandidates) { continue }

        $sizes = $vmCandidates | Select-Object -ExpandProperty MemoryGB | Sort-Object
        $count = $sizes.Count
        if ($count -eq 0) { continue }

        if ($count % 2 -eq 1) {
            $medianSize = $sizes[([int]($count/2))]
        }
        else {
            $medianSize = ($sizes[($count/2)-1] + $sizes[($count/2)]) / 2
        }

        foreach ($dst in $underloaded) {
            if ($movesDone -ge $MaxMigrations) {
                break
            }

            if ($src.ESXHost.Name -eq $dst.ESXHost.Name) {
                continue
            }

            $candidate = $vmCandidates | Sort-Object {
                [Math]::Abs($_.MemoryGB - $medianSize)
            } | Select-Object -First 1

            if (-not $candidate) {
                break
            }

            if (Test-VmMigrating -VM $candidate) {
                $vmCandidates = @($vmCandidates | Where-Object { $_.Name -ne $candidate.Name })
                continue
            }

            if (-not (Test-StorageCompatible -VM $candidate -TargetHost $dst.ESXHost)) {
                continue
            }

            if ($AntiAffinityGroups -and $AntiAffinityGroups.Count -gt 0) {
                $aaHosts = Get-AntiAffinityCompatibleHosts `
                    -VM $candidate `
                    -TargetHosts @($dst.ESXHost) `
                    -AntiAffinityGroups $AntiAffinityGroups `
                    -ClusterName $ClusterName
                if (-not $aaHosts -or $aaHosts.Count -eq 0) {
                    Write-Log -Message "[BALANCE] VM '$($candidate.Name)' skipped: anti-affinity blocks move to $($dst.ESXHost.Name)" -Level Debug
                    continue
                }
            }

            if ($AffinityGroups -and $AffinityGroups.Count -gt 0) {
                $affinityTargetForVM = Get-AffinityTargetHost `
                    -VMName $candidate.Name `
                    -AffinityGroups $AffinityGroups `
                    -ClusterName $ClusterName `
                    -VM $candidate
                if ($affinityTargetForVM -and $affinityTargetForVM.Name -ne $dst.ESXHost.Name) {
                    Write-Log -Message "[BALANCE] VM '$($candidate.Name)' skipped: affinity requires $($affinityTargetForVM.Name), not $($dst.ESXHost.Name)" -Level Debug
                    continue
                }
            }

            $msg = '[BALANCE] Rebalancing ' + $candidate.Name + ': ' + $src.ESXHost.Name + ' -> ' + $dst.ESXHost.Name + ' (src mem: ' + $src.MemPct + '% / dst mem: ' + $dst.MemPct + '%)'

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            } else {
                Write-Host $msg
                Move-VM -VM $candidate -Destination $dst.ESXHost -RunAsync -ErrorAction SilentlyContinue | Out-Null
            }

            $movesDone++
            $vmCandidates = @($vmCandidates | Where-Object { $_.Name -ne $candidate.Name })
            break
        }
    }

    # =========================================================================
    # VM COUNT REBALANCING
    # =========================================================================

    $vmCountImbalanceThreshold = 2

    $hostLoadsForCount = $esxHosts | ForEach-Object {
        Get-HostLoad -ESXHost $_ -IncludeNetwork:$IncludeNetwork
    }

    $vmCountPerHost = $hostLoadsForCount | ForEach-Object {
        [PSCustomObject]@{
            HostLoad   = $_
            VMCount    = $_.PoweredOnVMs
        }
    }

    $totalVMs   = ($vmCountPerHost | Measure-Object -Property VMCount -Sum).Sum
    $hostCount  = $vmCountPerHost.Count

    if ($hostCount -gt 1 -and $totalVMs -gt 0) {

        $avgVMCount = $totalVMs / $hostCount

        $sparseHosts = $vmCountPerHost | Where-Object {
            ($avgVMCount - $_.VMCount) -ge $vmCountImbalanceThreshold
        } | Sort-Object VMCount

        $donorHosts = $vmCountPerHost | Where-Object {
            $_.VMCount -gt $avgVMCount
        } | Sort-Object VMCount -Descending

        if ($sparseHosts -and $donorHosts) {

            Write-Log -Message "[BALANCE|VMCOUNT] VM count imbalance detected. Average: $([math]::Round($avgVMCount,1)) VMs/host. Sparse host(s): $(($sparseHosts | ForEach-Object { "$($_.HostLoad.ESXHost.Name)=$($_.VMCount)" }) -join ', ')"

            $countMovesDone = 0

            foreach ($sparse in $sparseHosts) {

                if ($countMovesDone -ge $MaxMigrations) { break }

                $sparseHost = $sparse.HostLoad.ESXHost

                foreach ($donor in $donorHosts) {

                    if ($countMovesDone -ge $MaxMigrations) { break }

                    $donorHost = $donor.HostLoad.ESXHost

                    if ($donorHost.Name -eq $sparseHost.Name) { continue }

                    $donorVMs = $donorHost | Get-VM | Where-Object {
                        $_.PowerState -eq 'PoweredOn' -and
                        -not (Test-VmBlacklisted -VM $_ `
                            -NameBlacklistPatterns $NameBlacklistPatterns `
                            -TagBlacklistNames $TagBlacklistNames)
                    }

                    if (-not $donorVMs -or $donorVMs.Count -eq 0) { continue }

                    $donorSizes = $donorVMs | Select-Object -ExpandProperty MemoryGB | Sort-Object
                    $donorCount = $donorSizes.Count
                    $medianMem  = if ($donorCount % 2 -eq 1) {
                        $donorSizes[[int]($donorCount / 2)]
                    } else {
                        ($donorSizes[($donorCount / 2) - 1] + $donorSizes[$donorCount / 2]) / 2
                    }

                    $candidate = $donorVMs | Sort-Object {
                        [Math]::Abs($_.MemoryGB - $medianMem)
                    } | Select-Object -First 1

                    if (-not $candidate)                                                      { continue }
                    if (Test-VmMigrating -VM $candidate)                                      { continue }
                    if (-not (Test-StorageCompatible -VM $candidate -TargetHost $sparseHost)) { continue }

                    $antiAffinityOK = $true
                    if ($AntiAffinityGroups -and $AntiAffinityGroups.Count -gt 0) {
                        $allowedByAntiAffinity = Get-AntiAffinityCompatibleHosts `
                            -VM $candidate `
                            -TargetHosts @($sparseHost) `
                            -AntiAffinityGroups $AntiAffinityGroups `
                            -ClusterName $ClusterName
                        if (-not $allowedByAntiAffinity -or $allowedByAntiAffinity.Count -eq 0) {
                            Write-Log -Message "[BALANCE|VMCOUNT] VM '$($candidate.Name)' skipped: anti-affinity rule blocks move to $($sparseHost.Name)" -Level Debug
                            $antiAffinityOK = $false
                        }
                    }
                    if (-not $antiAffinityOK) { continue }

                    $msg = "[BALANCE|VMCOUNT] Rebalancing VM count: '$($candidate.Name)' $($donorHost.Name) ($($donor.VMCount) VMs) -> $($sparseHost.Name) ($($sparse.VMCount) VMs) [avg: $([math]::Round($avgVMCount,1))]"

                    if ($DryRun) {
                        Write-Log -Message "[DRYRUN] $msg"
                    } else {
                        Write-Host $msg
                        Move-VM -VM $candidate -Destination $sparseHost -RunAsync -ErrorAction SilentlyContinue | Out-Null
                    }

                    $countMovesDone++

                    $sparse.VMCount++
                    $donor.VMCount--

                    break
                }
            }

            if ($countMovesDone -gt 0) {
                Write-Log -Message "[BALANCE|VMCOUNT] $countMovesDone VM(s) scheduled for VM-count rebalancing."
            } else {
                Write-Log -Message "[BALANCE|VMCOUNT] VM count imbalance detected but no eligible migration found (storage/anti-affinity/blacklist constraints)."
            }

        } else {
            Write-Log -Message "[BALANCE|VMCOUNT] VM count distribution is balanced (avg: $([math]::Round($avgVMCount,1)) VMs/host)." -Level Debug
        }
    }
}

# ---------- Main loop ----------
while ($true) {
    try {
        $script:loopCounter++
        Write-Log -Message "---- Iteration $(Get-Date) : cluster '$clusterNameLocal' (loop #$($script:loopCounter)) ----"

        # 1. Memory monitoring (every X hours)
        $timeSinceLastMonitor = (Get-Date) - $script:lastMemoryMonitor
        if ($timeSinceLastMonitor.TotalHours -ge $script:memoryMonitorIntervalHours) {
            Show-MemoryUsage
        }

        # 2. Automatic garbage collection (every X hours)
        $timeSinceLastGC = (Get-Date) - $script:lastGarbageCollection
        if ($timeSinceLastGC.TotalHours -ge $script:gcIntervalHours) {
            Write-Log -Message "[MEMORY] Triggering automatic garbage collection (last run: $($script:lastGarbageCollection))" -Level Info
            Invoke-MemoryCleanup
        }

        # 3. vCenter connection recycling (every X hours)
        $timeSinceLastRecycle = (Get-Date) - $script:lastVCenterRecycle
        if ($timeSinceLastRecycle.TotalHours -ge $script:vcRecycleIntervalHours) {
            Write-Log -Message "[MEMORY] Triggering vCenter recycling (last run: $($script:lastVCenterRecycle))" -Level Info
            $recycleSuccess = Invoke-VCenterRecycle -VCenter $vCenter -Credential $credential
            if (-not $recycleSuccess) {
                Write-Log -Message "[MEMORY] vCenter recycling failed, will retry next iteration" -Level Warning
            }
        }

        # HOST EVACUATION DETECTION
        $hostsNeedingEvac = Get-HostsNeedingEvacuation -ClusterName $clusterNameLocal

        if ($hostsNeedingEvac) {
            $hostsWithVMs = $hostsNeedingEvac | Where-Object {
                $vmsToMove = $_ | Get-VM | Where-Object {
                    -not (Test-VmBlacklisted -VM $_ `
                        -NameBlacklistPatterns $NameBlacklistPatterns `
                        -TagBlacklistNames $TagBlacklistNames)
                }
                ($vmsToMove | Measure-Object).Count -gt 0
            }

            if ($hostsWithVMs) {
                # EVACUATION MODE: Hosts with VMs to evacuate
                if (-not $script:wasInEvacuationMode) {
                    Write-Log -Message "*** Switching to evacuation mode (short loop: $EvacLoopSleepSeconds s) ***"
                    $script:wasInEvacuationMode = $true
                }

                Evacuate-Hosts -HostsToEvacuate $hostsWithVMs `
                    -ClusterName $clusterNameLocal `
                    -MaxMigrationsEvacTotal $MaxMigrationsEvacTotal `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames `
                    -AffinityGroups $script:affinityGroups `
                    -AntiAffinityGroups $script:antiAffinityGroups `
                    -VmToHostRules $script:vmToHostRules `
                    -IncludeNetwork:$IncludeNetwork `
                    -DryRun:$DryRun

                $sleep = $EvacLoopSleepSeconds

            } elseif ($script:evacuationQueue.Count -gt 0) {
                # EVACUATION MONITORING: hosts in maintenance, waiting for admin exit
                Write-Log -Message "*** [EVACUATION] Queue monitoring: $($script:evacuationQueue.Count) host(s) in maintenance ***"

                $hostsInfo = @()
                $activeMaintenance = $false

                foreach ($hostName in @($script:evacuationQueue.Keys)) {
                    $esxHost = Get-VMHost -Name $hostName -ErrorAction SilentlyContinue

                    if (-not $esxHost) {
                        Write-Log -Message "[EVACUATION] Host '$hostName' not found, removing from queue" -Level Warning
                        $script:evacuationQueue.Remove($hostName)
                        continue
                    }

                    if ($esxHost.ConnectionState -eq 'Maintenance' -or $esxHost.ConnectionState -eq 'NotResponding') {

                        $remainingVMs = $esxHost | Get-VM -ErrorAction SilentlyContinue | Where-Object {
                            -not (Test-VmBlacklisted -VM $_ `
                                -NameBlacklistPatterns $NameBlacklistPatterns `
                                -TagBlacklistNames $TagBlacklistNames)
                        }

                        $vmCount = ($remainingVMs | Measure-Object).Count

                        if ($vmCount -eq 0) {
                            Write-Log -Message "[EVACUATION] Host '$hostName' - evacuation complete. Waiting for manual exit from maintenance mode." -Level Info
                            $hostsInfo += "  * $($esxHost.Name): 0 VMs remaining (manual exit required)"
                        } else {
                            Write-Log -Message "[EVACUATION] Host '$hostName' - $vmCount VM(s) still migrating..."
                            $hostsInfo += "  * $($esxHost.Name): $vmCount VM(s) remaining"
                        }

                        $activeMaintenance = $true

                    } else {
                        Write-Log -Message "[EVACUATION] Host '$hostName' exited maintenance mode, removing from queue"
                        $script:evacuationQueue.Remove($hostName)
                    }
                }

                if ($hostsInfo.Count -gt 0) {
                    Write-Log -Message "*** [EVACUATION] Maintenance status: $($hostsInfo -join ' | ') ***"
                }

                $hostsWithVMs = $hostsInfo | Where-Object { $_ -notmatch "0 VMs remaining" }

                if ($hostsWithVMs.Count -gt 0) {
                    $sleep = $EvacLoopSleepSeconds
                } else {
                    Write-Log -Message "[EVACUATION] All evacuations complete (0 VMs remaining on all hosts). Returning to normal mode ($NormalLoopSleepSeconds s)."
                    $script:wasInEvacuationMode = $false
                    $script:evacuationQueue.Clear()
                    $sleep = $NormalLoopSleepSeconds
                }

            } else {
                # No hosts with VMs and queue empty
                if ($script:wasInEvacuationMode) {
                    Write-Log -Message "*** EVACUATION COMPLETE! Returning to normal mode ($NormalLoopSleepSeconds s). ***"
                    $script:wasInEvacuationMode = $false
                }

                $sleep = $NormalLoopSleepSeconds

                # NORMAL MODE: Rule checking with throttling
                $shouldCheckRules = ($script:loopCounter % $RulesCheckEveryXLoops) -eq 0

                if ($shouldCheckRules) {
                    Write-Log -Message "[RULES] Checking rule files (every $RulesCheckEveryXLoops loops)..." -Level Info

                    # Affinity rules - reload only if file changed
                    if (Test-Path $AffinityListPath) {
                        $currentAffinityWrite = (Get-Item $AffinityListPath).LastWriteTime
                        if ($currentAffinityWrite -ne $script:lastAffinityLoad) {
                            # FIX-1: @() prevents PS5.1 singleton unwrap (single group -> bare object -> .Count = $null)
                            $script:affinityGroups = @(Read-AffinityList -FilePath $AffinityListPath)
                            $script:lastAffinityLoad = $currentAffinityWrite
                            Write-Log -Message "[RULES] Affinity rules reloaded ($($script:affinityGroups.Count) groups)"
                        }
                    } else {
                        $loopsUntilCheck = $RulesCheckEveryXLoops - ($script:loopCounter % $RulesCheckEveryXLoops)
                        Write-Log -Message "[RULES] Using cached rules (will check in $loopsUntilCheck loops)" -Level Debug
                    }

                    # Anti-affinity rules - reload only if file changed
                    if (Test-Path $AntiAffinityListPath) {
                        $currentAntiAffinityWrite = (Get-Item $AntiAffinityListPath).LastWriteTime
                        if ($currentAntiAffinityWrite -ne $script:lastAntiAffinityLoad) {
                            # FIX-1: @() prevents PS5.1 singleton unwrap
                            $script:antiAffinityGroups = @(Read-AntiAffinityList -FilePath $AntiAffinityListPath)
                            $script:lastAntiAffinityLoad = $currentAntiAffinityWrite
                            Write-Log -Message "[RULES] Anti-affinity rules reloaded ($($script:antiAffinityGroups.Count) groups)"
                        }
                    }

                    # VM-to-Host rules - reload only if file changed
                    if (Test-Path $VmToHostListPath) {
                        $currentVmToHostWrite = (Get-Item $VmToHostListPath).LastWriteTime
                        if ($currentVmToHostWrite -ne $script:lastVmToHostLoad) {
                            # FIX-1: @() prevents PS5.1 singleton unwrap
                            $script:vmToHostRules = @(Read-VmToHostList -FilePath $VmToHostListPath)
                            $script:lastVmToHostLoad = $currentVmToHostWrite
                            Write-Log -Message "[RULES] VM-to-Host rules reloaded ($($script:vmToHostRules.Count) rules)"
                        }
                    }

                    # Apply rules
                    if ($script:affinityGroups.Count -gt 0) {
                        # FIX-2: previously truncated - missing -NameBlacklistPatterns / -TagBlacklistNames /
                        # -IncludeNetwork / -DryRun, with a stray trailing backtick causing a silent parse error
                        Enforce-AffinityGroups -ClusterName $clusterNameLocal `
                            -AffinityGroups $script:affinityGroups `
                            -MaxMigrations $MaxMigrationsAffinityPerLoop `
                            -NameBlacklistPatterns $NameBlacklistPatterns `
                            -TagBlacklistNames $TagBlacklistNames `
                            -IncludeNetwork:$IncludeNetwork `
                            -DryRun:$DryRun
                    }

                    $antiAffinityArray = $script:antiAffinityGroups
                    if ($antiAffinityArray.Count -gt 0) {
                        Enforce-AntiAffinityGroups -ClusterName $clusterNameLocal `
                            -AntiAffinityGroups $antiAffinityArray `
                            -MaxMigrations $MaxMigrationsAntiAffinityPerLoop `
                            -NameBlacklistPatterns $NameBlacklistPatterns `
                            -TagBlacklistNames $TagBlacklistNames `
                            -IncludeNetwork:$IncludeNetwork `
                            -DryRun:$DryRun
                    }

                    $vmToHostArray = $script:vmToHostRules
                    if ($vmToHostArray.Count -gt 0) {
                        Enforce-VmToHostRules -ClusterName $clusterNameLocal `
                            -VmToHostRules $vmToHostArray `
                            -MaxMigrations $MaxMigrationsVmToHostPerLoop `
                            -NameBlacklistPatterns $NameBlacklistPatterns `
                            -TagBlacklistNames $TagBlacklistNames `
                            -IncludeNetwork:$IncludeNetwork `
                            -DryRun:$DryRun
                    }
                }

                # Always run cluster balancing
                Balance-Cluster -ClusterName $clusterNameLocal `
                    -MaxMigrations $MaxMigrationsBalancePerLoop `
                    -HighCpuPercent $HighCpuPercent `
                    -LowCpuPercent $LowCpuPercent `
                    -HighMemPercent $HighMemPercent `
                    -LowMemPercent $LowMemPercent `
                    -DeltaTriggerCpu $DeltaTriggerCpu `
                    -DeltaTriggerMem $DeltaTriggerMem `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames `
                    -AffinityGroups $script:affinityGroups `
                    -AntiAffinityGroups $script:antiAffinityGroups `
                    -VmToHostRules $script:vmToHostRules `
                    -IncludeNetwork:$IncludeNetwork `
                    -DryRun:$DryRun
            }
        } else {
            # No hosts in evacuation mode
            if ($script:wasInEvacuationMode) {
                Write-Log -Message "*** No more maintenance hosts detected. Returning to normal mode. ***"
                $script:wasInEvacuationMode = $false
            }

            $sleep = $NormalLoopSleepSeconds

            # NORMAL MODE: Rule checking with throttling
            $shouldCheckRules = ($script:loopCounter % $RulesCheckEveryXLoops) -eq 0

            if ($shouldCheckRules) {
                Write-Log -Message "[RULES] Checking rule files (every $RulesCheckEveryXLoops loops)..." -Level Info

                # Affinity rules - reload only if file changed
                if (Test-Path $AffinityListPath) {
                    $currentAffinityWrite = (Get-Item $AffinityListPath).LastWriteTime
                    if ($currentAffinityWrite -ne $script:lastAffinityLoad) {
                        # FIX-1: @() prevents PS5.1 singleton unwrap
                        $script:affinityGroups = @(Read-AffinityList -FilePath $AffinityListPath)
                        $script:lastAffinityLoad = $currentAffinityWrite
                        Write-Log -Message "[RULES] Affinity rules reloaded ($($script:affinityGroups.Count) groups)"
                    }
                } else {
                    $loopsUntilCheck = $RulesCheckEveryXLoops - ($script:loopCounter % $RulesCheckEveryXLoops)
                    Write-Log -Message "[RULES] Using cached rules (will check in $loopsUntilCheck loops)" -Level Debug
                }

                # Anti-affinity rules - reload only if file changed
                if (Test-Path $AntiAffinityListPath) {
                    $currentAntiAffinityWrite = (Get-Item $AntiAffinityListPath).LastWriteTime
                    if ($currentAntiAffinityWrite -ne $script:lastAntiAffinityLoad) {
                        # FIX-1: @() prevents PS5.1 singleton unwrap
                        $script:antiAffinityGroups = @(Read-AntiAffinityList -FilePath $AntiAffinityListPath)
                        $script:lastAntiAffinityLoad = $currentAntiAffinityWrite
                        Write-Log -Message "[RULES] Anti-affinity rules reloaded ($($script:antiAffinityGroups.Count) groups)"
                    }
                }

                # VM-to-Host rules - reload only if file changed
                if (Test-Path $VmToHostListPath) {
                    $currentVmToHostWrite = (Get-Item $VmToHostListPath).LastWriteTime
                    if ($currentVmToHostWrite -ne $script:lastVmToHostLoad) {
                        # FIX-1: @() prevents PS5.1 singleton unwrap
                        $script:vmToHostRules = @(Read-VmToHostList -FilePath $VmToHostListPath)
                        $script:lastVmToHostLoad = $currentVmToHostWrite
                        Write-Log -Message "[RULES] VM-to-Host rules reloaded ($($script:vmToHostRules.Count) rules)"
                    }
                }

                # Apply rules
                if ($script:affinityGroups.Count -gt 0) {
                    Enforce-AffinityGroups -ClusterName $clusterNameLocal `
                        -AffinityGroups $script:affinityGroups `
                        -MaxMigrations $MaxMigrationsAffinityPerLoop `
                        -NameBlacklistPatterns $NameBlacklistPatterns `
                        -TagBlacklistNames $TagBlacklistNames `
                        -IncludeNetwork:$IncludeNetwork `
                        -DryRun:$DryRun
                }

                $antiAffinityArray = $script:antiAffinityGroups
                if ($antiAffinityArray.Count -gt 0) {
                    Enforce-AntiAffinityGroups -ClusterName $clusterNameLocal `
                        -AntiAffinityGroups $antiAffinityArray `
                        -MaxMigrations $MaxMigrationsAntiAffinityPerLoop `
                        -NameBlacklistPatterns $NameBlacklistPatterns `
                        -TagBlacklistNames $TagBlacklistNames `
                        -IncludeNetwork:$IncludeNetwork `
                        -DryRun:$DryRun
                }

                $vmToHostArray = $script:vmToHostRules
                if ($vmToHostArray.Count -gt 0) {
                    Enforce-VmToHostRules -ClusterName $clusterNameLocal `
                        -VmToHostRules $vmToHostArray `
                        -MaxMigrations $MaxMigrationsVmToHostPerLoop `
                        -NameBlacklistPatterns $NameBlacklistPatterns `
                        -TagBlacklistNames $TagBlacklistNames `
                        -IncludeNetwork:$IncludeNetwork `
                        -DryRun:$DryRun
                }
            }

            # Always run cluster balancing
            Balance-Cluster -ClusterName $clusterNameLocal `
                -MaxMigrations $MaxMigrationsBalancePerLoop `
                -HighCpuPercent $HighCpuPercent `
                -LowCpuPercent $LowCpuPercent `
                -HighMemPercent $HighMemPercent `
                -LowMemPercent $LowMemPercent `
                -DeltaTriggerCpu $DeltaTriggerCpu `
                -DeltaTriggerMem $DeltaTriggerMem `
                -NameBlacklistPatterns $NameBlacklistPatterns `
                -TagBlacklistNames $TagBlacklistNames `
                -AffinityGroups $script:affinityGroups `
                -AntiAffinityGroups $script:antiAffinityGroups `
                -VmToHostRules $script:vmToHostRules `
                -IncludeNetwork:$IncludeNetwork `
                -DryRun:$DryRun
        }

    } catch {
        Write-Log -Message "Error in pseudo-DRS loop (cluster '$clusterNameLocal'): $_" -Level Warning
        $sleep = $NormalLoopSleepSeconds
    }

    Write-Log -Message "Pausing for $sleep seconds..."
    Start-Sleep -Seconds $sleep
}
