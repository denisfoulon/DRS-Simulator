<#
.SYNOPSIS
    DRS Simulator Script - Version 1.33

.DESCRIPTION
    DRS-Simulator - Custom DRS Implementation for VMware vSphere

.NOTES
    Version: 1.33
    AUTHOR : Denis Foulon
    Date: 2026-16-01
    What's new in v1.33:
    - Migrations enhanced for evacuation

    What's new in v1.33:
    ✅ ESXi hosts can now be fully evacuated (PoweredOn + PoweredOff VMs)
    ✅ VMware maintenance mode succeeds without residual VMs
    ✅ Business rules respected for PoweredOn VMs
    ✅ Pragmatic migration for PoweredOff VMs (storage compatibility only)


.ABOUT
    This script simulates DRS-like behavior for VMware vSphere environments.
    It is an independent project created for learning, automation, and lab use.

.AFFILIATION DISCLAIMER
    This project is NOT affiliated, endorsed, or supported by VMware, Inc.
    “VMware” and “DRS” are registered trademarks of VMware, Inc.
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
    [string]$ClusterName = "cluster-name",

    # Timing parameters
    [int]$NormalLoopSleepSeconds = 60,
    [int]$EvacLoopSleepSeconds = 20,

    # Migration limits
    [int]$MaxMigrationsBalancePerLoop = 3,
    [int]$MaxMigrationsEvacTotal = 8,
    [int]$MaxMigrationsAffinityPerLoop = 5,
    [int]$MaxMigrationsAntiAffinityPerLoop = 5,
    [int]$MaxMigrationsVmToHostPerLoop = 5,

    # CPU/Memory thresholds
    [int]$HighCpuPercent = 75,
    [int]$LowCpuPercent = 40,
    [int]$HighMemPercent = 80,
    [int]$LowMemPercent = 50,

    # Blacklists
    [string[]]$NameBlacklistPatterns = @("vCLS", "NOMOVE"),
    [string[]]$TagBlacklistNames = @("No-DRS"),

    # Rule files
    [string]$AffinityListPath = "C:\scripts\drs_simulator\affinity_list.txt",
    [int]$AffinityCheckIntervalSeconds = 300,
    [string]$AntiAffinityListPath = "C:\scripts\drs_simulator\antiaffinity_list.txt",
    [int]$AntiAffinityCheckIntervalSeconds = 300,
    [string]$VmToHostListPath = "C:\scripts\drs_simulator\vm_to_host_list.txt",
    [int]$VmToHostCheckIntervalSeconds = 300,

    # SYSLOG parameters (new in v1.31)
    [string]$SyslogServer = "syslog-server.example.com",
    [int]$SyslogPort = 514,
    [int]$SyslogFacility = 16,
    [switch]$EnableSyslog = $true,

    # Options
    [switch]$IncludeNetwork,
    [switch]$DryRun
)


#region Memory Management Tracking Variables
$script:lastGarbageCollection = Get-Date
$script:lastVCenterRecycle = Get-Date
$script:lastMemoryMonitor = Get-Date
$script:gcIntervalHours = 12
$script:vcRecycleIntervalHours = 24
$script:memoryMonitorIntervalHours = 1
#endregion


#region Syslog Function (new in v1.31)
<#
.SYNOPSIS
    Sends a syslog-formatted message to a remote server

.DESCRIPTION
    This function sends messages in RFC 3164 format via UDP to a syslog server.
    Severity levels are automatically determined based on message type.

.PARAMETER Message
    The message to send

.PARAMETER Severity
    Severity level (0=Emergency, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug)

.PARAMETER AlsoWriteHost
    If specified, also displays the message in the console
#>
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
        $SyslogMsg = "<$Priority>$Timestamp $Hostname DRS_Simulator: $Message"

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

<#
.SYNOPSIS
    Wrapper to replace Write-Host with syslog sending
#>
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
<#
.SYNOPSIS
    Force garbage collection to free memory
#>
function Invoke-MemoryCleanup {
    param([switch]$Force)

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

<#
.SYNOPSIS
    Recycle vCenter connection to free resources
#>
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
        Write-Log -Message "[VCENTER] Error during recycle: $_" -Level Error
        Write-Log -Message "[VCENTER] Attempting emergency reconnection..." -Level Warning

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

<#
.SYNOPSIS
    Monitor PowerShell process memory usage
#>
function Show-MemoryUsage {
    try {
        $process = Get-Process -Id $PID
        $memoryMB = $process.WorkingSet64 / 1MB
        $peakMemoryMB = $process.PeakWorkingSet64 / 1MB
        $privateMemoryMB = $process.PrivateMemorySize64 / 1MB

        Write-Log -Message "[MEMORY] Current memory usage: ${memoryMB:F2} MB (peak: ${peakMemoryMB:F2} MB, private: ${privateMemoryMB:F2} MB)" -Level Info

        if ($memoryMB -gt 2048) {
            Write-Log -Message "[MEMORY] ⚠️ WARNING: High memory usage (>${memoryMB:F2} MB)" -Level Warning
            Invoke-MemoryCleanup
        }

        $script:lastMemoryMonitor = Get-Date
    }
    catch {
        Write-Log -Message "[MEMORY] Error during memory monitoring: $_" -Level Warning
    }
}

<#
.SYNOPSIS
    Clean statistics cache
#>
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

        Write-Log -Message "[MEMORY] Statistics cache cleaned" -Level Debug
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

$script:lastAffinityLoad = $null
$script:lastAntiAffinityLoad = $null
$script:lastVmToHostLoad = $null
$script:affinityGroups = @()
$script:antiAffinityGroups = @()
$script:vmToHostRules = @()

#endregion


#region Affinity Management
function Read-AffinityList {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
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
    
    Write-Log -Message "Affinity file loaded: $($groups.Count) group(s) detected" -Level Info
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

#endregion


#region Anti-Affinity Management
function Read-AntiAffinityList {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
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
        Write-Log -Message "[ANTI-AFFINITY] Less than 2 hosts available, cannot apply rules." -Level Warning
        return
    }

    $movesDone = 0
    $groupIndex = 0
    
    foreach ($groupObj in $AntiAffinityGroups) {
        $groupIndex++
        
        if ($movesDone -ge $MaxMigrations) { 
            Write-Log -Message "[ANTI-AFFINITY] Limit reached ($MaxMigrations), continuing next cycle."
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
            Write-Log -Message "[ANTI-AFFINITY] ⚠ Group skipped (less than 2 active VMs)"
            continue 
        }

        $vmsByHost = $groupVMs | Group-Object -Property { $_.VMHost.Name }
        $violations = $vmsByHost | Where-Object { $_.Count -gt 1 }

        if (-not $violations) {
            Write-Log -Message "[ANTI-AFFINITY] ✓ Group OK - All VMs are on different hosts"
            continue
        }

        Write-Log -Message "[ANTI-AFFINITY] ✗✗✗ VIOLATION DETECTED! ✗✗✗"

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

                $msg = "[ANTI-AFFINITY] ➜ Migrating VM '$($vm.Name)' : $($vm.VMHost.Name) → $($bestTarget.ESXHost.Name)"

                if ($DryRun) {
                    Write-Log -Message "[DRYRUN] $msg"
                } else {
                    Write-Host $msg
                    try {
                        Move-VM -VM $vm -Destination $bestTarget.ESXHost -RunAsync -ErrorAction Stop | Out-Null
                    } catch {
                        Write-Log -Message "[ANTI-AFFINITY] Migration error: $_" -Level Warning
                        continue
                    }
                }

                $movesDone++
            }
        }
    }

    if ($movesDone -eq 0) {
        Write-Log -Message "[ANTI-AFFINITY] ✓ All anti-affinity rules are respected"
    }
}

function Get-AntiAffinityCompatibleHosts {
    param(
        [Parameter(Mandatory)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
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

#endregion


#region VM-to-Host Management
function Read-VmToHostList {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
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
        Write-Log -Message "[VM-TO-HOST] Rule loaded: VMs=[$($vms -join ', ')] → Hosts=[$($hosts -join ', ')]"
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

        Write-Log -Message "[VM-TO-HOST] Rule $ruleIndex : VMs=[$($vms -join ', ')] → Hosts=[$($hosts -join ', ')]"

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

            $msg = "[VM-TO-HOST] ➜ $($vm.Name) : $($currentHost.Name) → $($bestTarget.ESXHost.Name)"

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
        Write-Log -Message "[VM-TO-HOST] ✓ All VM-to-Host rules are respected"
    }
}

#endregion


#region Helper Functions
function Get-HostLoad {
    param(
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]$ESXHost,
        [switch]$IncludeNetwork
    )

    $summary = $ESXHost.ExtensionData.Summary

    $cpuUsagePct = [int](
        $summary.QuickStats.OverallCpuUsage * 100 / $summary.Hardware.CpuMhz
    )
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
    $score = [int](
        (0.4 * $cpuUsagePct) +
        (0.4 * $memUsagePct) +
        (0.2 * $normNet)
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

function Test-VmBlacklisted {
    param(
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
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

function Test-VmMigrating {
    param(
        [Parameter(Mandatory)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM
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

function Test-StorageCompatible {
    param(
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]$TargetHost
    )

    $targetDsNames = ($TargetHost | Get-Datastore | Select-Object -ExpandProperty Name)

    $vmDsNames = $VM.ExtensionData.Layout.Disk | ForEach-Object {
        ($_.DiskFile | ForEach-Object {
            ($_ -split '\]')[0].TrimStart('[').Trim()
        })
    } | Sort-Object -Unique

    foreach ($ds in $vmDsNames) {
        if ($ds -like 'MYDATASTORE*') { continue }

        if ($targetDsNames -notcontains $ds) {
            return $false
        }
    }

    return $true
}

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

function Get-HostsNeedingEvacuation {
    param(
        [string]$ClusterName,
        [int]$RecentMinutes = 10
    )

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $allHosts   = Get-VMHost -Location $clusterObj

    $hostsMaintenance = $allHosts | Where-Object { $_.ConnectionState -eq 'Maintenance' }

    $enterTasks = Get-Task -Status Running,Queued -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DescriptionId -match "HostSystem.enterMaintenanceMode"
        }

    $hostsFromTasks = @()
    foreach ($t in $enterTasks) {
        if ($t.Entity -and $t.Entity -is [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]) {
            $hostsFromTasks += $t.Entity
        }
        elseif ($t.Entity -and $t.Entity.Name) {
            $h = Get-VMHost -Name $t.Entity.Name -ErrorAction SilentlyContinue
            if ($h) { $hostsFromTasks += $h }
        }
    }

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

    $hostsFromEvents = @()

    $maintenanceEvents |
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

            if (
                $lastEvt -is [VMware.Vim.ExitMaintenanceModeEvent] -or
                $lastEvt.FullFormattedMessage -match "exited Maintenance Mode"
            ) {
                return
            }

            if ($lastEvt.CreatedTime -ge $startEvt) {
                if (
                    $lastEvt -is [VMware.Vim.EnteredMaintenanceModeEvent] -or
                    $lastEvt -is [VMware.Vim.EnteringMaintenanceModeEvent] -or
                    $lastEvt.FullFormattedMessage -match "Enter maintenance mode" -or
                    $lastEvt.FullFormattedMessage -match "entered Maintenance Mode"
                ) {
                    $h = Get-VMHost -Name $hostName -ErrorAction SilentlyContinue
                    if ($h) { $hostsFromEvents += $h }
                }
            }
        }

    $allCandidates = @()
    $allCandidates += $hostsMaintenance
    $allCandidates += $hostsFromTasks
    $allCandidates += $hostsFromEvents

    $allCandidates = $allCandidates |
        Where-Object { $_ -is [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl] } |
        Select-Object -Unique

    return $allCandidates
}

#endregion


#region Evacuation
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

    # vMotions already in progress at function entry
    $nbEnCours = Get-CurrentVmotionCount -ClusterName $ClusterName
    $slotsDispoInitial = $MaxMigrationsEvacTotal - $nbEnCours

    if ($slotsDispoInitial -le 0) {
        Write-Log -Message "[EVACUATION] No vMotion slot available (already $nbEnCours in progress / $MaxMigrationsEvacTotal), waiting for next loop."
        return
    }

    $movesThisLoop = 0

    foreach ($mmESX in $HostsToEvacuate) {
        Write-Log -Message "========================================="
        Write-Log -Message "[EVACUATION] Evacuating host (maintenance or entering maintenance): $($mmESX.Name)"
        Write-Log -Message "========================================="

        # Get target hosts (all connected hosts EXCEPT the one in maintenance)
        $targetHosts = Get-VMHost -Location $clusterObj | Where-Object {
            $_.ConnectionState -eq 'Connected' -and $_.Name -ne $mmESX.Name
        }

        if (-not $targetHosts) {
            Write-Log -Message "[EVACUATION] No target host available for $($mmESX.Name)" -Level Warning
            continue
        }

        # ============================================================
        # Get ALL VMs (PoweredOn AND PoweredOff)
        # ============================================================
        $vmCandidates = $mmESX | Get-VM | Where-Object {
            -not (Test-VmBlacklisted -VM $_ `
                -NameBlacklistPatterns $NameBlacklistPatterns `
                -TagBlacklistNames $TagBlacklistNames)
        }

        if (-not $vmCandidates -or $vmCandidates.Count -eq 0) {
            Write-Log -Message "[EVACUATION] No VM to evacuate on $($mmESX.Name)"
            continue
        }

        # Separate PoweredOn and PoweredOff VMs for priority handling
        $vmsPoweredOn = $vmCandidates | Where-Object { $_.PowerState -eq 'PoweredOn' }
        $vmsPoweredOff = $vmCandidates | Where-Object { $_.PowerState -eq 'PoweredOff' }

        Write-Log -Message "[EVACUATION] VMs to evacuate: $($vmsPoweredOn.Count) powered ON + $($vmsPoweredOff.Count) powered OFF = $($vmCandidates.Count) total"

        # ============================================================
        # PART 1: PoweredOn VMs - Apply full rule logic
        # ============================================================
        foreach ($vm in $vmsPoweredOn) {
            # Dynamic recalculation of available slots
            $nbEnCours = Get-CurrentVmotionCount -ClusterName $ClusterName
            $slotsDispo = $MaxMigrationsEvacTotal - ($nbEnCours + $movesThisLoop)

            if ($slotsDispo -le 0) {
                Write-Log -Message "[EVACUATION] vMotion slots consumed for this loop ($nbEnCours in progress + $movesThisLoop launched), waiting for next iteration."
                return
            }

            # Skip VMs already migrating
            if (Test-VmMigrating -VM $vm) {
                Write-Log -Message "[EVACUATION] VM '$($vm.Name)' already migrating, skipped."
                continue
            }

            # Filter storage-compatible target hosts
            $compatibleTargets = $targetHosts | Where-Object {
                Test-StorageCompatible -VM $vm -TargetHost $_
            }

            if (-not $compatibleTargets) {
                Write-Log -Message "[EVACUATION] No target host with compatible storage for VM '$($vm.Name)' (Memory: $($vm.MemoryGB)GB, State: PoweredOn). vMotion skipped (slot NOT consumed)." -Level Warning
                continue
            }

            # Variable to hold the selected target and migration reason
            $bestTarget = $null
            $migrationReason = "balancing"

            # ============================================================
            # PRIORITY 1: VM-to-Host (only if target host valid and available)
            # ============================================================
            $vmToHostTarget = Get-VmToHostTargetHost -VMName $vm.Name `
                -VmToHostRules $VmToHostRules `
                -ClusterName $ClusterName `
                -VM $vm

            if ($vmToHostTarget -and ($compatibleTargets.Name -contains $vmToHostTarget.Name)) {
                # VM-to-Host rule can be applied
                $bestTarget = Get-HostLoad -ESXHost $vmToHostTarget -IncludeNetwork:$IncludeNetwork
                $migrationReason = "VM-TO-HOST"
                Write-Log -Message "[EVACUATION][VM-TO-HOST] VM '$($vm.Name)' directed to $($vmToHostTarget.Name) (rule respected)"
            }
            elseif ($vmToHostTarget) {
                # VM-to-Host rule exists BUT target host is unavailable
                Write-Log -Message "[EVACUATION][VM-TO-HOST] VM '$($vm.Name)' should go to $($vmToHostTarget.Name) but this host is in maintenance or incompatible. VM-to-Host rule SUSPENDED for evacuation (will use fallback)." -Level Warning
            }

            # ============================================================
            # PRIORITY 2: Affinity (only if no VM-to-Host was applied)
            # ============================================================
            if (-not $bestTarget) {
                $affinityHost = Get-AffinityTargetHost -VMName $vm.Name `
                    -AffinityGroups $AffinityGroups `
                    -ClusterName $ClusterName `
                    -VM $vm

                if ($affinityHost -and ($compatibleTargets.Name -contains $affinityHost.Name)) {
                    # Affinity rule can be applied
                    $bestTarget = Get-HostLoad -ESXHost $affinityHost -IncludeNetwork:$IncludeNetwork
                    $migrationReason = "AFFINITY"
                    Write-Log -Message "[EVACUATION][AFFINITY] VM '$($vm.Name)' directed to $($affinityHost.Name) (group respected)"
                }
                elseif ($affinityHost) {
                    # Affinity rule exists BUT target host is unavailable
                    Write-Log -Message "[EVACUATION][AFFINITY] VM '$($vm.Name)' should go to $($affinityHost.Name) but this host is in maintenance or incompatible. Affinity rule SUSPENDED for evacuation (will use fallback)." -Level Warning
                }
            }

            # ============================================================
            # PRIORITY 3: Anti-affinity (filtering only, best effort)
            # ============================================================
            if (-not $bestTarget) {
                # Apply anti-affinity filtering to compatible targets
                $antiAffinityTargets = Get-AntiAffinityCompatibleHosts -VM $vm `
                    -TargetHosts $compatibleTargets `
                    -AntiAffinityGroups $AntiAffinityGroups `
                    -ClusterName $ClusterName

                if ($antiAffinityTargets -and $antiAffinityTargets.Count -gt 0) {
                    # Select best host among anti-affinity compatible hosts
                    $bestTarget = Get-BestTargetHost -ESXHosts $antiAffinityTargets -IncludeNetwork:$IncludeNetwork
                    $migrationReason = "ANTI-AFFINITY"
                    Write-Log -Message "[EVACUATION][ANTI-AFFINITY] VM '$($vm.Name)' to host respecting anti-affinity"
                }
                else {
                    Write-Log -Message "[EVACUATION][ANTI-AFFINITY] No host available respecting anti-affinity constraints for '$($vm.Name)'. Rule SUSPENDED for evacuation (will use forced fallback)." -Level Warning
                }
            }

            # ============================================================
            # MANDATORY FALLBACK: If no rule has given a valid target
            # ============================================================
            if (-not $bestTarget) {
                # FORCED evacuation: select best available host regardless of rules
                $bestTarget = Get-BestTargetHost -ESXHosts $compatibleTargets -IncludeNetwork:$IncludeNetwork
                $migrationReason = "FORCED-EVACUATION"
                Write-Log -Message "[EVACUATION][FORCE] VM '$($vm.Name)' (State: PoweredOn) to best available host (affinity/VM-to-Host rules suspended due to maintenance)"
            }

            # ============================================================
            # Final check: If still no target (should never happen)
            # ============================================================
            if (-not $bestTarget -or -not $bestTarget.ESXHost) {
                Write-Log -Message "[EVACUATION][CRITICAL ERROR] Impossible to find a target host for '$($vm.Name)'. Migration canceled." -Level Warning
                Write-Log -Message "[EVACUATION][DEBUG] compatibleTargets Count: $($compatibleTargets.Count)" -Level Warning
                continue
            }

            # ============================================================
            # Execute the migration for PoweredOn VM
            # ============================================================
            $msg = "[EVACUATION][$migrationReason] VM '$($vm.Name)' [PoweredOn] (Mem: $($vm.MemoryGB)GB) : $($vm.VMHost.Name) → $($bestTarget.ESXHost.Name) (load: $($bestTarget.LoadScore))"

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            }
            else {
                Write-Host $msg
                try {
                    Move-VM -VM $vm -Destination $bestTarget.ESXHost -RunAsync -ErrorAction Stop | Out-Null
                    Write-Log -Message "[EVACUATION] Migration launched successfully"
                    $movesThisLoop++
                }
                catch {
                    Write-Log -Message "[EVACUATION] Error during migration of '$($vm.Name)': $_" -Level Warning
                    continue
                }
            }
        }

        # ============================================================
        # PART 2: PoweredOff VMs - SIMPLIFIED LOGIC
        # Just find ANY host with compatible storage, no rules applied
        # ============================================================

        foreach ($vm in $vmsPoweredOff) {
            # Dynamic recalculation of available slots
            $nbEnCours = Get-CurrentVmotionCount -ClusterName $ClusterName
            $slotsDispo = $MaxMigrationsEvacTotal - ($nbEnCours + $movesThisLoop)

            if ($slotsDispo -le 0) {
                Write-Log -Message "[EVACUATION] vMotion slots consumed for this loop ($nbEnCours in progress + $movesThisLoop launched), waiting for next iteration."
                return
            }

            # Skip VMs already migrating (even PoweredOff can be migrating)
            if (Test-VmMigrating -VM $vm) {
                Write-Log -Message "[EVACUATION] VM '$($vm.Name)' [PoweredOff] already migrating, skipped."
                continue
            }

            # ============================================================
            # SIMPLIFIED: Just find first host with compatible storage
            # No affinity, no anti-affinity, no load balancing
            # ============================================================
            $compatibleTarget = $null
            foreach ($targetHost in $targetHosts) {
                if (Test-StorageCompatible -VM $vm -TargetHost $targetHost) {
                    $compatibleTarget = $targetHost
                    break  # Take the first compatible host and go!
                }
            }

            if (-not $compatibleTarget) {
                Write-Log -Message "[EVACUATION] No target host with compatible storage for VM '$($vm.Name)' [PoweredOff]. vMotion skipped." -Level Warning
                continue
            }

            # ============================================================
            # Execute the migration for PoweredOff VM (no rule checking)
            # ============================================================
            $msg = "[EVACUATION][SIMPLE] VM '$($vm.Name)' [PoweredOff] : $($vm.VMHost.Name) → $($compatibleTarget.Name)"

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            }
            else {
                Write-Host $msg
                try {
                    Move-VM -VM $vm -Destination $compatibleTarget -RunAsync -ErrorAction Stop | Out-Null
                    Write-Log -Message "[EVACUATION] Migration launched successfully"
                    $movesThisLoop++
                }
                catch {
                    Write-Log -Message "[EVACUATION] Error during migration of PoweredOff VM '$($vm.Name)': $_" -Level Warning
                    continue
                }
            }
        }

        Write-Log -Message "-----------------------------------------"
    }

    if ($movesThisLoop -gt 0) {
        Write-Log -Message "========================================="
        Write-Log -Message "[EVACUATION] $movesThisLoop migration(s) launched for evacuation"
        Write-Log -Message "========================================="
    }
}



#region Balancing
function Balance-Cluster {
    param(
        [string]$ClusterName,
        [int]$MaxMigrations,
        [int]$HighCpuPercent,
        [int]$LowCpuPercent,
        [int]$HighMemPercent,
        [int]$LowMemPercent,
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

    $overloaded = $hostLoads | Where-Object {
        $_.CpuPct -ge $HighCpuPercent -or $_.MemPct -ge $HighMemPercent
    } | Sort-Object LoadScore -Descending

    $underloaded = $hostLoads | Where-Object {
        $_.CpuPct -le $LowCpuPercent -and $_.MemPct -le $LowMemPercent
    } | Sort-Object LoadScore

    if (-not $overloaded -or -not $underloaded) {
        Write-Log -Message "No significant imbalance detected."
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
            if ($movesDone -ge $MaxMigrations) { return }
            if ($src.ESXHost.Name -eq $dst.ESXHost.Name) { continue }

            $candidate = $vmCandidates |
                Sort-Object @{Expression = { [math]::Abs($_.MemoryGB - $medianSize) }; Ascending = $true} |
                Select-Object -First 1

            if (-not $candidate) { break }

            if (Test-VmMigrating -VM $candidate) { continue }

            if (-not (Test-StorageCompatible -VM $candidate -TargetHost $dst.ESXHost)) { continue }

            $vmToHostTarget = Get-VmToHostTargetHost -VMName $candidate.Name -VmToHostRules $VmToHostRules -ClusterName $ClusterName -VM $candidate
            if ($vmToHostTarget -and $vmToHostTarget.Name -ne $dst.ESXHost.Name) {
                Write-Log -Message "[VM-TO-HOST] VM '$($candidate.Name)' must go to '$($vmToHostTarget.Name)'. Rebalancing cancelled."
                continue
            }

            $affinityHost = Get-AffinityTargetHost -VMName $candidate.Name -AffinityGroups $AffinityGroups -ClusterName $ClusterName -VM $candidate
            if ($affinityHost -and $affinityHost.Name -ne $dst.ESXHost.Name) {
                Write-Log -Message "[AFFINITY] VM '$($candidate.Name)' must stay with its group. Rebalancing cancelled."
                continue
            }

            $compatibleHosts = Get-AntiAffinityCompatibleHosts -VM $candidate -TargetHosts @($dst.ESXHost) -AntiAffinityGroups $AntiAffinityGroups -ClusterName $ClusterName
            if (-not $compatibleHosts) {
                Write-Log -Message "[ANTI-AFFINITY] VM '$($candidate.Name)' cannot go to '$($dst.ESXHost.Name)'. Rebalancing cancelled."
                continue
            }

            $msg = "Rebalancing $($candidate.Name) : $($src.ESXHost.Name) -> $($dst.ESXHost.Name)"

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            } else {
                Write-Host $msg
                Move-VM -VM $candidate -Destination $dst.ESXHost -RunAsync | Out-Null
            }

            $movesDone++
        }
    }
}

#endregion


#region Main Loop
while ($true) {
    try {
        # Automatic garbage collection every 12h
        $timeSinceLastGC = (Get-Date) - $script:lastGarbageCollection
        if ($timeSinceLastGC.TotalHours -ge $script:gcIntervalHours) {
            Write-Log -Message "[MEMORY] ⏰ Running automatic garbage collection" -Level Info
            Invoke-MemoryCleanup
        }

        # vCenter recycling every 24h
        $timeSinceLastRecycle = (Get-Date) - $script:lastVCenterRecycle
        if ($timeSinceLastRecycle.TotalHours -ge $script:vcRecycleIntervalHours) {
            Write-Log -Message "[MEMORY] ⏰ Running vCenter recycle" -Level Info
            $recycleSuccess = Invoke-VCenterRecycle -VCenter $vCenter -Credential $credential

            if (-not $recycleSuccess) {
                Write-Log -Message "[MEMORY] ⚠️ vCenter recycle failed, will retry next iteration" -Level Warning
            }
        }

        # Memory monitoring every hour
        $timeSinceLastMonitor = (Get-Date) - $script:lastMemoryMonitor
        if ($timeSinceLastMonitor.TotalHours -ge $script:memoryMonitorIntervalHours) {
            Show-MemoryUsage
        }

        # Statistics cache cleanup
        Clear-StatisticsCache

        Write-Log -Message "---- Iteration $(Get-Date) : cluster $clusterNameLocal ----"

        if ($null -eq $script:lastAffinityLoad -or ((Get-Date) - $script:lastAffinityLoad).TotalSeconds -ge $AffinityCheckIntervalSeconds) {
            $script:affinityGroups = Read-AffinityList -FilePath $AffinityListPath
            $script:lastAffinityLoad = Get-Date
        }

        if ($null -eq $script:lastAntiAffinityLoad -or ((Get-Date) - $script:lastAntiAffinityLoad).TotalSeconds -ge $AntiAffinityCheckIntervalSeconds) {
            $script:antiAffinityGroups = Read-AntiAffinityList -FilePath $AntiAffinityListPath
            $script:lastAntiAffinityLoad = Get-Date
        }

        if ($null -eq $script:lastVmToHostLoad -or ((Get-Date) - $script:lastVmToHostLoad).TotalSeconds -ge $VmToHostCheckIntervalSeconds) {
            $script:vmToHostRules = Read-VmToHostList -FilePath $VmToHostListPath
            $script:lastVmToHostLoad = Get-Date
        }

        
        if ($script:affinityGroups.Count -gt 0) {
            Enforce-AffinityGroups `
                -ClusterName $clusterNameLocal `
                -AffinityGroups $script:affinityGroups `
                -MaxMigrations $MaxMigrationsAffinityPerLoop `
                -NameBlacklistPatterns $NameBlacklistPatterns `
                -TagBlacklistNames $TagBlacklistNames `
                -IncludeNetwork:$IncludeNetwork `
                -DryRun:$DryRun
        }

        $antiAffinityArray = @($script:antiAffinityGroups)
        if ($antiAffinityArray.Count -gt 0) {
            Enforce-AntiAffinityGroups `
                -ClusterName $clusterNameLocal `
                -AntiAffinityGroups $antiAffinityArray `
                -MaxMigrations $MaxMigrationsAntiAffinityPerLoop `
                -NameBlacklistPatterns $NameBlacklistPatterns `
                -TagBlacklistNames $TagBlacklistNames `
                -IncludeNetwork:$IncludeNetwork `
                -DryRun:$DryRun
        }

        $vmToHostArray = @($script:vmToHostRules)
        if ($vmToHostArray.Count -gt 0) {
            Enforce-VmToHostRules `
                -ClusterName $clusterNameLocal `
                -VmToHostRules $vmToHostArray `
                -MaxMigrations $MaxMigrationsVmToHostPerLoop `
                -NameBlacklistPatterns $NameBlacklistPatterns `
                -TagBlacklistNames $TagBlacklistNames `
                -IncludeNetwork:$IncludeNetwork `
                -DryRun:$DryRun
        }

        $hostsNeedingEvac = Get-HostsNeedingEvacuation -ClusterName $clusterNameLocal

        if ($hostsNeedingEvac) {
            $hostsWithVMs = $hostsNeedingEvac | Where-Object {
                $vmsToMove = $_ | Get-VM | Where-Object {
                    $_.PowerState -eq 'PoweredOn' -and
                    -not (Test-VmBlacklisted -VM $_ `
                            -NameBlacklistPatterns $NameBlacklistPatterns `
                            -TagBlacklistNames $TagBlacklistNames)
                }
                ($vmsToMove | Measure-Object).Count -gt 0
            }

            if ($hostsWithVMs) {
                if (-not $script:wasInEvacuationMode) {
                    Write-Log -Message "*** Switching to evacuation mode (short loop ${EvacLoopSleepSeconds}s) ***"
                    $script:wasInEvacuationMode = $true
                }

                Evacuate-Hosts `
                    -HostsToEvacuate $hostsWithVMs `
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
            }
            else {
                if ($script:wasInEvacuationMode) {
                    Write-Log -Message "*** EVACUATION COMPLETE! Returning to normal mode (${NormalLoopSleepSeconds}s). ***"
                    $script:wasInEvacuationMode = $false
                }

                Balance-Cluster `
                    -ClusterName $clusterNameLocal `
                    -MaxMigrations $MaxMigrationsBalancePerLoop `
                    -HighCpuPercent $HighCpuPercent `
                    -LowCpuPercent  $LowCpuPercent `
                    -HighMemPercent $HighMemPercent `
                    -LowMemPercent  $LowMemPercent `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames `
                    -AffinityGroups $script:affinityGroups `
                    -AntiAffinityGroups $script:antiAffinityGroups `
                    -VmToHostRules $script:vmToHostRules `
                    -IncludeNetwork:$IncludeNetwork `
                    -DryRun:$DryRun

                $sleep = $NormalLoopSleepSeconds
            }
        }
        else {
            if ($script:wasInEvacuationMode) {
                Write-Log -Message "*** No more maintenance hosts detected. Returning to normal mode. ***"
                $script:wasInEvacuationMode = $false
            }

            Balance-Cluster `
                -ClusterName $clusterNameLocal `
                -MaxMigrations $MaxMigrationsBalancePerLoop `
                -HighCpuPercent $HighCpuPercent `
                -LowCpuPercent  $LowCpuPercent `
                -HighMemPercent $HighMemPercent `
                -LowMemPercent  $LowMemPercent `
                -NameBlacklistPatterns $NameBlacklistPatterns `
                -TagBlacklistNames $TagBlacklistNames `
                -AffinityGroups $script:affinityGroups `
                -AntiAffinityGroups $script:antiAffinityGroups `
                -VmToHostRules $script:vmToHostRules `
                -IncludeNetwork:$IncludeNetwork `
                -DryRun:$DryRun

            $sleep = $NormalLoopSleepSeconds
        }
    }
    catch {
        Write-Log -Message "Error in pseudo-DRS loop (cluster $clusterNameLocal) : $_" -Level Warning
        $sleep = $NormalLoopSleepSeconds
    }

    Write-Log -Message "Pausing for $sleep seconds..."
    Start-Sleep -Seconds $sleep
}
#endregion
