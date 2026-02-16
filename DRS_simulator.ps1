<#
.SYNOPSIS
    DRS Simulator Script - Version 1.36

.DESCRIPTION
    DRS-Simulator - Custom DRS Implementation for VMware vSphere

.NOTES
    Version: 1.35
    AUTHOR : Denis Foulon
    Date: 2026-01-16


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
    3. Create credential file: Get-Credential | Export-Clixml -Path ".\secrets\vcenter_credentials.xml"
    4. Adjust paths to rule files (affinity, anti-affinity, VM-to-Host)
    5. Configure Syslog server parameters if using centralized logging
    6. Adjust thresholds and limits according to your environment

================================================================================
#>


param(
    [string]$VCenter = "vcenter.example.local",
    [string]$ClusterName = "cluster-example",

    # Timing parameters
    [int]$NormalLoopSleepSeconds = 60,
    [int]$EvacLoopSleepSeconds = 20,

    # Migration limits
    [int]$MaxMigrationsBalancePerLoop = 3,
    [int]$MaxMigrationsEvacTotal = 14,
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
    [string]$AffinityListPath = ".\rules\affinity_linux.txt",
    [int]$AffinityCheckIntervalSeconds = 300,
    [string]$AntiAffinityListPath = ".\rules\anti_affinity_linux.txt",
    [int]$AntiAffinityCheckIntervalSeconds = 300,
    [string]$VmToHostListPath = ".\rules\vm_to_host_linux.txt",
    [int]$VmToHostCheckIntervalSeconds = 300,

    # SYSLOG parameters (new in v1.31)
    [string]$SyslogServer = "syslog.example.local",  # Your log server IP
    [int]$SyslogPort = 514,                    # Standard syslog UDP port
    [int]$SyslogFacility = 16,                 # Facility 16 = local0
    [switch]$EnableSyslog = $true,             # Enable/disable syslog sending

    # Options
    [switch]$IncludeNetwork,
    [switch]$DryRun
)

#Rules check frequency - check rules every X loops instead of every loop
# Example: 15 = check every 15 minutes (with 60s loop), reducing CPU/IO load
# Set to 1 to check every loop (original behavior)
$RulesCheckEveryXLoops = 15

# Loop counter for throttling
$script:loopCounter = 0

# Last check time variables (now using file LastWriteTime instead of timer)
# These will be set to file timestamps, not DateTime
$script:lastAffinityLoad = $null
$script:lastAntiAffinityLoad = $null
$script:lastVmToHostLoad = $null

# Rule storage (cached between checks)
$script:affinityGroups = @()
$script:antiAffinityGroups = @()
$script:vmToHostRules = @()
# ===== FIN VARIABLES DE THROTTLING =====

#region Global Cache Variables for Performance Optimization
$script:allClusterVMs = $null
$script:allClusterHosts = $null
$script:lastClusterDataRefresh = $null
$script:clusterDataRefreshIntervalSeconds = 30

$script:hostLoadCache = @{}
$script:hostLoadCacheTTL = 30
#endregion


#region Memory Management Tracking Variables
# Variables pour la gestion mémoire
$script:lastGarbageCollection = Get-Date
$script:lastVCenterRecycle = Get-Date
$script:lastMemoryMonitor = Get-Date
##$script:gcIntervalHours = 12
##$script:vcRecycleIntervalHours = 24
$script:gcIntervalHours = 1
$script:vcRecycleIntervalHours = 2
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
        [int]$Severity = 6,  # Info by default

        [switch]$AlsoWriteHost
    )

    if (-not $script:EnableSyslog) {
        if ($AlsoWriteHost) {
            Write-Host $Message
        }
        return
    }

    try {
        # PRI calculation per RFC 3164: PRI = (Facility * 8) + Severity
        $Priority = ($script:SyslogFacility * 8) + $Severity

        # Syslog message format: <PRI>TIMESTAMP HOSTNAME MESSAGE
        $Timestamp = Get-Date -Format "MMM dd HH:mm:ss"
        $Hostname = $env:COMPUTERNAME
        $SyslogMsg = "<$Priority>$Timestamp $Hostname DRS_Simulator: $Message"

        # UDP client creation
        $UdpClient = New-Object System.Net.Sockets.UdpClient
        $UdpClient.Connect($script:SyslogServer, $script:SyslogPort)

        # Encoding and sending
        $Encoding = [System.Text.Encoding]::UTF8
        $BytesSyslogMessage = $Encoding.GetBytes($SyslogMsg)

        # Limited to 1024 bytes (RFC 3164)
        if ($BytesSyslogMessage.Length -gt 1024) {
            $BytesSyslogMessage = $BytesSyslogMessage[0..1023]
        }

        $null = $UdpClient.Send($BytesSyslogMessage, $BytesSyslogMessage.Length)
        $UdpClient.Close()
        $UdpClient.Dispose()

    } catch {
        # In case of syslog error, display at least in console
        Write-Warning "Syslog send error: $($_.Exception.Message)"
    }

    # Console display if requested
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

    # Level mapping to syslog severity
    $SeverityMap = @{
        'Error'   = 3  # Error
        'Warning' = 4  # Warning
        'Info'    = 6  # Informational
        'Debug'   = 7  # Debug
    }

    $Severity = $SeverityMap[$Level]

    # Syslog send + console display
    Send-SyslogMessage -Message $Message -Severity $Severity -AlsoWriteHost

    # Color management for Write-Host based on level
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
    Force le garbage collection pour libérer la mémoire
#>
function Invoke-MemoryCleanup {
    param(
        [switch]$Force
    )

    try {
        $beforeMem = [System.GC]::GetTotalMemory($false) / 1MB

        # Forcer la collecte sur toutes les générations
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()

        $afterMem = [System.GC]::GetTotalMemory($false) / 1MB
        $freed = $beforeMem - $afterMem

        Write-Log -Message "[MEMORY] Garbage collection effectuée: ${freed:F2} MB libérés (avant: ${beforeMem:F2} MB, après: ${afterMem:F2} MB)" -Level Info

        $script:lastGarbageCollection = Get-Date
    }
    catch {
        Write-Log -Message "[MEMORY] Erreur lors du garbage collection: $_" -Level Warning
    }
}

<#
.SYNOPSIS
    Recycle la connexion vCenter pour libérer les ressources
#>
function Invoke-VCenterRecycle {
    param(
        [Parameter(Mandatory)]
        [string]$VCenter,

        [Parameter(Mandatory)]
        $Credential
    )

    try {
        Write-Log -Message "[VCENTER] Recyclage de la connexion vCenter..." -Level Info

        # Déconnexion propre
        $currentConnections = $global:DefaultVIServers
        if ($currentConnections) {
            foreach ($conn in $currentConnections) {
                Disconnect-VIServer -Server $conn -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log -Message "[VCENTER] Déconnexion de $($conn.Name)" -Level Info
            }
        }

        # Attendre un peu pour que les ressources soient libérées
        Start-Sleep -Seconds 5

        # Garbage collection après déconnexion
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        # Reconnexion
        Write-Log -Message "[VCENTER] Reconnexion à $VCenter..." -Level Info
        Connect-VIServer -Server $VCenter -Credential $Credential -ErrorAction Stop | Out-Null

        Write-Log -Message "[VCENTER] Reconnexion réussie" -Level Info
        $script:lastVCenterRecycle = Get-Date

        return $true
    }
    catch {
        Write-Log -Message "[VCENTER] Erreur lors du recyclage: $_" -Level Error
        Write-Log -Message "[VCENTER] Tentative de reconnexion..." -Level Warning

        try {
            Connect-VIServer -Server $VCenter -Credential $Credential -ErrorAction Stop | Out-Null
            Write-Log -Message "[VCENTER] Reconnexion d'urgence réussie" -Level Info
            return $true
        }
        catch {
            Write-Log -Message "[VCENTER] Échec de la reconnexion d'urgence: $_" -Level Error
            return $false
        }
    }
}

<#
.SYNOPSIS
    Monitore l'utilisation mémoire du processus PowerShell
#>
function Show-MemoryUsage {
    try {
        $process = Get-Process -Id $PID
        $memoryMB = $process.WorkingSet64 / 1MB
        $peakMemoryMB = $process.PeakWorkingSet64 / 1MB
        $privateMemoryMB = $process.PrivateMemorySize64 / 1MB

        Write-Log -Message "[MEMORY] Utilisation mémoire actuelle: ${memoryMB:F2} MB (pic: ${peakMemoryMB:F2} MB, privée: ${privateMemoryMB:F2} MB)" -Level Info

        # Alerte si la mémoire dépasse 2 GB
        if ($memoryMB -gt 2048) {
            Write-Log -Message "[MEMORY] ⚠️ ATTENTION: Utilisation mémoire élevée (>${memoryMB:F2} MB)" -Level Warning
            Invoke-MemoryCleanup
        }

        $script:lastMemoryMonitor = Get-Date
    }
    catch {
        Write-Log -Message "[MEMORY] Erreur lors du monitoring mémoire: $_" -Level Warning
    }
}

<#
.SYNOPSIS
    Nettoie les statistiques Get-Stat en cache
#>
function Clear-StatisticsCache {
    try {
        # Vider le cache des statistiques VMware
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

        Write-Log -Message "[MEMORY] Cache des statistiques nettoyé" -Level Debug
    }
    catch {
        Write-Log -Message "[MEMORY] Erreur lors du nettoyage du cache: $_" -Level Warning
    }
}
#endregion


#region vCenter Connection
Write-Log -Message "Connecting to $VCenter ..."

# Credentials are loaded from an external CLIXML file.
if (-not (Test-Path $CredentialFile)) {
    throw "Credential file not found: $CredentialFile (create it with Get-Credential | Export-Clixml)"
}

$credential = Import-Clixml -Path $CredentialFile
Connect-VIServer -Server $VCenter -Credential $credential | Out-Null

$clusterNameLocal = $ClusterName
Write-Log -Message "Starting pseudo-DRS on cluster '$clusterNameLocal' (Ctrl+C to stop)."

# State variable to track evacuation mode
$script:wasInEvacuationMode = $false
$script:evacuationQueue = @{}
# Variables for affinity AND anti-affinity AND VM-to-Host systems
$script:lastAffinityLoad = $null
$script:lastAntiAffinityLoad = $null
$script:lastVmToHostLoad = $null
$script:affinityGroups = @()
$script:antiAffinityGroups = @()
$script:vmToHostRules = @()

# ---------- Affinity file management ----------

function Read-AffinityList {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Log -Message " -Level WarningAffinity file not found: $FilePath"
        return @()
    }
    
    $groups = @()
    $lines = Get-Content -Path $FilePath -ErrorAction SilentlyContinue
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        
        # Split line into VM names (space-separated)
        $vmNames = $line -split '\s+' | Where-Object { $_ -ne '' }
        if ($vmNames.Count -gt 1) {
            $groups += ,@($vmNames)  # Add the group
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
    
    # Find the group containing this VM
    $groupVMs = $null
    foreach ($group in $AffinityGroups) {
        if ($group -contains $VMName) {
            $groupVMs = $group
            break
        }
    }
    
    if (-not $groupVMs) { return $null }
    
    # Search for hosts where group VMs are already present
    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction SilentlyContinue
    if (-not $clusterObj) { return $null }
    
    # Get all cluster VMs once
    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue
    
    $candidateHosts = @()
    
    foreach ($vmNameInGroup in $groupVMs) {
        if ($vmNameInGroup -eq $VMName) { continue }  # Ignore the VM itself
        
        # Filter by exact name instead of using Get-VM -Name
        $groupVM = $allClusterVMs | Where-Object { $_.Name -eq $vmNameInGroup -and $_.PowerState -eq 'PoweredOn' }
        
        if ($groupVM -and $groupVM.VMHost) {
            # Check if this host is storage-compatible with our VM
            if (Test-StorageCompatible -VM $VM -TargetHost $groupVM.VMHost) {
                $candidateHosts += $groupVM.VMHost
            }
        }
    }
    
    if ($candidateHosts.Count -eq 0) { return $null }
    
    # Return the host hosting the most VMs in the group
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
    
    # Get all cluster VMs once
    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue

    $movesDone = 0

    foreach ($group in $AffinityGroups) {
        if ($movesDone -ge $MaxMigrations) { 
            Write-Log -Message "[AFFINITY] Migration limit reached ($MaxMigrations), continuing next cycle."
            return 
        }

        # Récupérer toutes les VMs du groupe qui existent et sont allumées
        $groupVMs = @()
        foreach ($vmName in $group) {
            # Filter by exact name instead of using Get-VM -Name
            $vm = $allClusterVMs | Where-Object { $_.Name -eq $vmName -and $_.PowerState -eq 'PoweredOn' }
            
            if ($vm -and -not (Test-VmBlacklisted -VM $vm `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames)) {
                $groupVMs += $vm
            }
        }

        if ($groupVMs.Count -le 1) { continue }

        # Determine reference host taking storage into account
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
            Write-Log -Message " -Level Warning[AFFINITY] Cannot find compatible host for group [$($group -join ', ')]"
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
                Write-Log -Message " -Level Warning[AFFINITY] VM '$($vm.Name)' storage-incompatible with $targetHostName. Searching for alternative host..."
                
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
                    Write-Log -Message " -Level Warning[AFFINITE] No compatible host found for '$($vm.Name)'. Migration skipped."
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
        Write-Log -Message " -Level WarningAnti-affinity file not found: $FilePath"
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
            Write-Log -Message " -Level Warning[ANTI-AFFINITY] Line skipped (single VM): $($vmNames[0])"
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
        Write-Log -Message " -Level Warning[ANTI-AFFINITY] Less than 2 hosts available, cannot apply rules."
        return
    }

    $movesDone = 0
    $groupIndex = 0
    
    foreach ($groupObj in $AntiAffinityGroups) {
        $groupIndex++
        
        if ($movesDone -ge $MaxMigrations) { 
            Write-Log -Message "[ANTI-AFFINITE] Limite de migrations atteinte ($MaxMigrations), continuing next cycle."
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
                        Write-Log -Message " -Level Warning[ANTI-AFFINITY] Migration error: $_"
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
        Write-Log -Message " -Level WarningVM-to-Host file not found: $FilePath"
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
            # Detection: if contains 'esx', 'host', '-mgt' or '.' it's a host
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

# ---------- Host load helpers ----------

#region Cluster Data Cache Management
function Update-ClusterDataCache {
    param(
        [Parameter(Mandatory)]
        [string]$ClusterName,
        [switch]$Force
    )

    $now = Get-Date

    if (-not $Force -and $script:lastClusterDataRefresh) {
        $elapsed = ($now - $script:lastClusterDataRefresh).TotalSeconds
        if ($elapsed -lt $script:clusterDataRefreshIntervalSeconds) {
            return
        }
    }

    try {
        $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop
        $script:allClusterVMs = Get-VM -Location $clusterObj -ErrorAction Stop
        $script:allClusterHosts = Get-VMHost -Location $clusterObj | Where-Object { $_.ConnectionState -eq 'Connected' }
        $script:lastClusterDataRefresh = $now

        Write-Log -Message "[CACHE] Rafraîchi: $($script:allClusterVMs.Count) VMs, $($script:allClusterHosts.Count) hosts" -Level Info
    }
    catch {
        Write-Log -Message "[CACHE] Erreur rafraîchissement: $_" -Level Warning
    }
}
#endregion



function Get-HostLoad {
    param(
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]$ESXHost,
        [switch]$IncludeNetwork,
        [switch]$BypassCache
    )

    $cacheKey = "$($ESXHost.Name)_$IncludeNetwork"
    $now = Get-Date

    if (-not $BypassCache -and $script:hostLoadCache.ContainsKey($cacheKey)) {
        $cached = $script:hostLoadCache[$cacheKey]
        if (($now - $cached.Timestamp).TotalSeconds -lt $script:hostLoadCacheTTL) {
            return $cached.Data
        }
    }

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

        # Cleanup des statistiques pour libérer la mémoire
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

    $result = [PSCustomObject]@{
        ESXHost      = $ESXHost
        CpuPct       = $cpuUsagePct
        MemPct       = $memUsagePct
        NetKbps      = $netUsageKbps
        LoadScore    = $score
        PoweredOnVMs = ($ESXHost | Get-VM | Where-Object {$_.PowerState -eq 'PoweredOn'}).Count
    }

    $script:hostLoadCache[$cacheKey] = @{
        Data = $result
        Timestamp = $now
    }

    return $result
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
#    if ($vmView) {
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
        if ($ds -like 'EXEMPT_DATASTORE_*') { continue }

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
        [int]$RecentMinutes = 120  # Augmenté de 10 à 120 minutes
    )

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $allHosts   = Get-VMHost -Location $clusterObj

    # 1. Détection directe: hôtes déjà en état Maintenance ou NotResponding
    $hostsMaintenance = $allHosts | Where-Object { 
        $_.ConnectionState -eq 'Maintenance' -or 
        $_.ConnectionState -eq 'NotResponding'
    }

    # 2. Détection via tâches en cours
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

    # 3. Détection événementielle (avec fenêtre temporelle étendue)
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

    # 4. NOUVEAU: Vérifier aussi la queue d'évacuation persistante
    $hostsFromQueue = @()
    foreach ($hostName in $script:evacuationQueue.Keys) {
        $esxHost = Get-VMHost -Name $hostName -ErrorAction SilentlyContinue
        if ($esxHost) {
            $hostsFromQueue += $host
        }
    }

    # Agrégation de toutes les sources
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

    # ===== NOUVELLE LOGIQUE: Initialisation de la queue d'évacuation =====
    foreach ($mmESX in $HostsToEvacuate) {
        # Si l'hôte n'est PAS encore dans la queue, l'initialiser
        if (-not $script:evacuationQueue.ContainsKey($mmESX.Name)) {
            
            Write-Log -Message "[EVACUATION] 🆕 Nouvel hôte détecté en maintenance: $($mmESX.Name)"
            Write-Log -Message "[EVACUATION] Initialisation de la queue d'évacuation..."
            
            # Récupérer TOUTES les VMs à évacuer (powered ON uniquement pour démarrer)
            $allVMsOnHost = $mmESX | Get-VM | Where-Object {
                -not (Test-VmBlacklisted -VM $_ `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames)
            }
            
            $vmsPoweredOn = $allVMsOnHost | Where-Object { $_.PowerState -eq 'PoweredOn' }
            $vmsPoweredOff = $allVMsOnHost | Where-Object { $_.PowerState -eq 'PoweredOff' }
            
            # Créer l'entrée dans la queue avec TOUTES les VMs
            $script:evacuationQueue[$mmESX.Name] = @{
                VMs = @($vmsPoweredOn) + @($vmsPoweredOff)
                VMsInitialCount = $vmsPoweredOn.Count + $vmsPoweredOff.Count
                VMsPoweredOnCount = $vmsPoweredOn.Count
                VMsPoweredOffCount = $vmsPoweredOff.Count
                StartTime = Get-Date
                Host = $mmESX
            }
            
            Write-Log -Message "[EVACUATION] 📋 Queue initialisée: $($vmsPoweredOn.Count) VM(s) ON + $($vmsPoweredOff.Count) VM(s) OFF = $($vmsPoweredOn.Count + $vmsPoweredOff.Count) total"
        }
    }
    # ===== FIN NOUVELLE LOGIQUE =====

    # Vérifier les slots vMotion disponibles
    $nbEnCours = Get-CurrentVmotionCount -ClusterName $ClusterName
    $slotsDispoInitial = $MaxMigrationsEvacTotal - $nbEnCours

    if ($slotsDispoInitial -le 0) {
        Write-Log -Message "[EVACUATION] ⏸️ Aucun slot vMotion disponible ($nbEnCours en cours / $MaxMigrationsEvacTotal max), attente prochaine boucle."
        return
    }

    $movesThisLoop = 0

    # ===== NOUVELLE LOGIQUE: Traiter la queue au lieu de recharger les VMs =====
    foreach ($hostName in @($script:evacuationQueue.Keys)) {
        
        $queueEntry = $script:evacuationQueue[$hostName]
        $mmESX = $queueEntry.Host
        
        # Rafraîchir l'état de l'hôte
        $mmESX = Get-VMHost -Name $mmESX.Name -ErrorAction SilentlyContinue
        if (-not $mmESX) {
            Write-Log -Message "[EVACUATION] ⚠️ Hôte '$hostName' introuvable, suppression de la queue" -Level Warning
            $script:evacuationQueue.Remove($hostName)
            continue
        }

        Write-Log -Message "=========================================="
        Write-Log -Message "[EVACUATION] 🔄 Traitement de l'hôte: $($mmESX.Name)"
        Write-Log -Message "[EVACUATION] État: $($mmESX.ConnectionState)"
        
        # Obtenir les hôtes cibles
        $targetHosts = Get-VMHost -Location $clusterObj | 
            Where-Object { $_.ConnectionState -eq 'Connected' -and $_.Name -ne $mmESX.Name }

        if (-not $targetHosts) {
            Write-Log -Message "[EVACUATION] ❌ Aucun hôte cible disponible pour $($mmESX.Name)" -Level Warning
            continue
        }

        # Récupérer les VMs restantes dans la queue pour CET hôte
        $vmsInQueue = $queueEntry.VMs
        
        if (-not $vmsInQueue -or $vmsInQueue.Count -eq 0) {
            Write-Log -Message "[EVACUATION] ✅ Queue vide pour $($mmESX.Name)"
            
            # Vérifier si l'hôte est sorti du mode maintenance
            if ($mmESX.ConnectionState -eq 'Connected') {
                Write-Log -Message "[EVACUATION] ✅ Hôte $($mmESX.Name) sorti du mode maintenance ET queue vide → Nettoyage"
                $script:evacuationQueue.Remove($hostName)
            } else {
                Write-Log -Message "[EVACUATION] ⏳ Hôte $($mmESX.Name) toujours en $($mmESX.ConnectionState), queue vide, surveillance maintenue"
            }
            continue
        }

        # Rafraîchir l'état des VMs dans la queue
        $vmsStillOnHost = @()
        foreach ($vm in $vmsInQueue) {
            $refreshedVM = Get-VM -Name $vm.Name -ErrorAction SilentlyContinue
            
            if ($refreshedVM) {
                # Si la VM est toujours sur l'hôte en maintenance
                if ($refreshedVM.VMHost.Name -eq $mmESX.Name) {
                    $vmsStillOnHost += $refreshedVM
                } else {
                    Write-Log -Message "[EVACUATION] ✓ VM '$($vm.Name)' a été migrée vers $($refreshedVM.VMHost.Name)"
                }
            } else {
                Write-Log -Message "[EVACUATION] ⚠️ VM '$($vm.Name)' introuvable (supprimée?)" -Level Warning
            }
        }

        # Mettre à jour la queue avec les VMs restantes
        $queueEntry.VMs = $vmsStillOnHost
        
        $elapsed = (Get-Date) - $queueEntry.StartTime
        Write-Log -Message "[EVACUATION] 📊 Progression: $($queueEntry.VMsInitialCount - $vmsStillOnHost.Count)/$($queueEntry.VMsInitialCount) VMs évacuées (durée: $($elapsed.ToString('hh\:mm\:ss')))"
        Write-Log -Message "[EVACUATION] 📋 VMs restantes: $($vmsStillOnHost.Count)"

        if ($vmsStillOnHost.Count -eq 0) {
            if ($mmESX.ConnectionState -eq 'Connected') {
                Write-Log -Message "[EVACUATION] 🎉 ÉVACUATION TERMINÉE pour $($mmESX.Name) - Hôte sorti du mode maintenance"
                $script:evacuationQueue.Remove($hostName)
            }
            continue
        }

        # Séparer PoweredOn et PoweredOff
        $vmsPoweredOn = $vmsStillOnHost | Where-Object { $_.PowerState -eq 'PoweredOn' }
        $vmsPoweredOff = $vmsStillOnHost | Where-Object { $_.PowerState -eq 'PoweredOff' }

        Write-Log -Message "[EVACUATION] VMs à traiter: $($vmsPoweredOn.Count) ON, $($vmsPoweredOff.Count) OFF"

        # Traiter les VMs PoweredOn en priorité
        foreach ($vm in $vmsPoweredOn) {
            
            # ===== OPTIMISATION: Vérifier les slots seulement si on approche de la limite =====
            if ($movesThisLoop -ge $MaxMigrationsEvacTotal) {
                Write-Log -Message "[EVACUATION] ⏸️ Limite de migrations atteinte ($MaxMigrationsEvacTotal), passage à l'hôte suivant."
                break
            }
            
            # Vérification légère : ne recalculer que toutes les 3 VMs
            if ($movesThisLoop % 3 -eq 0) {
                $nbEnCours = Get-CurrentVmotionCount -ClusterName $ClusterName
                $slotsDispo = $MaxMigrationsEvacTotal - $nbEnCours - $movesThisLoop
                
                if ($slotsDispo -le 0) {
                    Write-Log -Message "[EVACUATION] ⏸️ Slots vMotion saturés ($nbEnCours en cours + $movesThisLoop lancées = $($nbEnCours + $movesThisLoop)/$MaxMigrationsEvacTotal)"
                    break
                }
            }
            # ===== FIN OPTIMISATION =====

            # Vérifier si déjà en migration
            if (Test-VmMigrating -VM $vm) {
                Write-Log -Message "[EVACUATION] ⏳ VM '$($vm.Name)' déjà en migration, sautée."
                continue
            }

            # Trouver les hôtes compatibles
            $compatibleTargets = $targetHosts | Where-Object {
                Test-StorageCompatible -VM $vm -TargetHost $_
            }

            if (-not $compatibleTargets -or $compatibleTargets.Count -eq 0) {
                Write-Log -Message "[EVACUATION|STORAGE] ❌ Aucun hôte cible compatible stockage pour '$($vm.Name)' (Mem: $($vm.MemoryGB)GB). VM NON MIGRABLE!" -Level Error
                continue
            }

            Write-Log -Message "[EVACUATION|STORAGE] VM '$($vm.Name)' a $($compatibleTargets.Count) hôte(s) compatible(s) stockage" -Level Debug

            # Logique de sélection de cible (VM-to-Host > Affinity > Anti-Affinity > Meilleur hôte)
            $bestTarget = $null
            $migrationReason = "STORAGE-FALLBACK"

            # 1. VM-to-Host
            $vmToHostTarget = Get-VmToHostTargetHost -VMName $vm.Name -VmToHostRules $VmToHostRules -ClusterName $ClusterName -VM $vm
            if ($vmToHostTarget -and $compatibleTargets.Name -contains $vmToHostTarget.Name) {
                $bestTarget = Get-HostLoad -ESXHost $vmToHostTarget -IncludeNetwork:$IncludeNetwork
                $migrationReason = "VM-TO-HOST"
                Write-Log -Message "[EVACUATION|VM-TO-HOST] VM '$($vm.Name)' → $($vmToHostTarget.Name) (règle respectée)" -Level Debug
            }

            # 2. Affinity
            if (-not $bestTarget) {
                $affinityHost = Get-AffinityTargetHost -VMName $vm.Name -AffinityGroups $AffinityGroups -ClusterName $ClusterName -VM $vm
                if ($affinityHost -and $compatibleTargets.Name -contains $affinityHost.Name) {
                    $bestTarget = Get-HostLoad -ESXHost $affinityHost -IncludeNetwork:$IncludeNetwork
                    $migrationReason = "AFFINITY"
                    Write-Log -Message "[EVACUATION|AFFINITY] VM '$($vm.Name)' → $($affinityHost.Name) (groupe respecté)" -Level Debug
                }
            }

            # 3. Anti-Affinity
            if (-not $bestTarget) {
                $antiAffinityTargets = Get-AntiAffinityCompatibleHosts -VM $vm -TargetHosts $compatibleTargets -AntiAffinityGroups $AntiAffinityGroups -ClusterName $ClusterName
                if ($antiAffinityTargets -and $antiAffinityTargets.Count -gt 0) {
                    $bestTarget = Get-BestTargetHost -ESXHosts $antiAffinityTargets -IncludeNetwork:$IncludeNetwork
                    $migrationReason = "ANTI-AFFINITY"
                    Write-Log -Message "[EVACUATION|ANTI-AFFINITY] VM '$($vm.Name)' (anti-affinity respectée)" -Level Debug
                }
            }

            # 4. Fallback: Meilleur hôte disponible
            if (-not $bestTarget) {
                $bestTarget = Get-BestTargetHost -ESXHosts $compatibleTargets -IncludeNetwork:$IncludeNetwork
                $migrationReason = "STORAGE-FALLBACK"
                Write-Log -Message "[EVACUATION|STORAGE-FALLBACK] VM '$($vm.Name)' → $($bestTarget.ESXHost.Name) (aucune règle applicable, priorité stockage)" -Level Debug
            }

            if (-not $bestTarget -or -not $bestTarget.ESXHost) {
                Write-Log -Message "[EVACUATION|ERREUR] Impossible de sélectionner un hôte pour '$($vm.Name)' (stockage incompatible sur TOUS les hôtes?)" -Level Error
                continue
            }

            # Migration
            $msg = "[EVACUATION|$migrationReason] VM '$($vm.Name)' (PoweredOn, Mem: $($vm.MemoryGB)GB): $($vm.VMHost.Name) → $($bestTarget.ESXHost.Name) (load: $($bestTarget.LoadScore))"

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            } else {
                Write-Host $msg
                try {
                    Move-VM -VM $vm -Destination $bestTarget.ESXHost -RunAsync -ErrorAction Stop | Out-Null
                    Write-Log -Message "[EVACUATION] ✓ Migration lancée avec succès"
                    $movesThisLoop++
                } catch {
                    Write-Log -Message "[EVACUATION] ❌ Erreur lors de la migration de '$($vm.Name)': $_" -Level Warning
                    continue
                }
            }
        }

        # Traiter les VMs PoweredOff (si des slots restent disponibles)
        foreach ($vm in $vmsPoweredOff) {
            
            # ===== OPTIMISATION: Check simple de la limite =====
            if ($movesThisLoop -ge $MaxMigrationsEvacTotal) {
                Write-Log -Message "[EVACUATION] ⏸️ Limite de migrations atteinte, VMs PoweredOff reportées."
                break
            }
            # ===== FIN OPTIMISATION =====

            if (Test-VmMigrating -VM $vm) {
                Write-Log -Message "[EVACUATION] ⏳ VM '$($vm.Name)' (PoweredOff) déjà en migration, sautée."
                continue
            }

            # Trouver un hôte compatible (premier disponible suffit pour PoweredOff)
            $compatibleTarget = $null
            foreach ($targetHost in $targetHosts) {
                if (Test-StorageCompatible -VM $vm -TargetHost $targetHost) {
                    $compatibleTarget = $targetHost
                    break
                }
            }

            if (-not $compatibleTarget) {
                Write-Log -Message "[EVACUATION] ❌ Aucun hôte cible compatible stockage pour '$($vm.Name)' (PoweredOff). vMotion sautée." -Level Warning
                continue
            }

            $msg = "[EVACUATION|SIMPLE] VM '$($vm.Name)' (PoweredOff): $($vm.VMHost.Name) → $($compatibleTarget.Name)"

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            } else {
                Write-Host $msg
                try {
                    Move-VM -VM $vm -Destination $compatibleTarget -RunAsync -ErrorAction Stop | Out-Null
                    Write-Log -Message "[EVACUATION] ✓ Migration lancée avec succès"
                    $movesThisLoop++
                } catch {
                    Write-Log -Message "[EVACUATION] ❌ Erreur lors de la migration de la VM PoweredOff '$($vm.Name)': $_" -Level Warning
                    continue
                }
            }
        }

        Write-Log -Message "=========================================="
    }

    if ($movesThisLoop -gt 0) {
        Write-Log -Message "[EVACUATION] 🚀 $movesThisLoop migration(s) lancée(s) pour évacuation"
    }
}




# ---------- Rébalancing cluster ----------

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
    if ($movesDone -ge $MaxMigrations) {
        break  # ← Utilise break au lieu de return pour finir les migrations en attente
    }
    
    if ($src.ESXHost.Name -eq $dst.ESXHost.Name) {
        continue
    }
    
    $candidate = $vmCandidates | Sort-Object {
        [Math]::Abs($_.MemoryGB - $medianSize)
    } -Ascending | Select-Object -First 1
    
    if (-not $candidate) {
        break
    }
    
    if (Test-VmMigrating -VM $candidate) {
        continue
    }
    
    if (-not (Test-StorageCompatible -VM $candidate -TargetHost $dst.ESXHost)) {
        continue
    }
    
    # Affinity/Anti-Affinity checks...
    
    $msg = "Rebalancing $($candidate.Name): $($src.ESXHost.Name) → $($dst.ESXHost.Name)"
    
    if ($DryRun) {
        Write-Log -Message "[DRYRUN] $msg"
    } else {
        Write-Host $msg
        # IMPORTANT: Lancer la migration en asynchrone
        Move-VM -VM $candidate -Destination $dst.ESXHost -RunAsync -ErrorAction SilentlyContinue | Out-Null
    }
    
    $movesDone++
}

    }
}

# ---------- Main loop ----------
while ($true) {
    try {
        # Increment loop counter for throttling
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
            # Check which hosts have VMs to evacuate
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
        
        # Check if host is still in maintenance
        if ($esxHost.ConnectionState -eq 'Maintenance' -or $esxHost.ConnectionState -eq 'NotResponding') {
            
            # Refresh VM list to be absolutely sure
            $remainingVMs = $esxHost | Get-VM -ErrorAction SilentlyContinue | Where-Object {
                -not (Test-VmBlacklisted -VM $_ `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames)
            }
            
            $vmCount = ($remainingVMs | Measure-Object).Count
            
            if ($vmCount -eq 0) {
                # Evacuation complete, waiting for admin to exit maintenance
                Write-Log -Message "[EVACUATION] ✅ Host '$hostName' - evacuation complete. Waiting for manual exit from maintenance mode." -Level Info
                $hostsInfo += "  • $($esxHost.Name): 0 VMs remaining (manual exit required)"
            } else {
                # Still has VMs
                Write-Log -Message "[EVACUATION] ⏳ Host '$hostName' - $vmCount VM(s) still migrating..."
                $hostsInfo += "  • $($esxHost.Name): $vmCount VM(s) remaining"
            }
            
            $activeMaintenance = $true
            
        } else {
            # Host has exited maintenance (admin did it manually)
            Write-Log -Message "[EVACUATION] ✅ Host '$hostName' exited maintenance mode, removing from queue"
            $script:evacuationQueue.Remove($hostName)
        }
    }
    
    # Log status summary
    if ($hostsInfo.Count -gt 0) {
        Write-Log -Message "*** [EVACUATION] Maintenance status:`n$($hostsInfo -join "`n") ***"
    }
    
    # Check if ANY host still has VMs to migrate
    $hostsWithVMs = $hostsInfo | Where-Object { $_ -notmatch "0 VMs remaining" }
    
    if ($hostsWithVMs.Count -gt 0) {
        # Still migrating VMs, stay in 20s loop
        $sleep = $EvacLoopSleepSeconds
    } else {
        # Evacuation complete (0 VMs on all hosts), return to normal mode
        Write-Log -Message "[EVACUATION] ✅ All evacuations complete (0 VMs remaining on all hosts). Returning to normal mode ($NormalLoopSleepSeconds s)."
        $script:wasInEvacuationMode = $false
        $script:evacuationQueue.Clear()
        $sleep = $NormalLoopSleepSeconds  # Return to 60s normal cycle
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
                            $script:affinityGroups = Read-AffinityList -FilePath $AffinityListPath
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
                            $script:antiAffinityGroups = Read-AntiAffinityList -FilePath $AntiAffinityListPath
                            $script:lastAntiAffinityLoad = $currentAntiAffinityWrite
                            Write-Log -Message "[RULES] Anti-affinity rules reloaded ($($script:antiAffinityGroups.Count) groups)"
                        }
                    }
                    
                    # VM-to-Host rules - reload only if file changed
                    if (Test-Path $VmToHostListPath) {
                        $currentVmToHostWrite = (Get-Item $VmToHostListPath).LastWriteTime
                        if ($currentVmToHostWrite -ne $script:lastVmToHostLoad) {
                            $script:vmToHostRules = Read-VmToHostList -FilePath $VmToHostListPath
                            $script:lastVmToHostLoad = $currentVmToHostWrite
                            Write-Log -Message "[RULES] VM-to-Host rules reloaded ($($script:vmToHostRules.Count) rules)"
                        }
                    }
                    
                    # Apply rules at each cycle where rules are checked
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
                        $script:affinityGroups = Read-AffinityList -FilePath $AffinityListPath
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
                        $script:antiAffinityGroups = Read-AntiAffinityList -FilePath $AntiAffinityListPath
                        $script:lastAntiAffinityLoad = $currentAntiAffinityWrite
                        Write-Log -Message "[RULES] Anti-affinity rules reloaded ($($script:antiAffinityGroups.Count) groups)"
                    }
                }
                
                # VM-to-Host rules - reload only if file changed
                if (Test-Path $VmToHostListPath) {
                    $currentVmToHostWrite = (Get-Item $VmToHostListPath).LastWriteTime
                    if ($currentVmToHostWrite -ne $script:lastVmToHostLoad) {
                        $script:vmToHostRules = Read-VmToHostList -FilePath $VmToHostListPath
                        $script:lastVmToHostLoad = $currentVmToHostWrite
                        Write-Log -Message "[RULES] VM-to-Host rules reloaded ($($script:vmToHostRules.Count) rules)"
                    }
                }
                
                # Apply rules at each cycle where rules are checked
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

    # Sleep before next iteration
    Write-Log -Message "Pausing for $sleep seconds..."
    Start-Sleep -Seconds $sleep
}
