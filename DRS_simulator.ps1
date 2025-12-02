<#
================================================================================
DRS-Simulator - Custom DRS Implementation for VMware vSphere
================================================================================

.AUTHOR
    Denis Foulon
    Version: 1.31
    Date: 2025-12-02
    GitHub: https://github.com/denisfoulon/DRS-Simulator

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

<#
.SYNOPSIS
    DRS Simulator Script - Version 1.31

.DESCRIPTION
    Pseudo-DRS for VMware with centralized log management via Syslog

.NOTES
    Version: 1.31
    Date: 2025-12-02
    What's New in v1.31:
    - Added Send-SyslogMessage function for sending logs to a remote server
    - All logs are now sent via UDP to the log server
    - Console output is still displayed in parallel
    - Configurable Syslog parameters (server, port, facility)
#>

param(
    [string]$VCenter = "vcenter.example.com",
    [string]$ClusterName = "production_cluster",

    # Paramètres temporels
    [int]$NormalLoopSleepSeconds = 60,
    [int]$EvacLoopSleepSeconds = 20,

    # Limites de migrations
    [int]$MaxMigrationsBalancePerLoop = 3,
    [int]$MaxMigrationsEvacTotal = 8,
    [int]$MaxMigrationsAffinityPerLoop = 5,
    [int]$MaxMigrationsAntiAffinityPerLoop = 5,
    [int]$MaxMigrationsVmToHostPerLoop = 5,

    # Seuils CPU/Mem
    [int]$HighCpuPercent = 75,
    [int]$LowCpuPercent = 40,
    [int]$HighMemPercent = 80,
    [int]$LowMemPercent = 50,

    # Blacklists
    [string[]]$NameBlacklistPatterns = @("vCLS", "NOMOVE"),
    [string[]]$TagBlacklistNames = @("No-DRS"),

    # Fichiers de règles
    [string]$AffinityListPath = "C:\DRS_simulator\liste_affinite.txt",
    [int]$AffinityCheckIntervalSeconds = 300,
    [string]$AntiAffinityListPath = "C:\DRS_simulator\liste_antiaffinite.txt",
    [int]$AntiAffinityCheckIntervalSeconds = 300,
    [string]$VmToHostListPath = "C:\DRS_simulator\list_vm_to_host.txt",
    [int]$VmToHostCheckIntervalSeconds = 300,

    # Paramètres SYSLOG (nouveauté v1.31)
    [string]$SyslogServer = "syslog.example.com",  # IP de votre serveur de logs
    [int]$SyslogPort = 514,                    # Port UDP standard syslog
    [int]$SyslogFacility = 16,                 # Facility 16 = local0
    [switch]$EnableSyslog = $true,             # Activer/désactiver l'envoi syslog

    # Options
    [switch]$IncludeNetwork,
    [switch]$DryRun
)

<#
.SYNOPSIS
    Sends a syslog-formatted message to a remote server

.DESCRIPTION
    This function sends messages in RFC 3164 format via UDP to a syslog server.
    Severity levels are automatically determined based on the message type.

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
        [int]$Severity = 6,  # Info par défaut

        [switch]$AlsoWriteHost
    )

    if (-not $script:EnableSyslog) {
        if ($AlsoWriteHost) {
            Write-Host $Message
        }
        return
    }

    try {
        # Calcul du PRI selon RFC 3164: PRI = (Facility * 8) + Severity
        $Priority = ($script:SyslogFacility * 8) + $Severity

        # Format du message syslog: <PRI>TIMESTAMP HOSTNAME MESSAGE
        $Timestamp = Get-Date -Format "MMM dd HH:mm:ss"
        $Hostname = $env:COMPUTERNAME
        $SyslogMsg = "<$Priority>$Timestamp $Hostname DRSLIKE: $Message"

        # Création du client UDP
        $UdpClient = New-Object System.Net.Sockets.UdpClient
        $UdpClient.Connect($script:SyslogServer, $script:SyslogPort)

        # Encodage et envoi
        $Encoding = [System.Text.Encoding]::UTF8
        $BytesSyslogMessage = $Encoding.GetBytes($SyslogMsg)

        # Limitation à 1024 octets (RFC 3164)
        if ($BytesSyslogMessage.Length -gt 1024) {
            $BytesSyslogMessage = $BytesSyslogMessage[0..1023]
        }

        $null = $UdpClient.Send($BytesSyslogMessage, $BytesSyslogMessage.Length)
        $UdpClient.Close()

    } catch {
        # En cas d'erreur syslog, on affiche au moins en console
        Write-Warning "Erreur envoi syslog: $($_.Exception.Message)"
    }

    # Affichage console si demandé
    if ($AlsoWriteHost) {
        Write-Host $Message
    }
}

<#
.SYNOPSIS
    Wrapper pour remplacer Write-Host avec envoi syslog
#>
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet('Info','Warning','Error','Debug')]
        [string]$Level = 'Info'
    )

    # Mapping des niveaux vers syslog severity
    $SeverityMap = @{
        'Error'   = 3  # Error
        'Warning' = 4  # Warning
        'Info'    = 6  # Informational
        'Debug'   = 7  # Debug
    }

    $Severity = $SeverityMap[$Level]

    # Envoi syslog + affichage console
    Send-SyslogMessage -Message $Message -Severity $Severity -AlsoWriteHost

    # Gestion des couleurs pour Write-Host selon le niveau
    if ($Level -eq 'Warning') {
        Write-Host $Message -ForegroundColor Yellow
    } elseif ($Level -eq 'Error') {
        Write-Host $Message -ForegroundColor Red
    }
}
#endregion

#region Connexion vCenter
Write-Log -Message "Connexion à $VCenter ..."

# compte utilisé dans cred_op : ADLYON2\op_powercli
$credential = Import-Clixml -Path C:\scripts\cred_op
Connect-VIServer -Server $vCenter -Credential $credential | Out-Null

$clusterNameLocal = $ClusterName
Write-Log -Message "Démarrage pseudo-DRS sur cluster '$clusterNameLocal' (Ctrl+C pour arrêter)."

# Variable d'état pour suivre le mode évacuation
$script:wasInEvacuationMode = $false

# Variables pour les systèmes d'affinité ET anti-affinité ET VM-to-Host
$script:lastAffinityLoad = $null
$script:lastAntiAffinityLoad = $null
$script:lastVmToHostLoad = $null
$script:affinityGroups = @()
$script:antiAffinityGroups = @()
$script:vmToHostRules = @()

# ---------- Gestion fichier affinité ----------

function Read-AffinityList {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Log -Message " -Level WarningFichier d'affinité introuvable : $FilePath"
        return @()
    }
    
    $groups = @()
    $lines = Get-Content -Path $FilePath -ErrorAction SilentlyContinue
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        
        # Découper la ligne en noms de VMs (séparés par espaces)
        $vmNames = $line -split '\s+' | Where-Object { $_ -ne '' }
        if ($vmNames.Count -gt 1) {
            $groups += ,@($vmNames)  # Ajouter le groupe
        }
    }
    
    Write-Log -Message "Fichier d'affinité chargé : $($groups.Count) groupe(s) détecté(s)"
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
    
    # Trouver le groupe contenant cette VM
    $groupVMs = $null
    foreach ($group in $AffinityGroups) {
        if ($group -contains $VMName) {
            $groupVMs = $group
            break
        }
    }
    
    if (-not $groupVMs) { return $null }
    
    # Chercher les hôtes où des VMs du groupe sont déjà présentes
    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction SilentlyContinue
    if (-not $clusterObj) { return $null }
    
    # Récupérer toutes les VMs du cluster une seule fois
    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue
    
    $candidateHosts = @()
    
    foreach ($vmNameInGroup in $groupVMs) {
        if ($vmNameInGroup -eq $VMName) { continue }  # Ignorer la VM elle-même
        
        # Filtrer par nom exact au lieu d'utiliser Get-VM -Name
        $groupVM = $allClusterVMs | Where-Object { $_.Name -eq $vmNameInGroup -and $_.PowerState -eq 'PoweredOn' }
        
        if ($groupVM -and $groupVM.VMHost) {
            # Vérifier si cet hôte est compatible stockage avec notre VM
            if (Test-StorageCompatible -VM $VM -TargetHost $groupVM.VMHost) {
                $candidateHosts += $groupVM.VMHost
            }
        }
    }
    
    if ($candidateHosts.Count -eq 0) { return $null }
    
    # Retourner l'hôte qui héberge le plus de VMs du groupe
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

    Write-Log -Message "[AFFINITE] Vérification et regroupement des VMs selon les règles d'affinité..."

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $allHosts = Get-VMHost -Location $clusterObj | Where-Object { $_.ConnectionState -eq 'Connected' }
    
    # Récupérer toutes les VMs du cluster une seule fois
    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue

    $movesDone = 0

    foreach ($group in $AffinityGroups) {
        if ($movesDone -ge $MaxMigrations) { 
            Write-Log -Message "[AFFINITE] Limite de migrations atteinte ($MaxMigrations), suite au prochain cycle."
            return 
        }

        # Récupérer toutes les VMs du groupe qui existent et sont allumées
        $groupVMs = @()
        foreach ($vmName in $group) {
            # Filtrer par nom exact au lieu d'utiliser Get-VM -Name
            $vm = $allClusterVMs | Where-Object { $_.Name -eq $vmName -and $_.PowerState -eq 'PoweredOn' }
            
            if ($vm -and -not (Test-VmBlacklisted -VM $vm `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames)) {
                $groupVMs += $vm
            }
        }

        if ($groupVMs.Count -le 1) { continue }

        # Déterminer l'hôte de référence en tenant compte du stockage
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
            Write-Log -Message " -Level Warning[AFFINITE] Impossible de trouver un hôte compatible pour le groupe [$($group -join ', ')]"
            continue 
        }

        $targetHost = $bestCandidate.Value.Host
        $targetHostName = $bestCandidate.Key

        Write-Log -Message "[AFFINITE] Groupe [$($group -join ', ')] - Hôte cible: $targetHostName ($($bestCandidate.Value.CompatibleVMCount)/$($groupVMs.Count) VMs compatibles)"

        foreach ($vm in $groupVMs) {
            if ($movesDone -ge $MaxMigrations) { 
                Write-Log -Message "[AFFINITE] Limite de migrations atteinte, suite au prochain cycle."
                return 
            }

            if ($vm.VMHost.Name -eq $targetHostName) { continue }

            if (Test-VmMigrating -VM $vm) {
                Write-Log -Message "[AFFINITE] VM '$($vm.Name)' déjà en cours de migration, ignorée."
                continue
            }

            if (-not (Test-StorageCompatible -VM $vm -TargetHost $targetHost)) {
                Write-Log -Message " -Level Warning[AFFINITE] VM '$($vm.Name)' incompatible stockage avec $targetHostName. Recherche d'un hôte alternatif..."
                
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
                    Write-Log -Message " -Level Warning[AFFINITE] Aucun hôte compatible trouvé pour '$($vm.Name)'. Migration ignorée."
                    continue
                }
            }

            $msg = "[AFFINITE] Regroupement VM '$($vm.Name)' : $($vm.VMHost.Name) -> $targetHostName"

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
        Write-Log -Message "[AFFINITE] Tous les groupes sont déjà correctement regroupés."
    }
}

# ---------- Gestion fichier anti-affinité ----------

function Read-AntiAffinityList {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Log -Message " -Level WarningFichier d'anti-affinité introuvable : $FilePath"
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
            Write-Log -Message "[ANTI-AFFINITE] Groupe chargé: [$($vmNames -join ', ')] ($($vmNames.Count) VMs)"
        } elseif ($vmNames.Count -eq 1) {
            Write-Log -Message " -Level Warning[ANTI-AFFINITE] Ligne ignorée (une seule VM): $($vmNames[0])"
        }
    }
    
    Write-Log -Message "Fichier d'anti-affinité chargé : $($groups.Count) groupe(s) détecté(s)"
    
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

    Write-Log -Message "[ANTI-AFFINITE] Vérification et séparation des VMs selon les règles d'anti-affinité..."

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $allHosts = Get-VMHost -Location $clusterObj | Where-Object { $_.ConnectionState -eq 'Connected' }
    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue

    if ($allHosts.Count -lt 2) {
        Write-Log -Message " -Level Warning[ANTI-AFFINITE] Moins de 2 hôtes disponibles, impossible d'appliquer les règles."
        return
    }

    $movesDone = 0
    $groupIndex = 0
    
    foreach ($groupObj in $AntiAffinityGroups) {
        $groupIndex++
        
        if ($movesDone -ge $MaxMigrations) { 
            Write-Log -Message "[ANTI-AFFINITE] Limite de migrations atteinte ($MaxMigrations), suite au prochain cycle."
            return 
        }

        $group = $groupObj.VMs
        
        Write-Log -Message "[ANTI-AFFINITE] ========================================="
        Write-Log -Message "[ANTI-AFFINITE] Traitement du groupe $groupIndex/$($AntiAffinityGroups.Count)"
        Write-Log -Message "[ANTI-AFFINITE] VMs attendues: [$($group -join ', ')]"

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
            Write-Log -Message "[ANTI-AFFINITE] ⚠ Groupe ignoré (moins de 2 VMs actives)"
            continue 
        }

        $vmsByHost = $groupVMs | Group-Object -Property { $_.VMHost.Name }
        $violations = $vmsByHost | Where-Object { $_.Count -gt 1 }

        if (-not $violations) {
            Write-Log -Message "[ANTI-AFFINITE] ✓ Groupe OK - Toutes les VMs sont sur des hôtes différents"
            continue
        }

        Write-Log -Message "[ANTI-AFFINITE] ✗✗✗ VIOLATION DETECTEE ! ✗✗✗"

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

                $msg = "[ANTI-AFFINITE] ➜ Migration VM '$($vm.Name)' : $($vm.VMHost.Name) → $($bestTarget.ESXHost.Name)"

                if ($DryRun) {
                    Write-Log -Message "[DRYRUN] $msg"
                } else {
                    Write-Host $msg
                    try {
                        Move-VM -VM $vm -Destination $bestTarget.ESXHost -RunAsync -ErrorAction Stop | Out-Null
                    } catch {
                        Write-Log -Message " -Level Warning[ANTI-AFFINITE] Erreur migration: $_"
                        continue
                    }
                }

                $movesDone++
            }
        }
    }

    if ($movesDone -eq 0) {
        Write-Log -Message "[ANTI-AFFINITE] ✓ Toutes les règles d'anti-affinité sont respectées"
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

# ---------- Gestion fichier VM-to-Host ----------

function Read-VmToHostList {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Log -Message " -Level WarningFichier VM-to-Host introuvable : $FilePath"
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
            # Détection: si contient 'esx', 'host', '-mgt' ou '.' c'est un hôte
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
        Write-Log -Message "[VM-TO-HOST] Règle chargée: VMs=[$($vms -join ', ')] → Hosts=[$($hosts -join ', ')]"
    }
    
    Write-Log -Message "Fichier VM-to-Host chargé : $($rules.Count) règle(s) détectée(s)"
    
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

    Write-Log -Message "[VM-TO-HOST] Vérification et application des règles VM-to-Host..."

    $clusterObj = Get-Cluster -Name $ClusterName -ErrorAction Stop
    $allClusterVMs = Get-VM -Location $clusterObj -ErrorAction SilentlyContinue
    $allClusterHosts = Get-VMHost -Location $clusterObj | Where-Object { $_.ConnectionState -eq 'Connected' }

    $movesDone = 0
    $ruleIndex = 0

    foreach ($ruleObj in $VmToHostRules) {
        $ruleIndex++
        
        if ($movesDone -ge $MaxMigrations) { 
            Write-Log -Message "[VM-TO-HOST] Limite de migrations atteinte ($MaxMigrations)"
            return 
        }

        $vms = $ruleObj.VMs
        $hosts = $ruleObj.Hosts

        Write-Log -Message "[VM-TO-HOST] Règle $ruleIndex : VMs=[$($vms -join ', ')] → Hosts=[$($hosts -join ', ')]"

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
        Write-Log -Message "[VM-TO-HOST] ✓ Toutes les règles VM-to-Host sont respectées"
    }
}

# ---------- Helpers charge hôte ----------

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

# ---------- Helpers blacklist VMs ----------

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

# ---------- Vérification migration VM en cours ----------

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

# ---------- Compatibilité stockage VM / hôte cible ----------

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
        if ($ds -like 'SHARED_STORAGE*') { continue }

        if ($targetDsNames -notcontains $ds) {
            return $false
        }
    }

    return $true
}

# ---------- Comptage vMotions en cours ----------

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

# ---------- Détection des hôtes à évacuer ----------

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

# ---------- Evacuation des hôtes détectés (VMs moyennes restantes) ----------

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

    # vMotions déjà en cours à l'entrée dans la fonction
    $nbEnCours = Get-CurrentVmotionCount -ClusterName $ClusterName
    $slotsDispoInitial = $MaxMigrationsEvacTotal - $nbEnCours
    if ($slotsDispoInitial -le 0) {
        Write-Log -Message "Aucun slot de vMotion disponible (déjà $nbEnCours en cours / $MaxMigrationsEvacTotal), on attend la prochaine boucle."
        return
    }

    $movesThisLoop = 0

    foreach ($mmESX in $HostsToEvacuate) {
        Write-Log -Message "========================================="
        Write-Log -Message "Evacuation de l'hôte (maintenance ou entrée en maintenance) : $($mmESX.Name)"
        Write-Log -Message "========================================="

        $targetHosts = Get-VMHost -Location $clusterObj |
                       Where-Object {
                           $_.ConnectionState -eq 'Connected' -and $_.Name -ne $mmESX.Name
                       }

        if (-not $targetHosts) {
            Write-Log -Message " -Level WarningAucun hôte cible disponible pour $($mmESX.Name)"
            continue
        }

        # Récupérer TOUTES les VMs candidates sur cet hôte
        $vmCandidates = $mmESX | Get-VM | Where-Object {
            $_.PowerState -eq 'PoweredOn' -and
            -not (Test-VmBlacklisted -VM $_ `
                    -NameBlacklistPatterns $NameBlacklistPatterns `
                    -TagBlacklistNames $TagBlacklistNames)
        }

        if (-not $vmCandidates) {
            Write-Log -Message "Aucune VM à évacuer sur $($mmESX.Name)"
            continue
        }

        Write-Log -Message "Nombre de VMs à évacuer : $($vmCandidates.Count)"

        # Calculer la médiane des VMs restantes
        $sizes = $vmCandidates | Select-Object -ExpandProperty MemoryGB | Sort-Object
        $count = $sizes.Count
        if ($count -eq 0) { continue }

        if ($count % 2 -eq 1) {
            $medianSize = $sizes[([int]($count/2))]
        }
        else {
            $medianSize = ($sizes[($count/2)-1] + $sizes[($count/2)]) / 2
        }

        Write-Log -Message "Taille médiane des VMs : $medianSize GB"

        # Prendre les VMs les plus proches de la médiane (limitées par les slots disponibles initiaux)
        $vmsToMove = $vmCandidates |
            Sort-Object @{Expression = { [math]::Abs($_.MemoryGB - $medianSize) }; Ascending = $true} |
            Select-Object -First $slotsDispoInitial

        Write-Log -Message "VMs sélectionnées pour migration (proches médiane) : $($vmsToMove.Count)"
        Write-Log -Message "-----------------------------------------"

        foreach ($vm in $vmsToMove) {
            # Vérifier si la VM est déjà en cours de migration
            if (Test-VmMigrating -VM $vm) {
                Write-Log -Message "VM '$($vm.Name)' déjà en cours de migration, ignorée."
                continue
            }

            # Recalcule dynamique des slots disponibles pour tenir compte des tâches réellement en cours
            $nbEnCours = Get-CurrentVmotionCount -ClusterName $ClusterName
            $slotsDispo = $MaxMigrationsEvacTotal - ($nbEnCours + $movesThisLoop)
            if ($slotsDispo -le 0) {
                Write-Log -Message "Slots de vMotion disponibles consommés pour cette boucle, on attend la prochaine itération."
                return
            }

            # Filtrer les hôtes cibles compatibles stockage
            $compatibleTargets = $targetHosts | Where-Object {
                Test-StorageCompatible -VM $vm -TargetHost $_
            }

            if (-not $compatibleTargets) {
                Write-Log -Message " -Level WarningAucun hôte cible compatible stockage pour la VM '$($vm.Name)' (Memory $($vm.MemoryGB)GB). vMotion ignoré et slot NON consommé."
                continue
            }

            # ===== MODE EVACUATION : Priorité absolue avec fallback =====
            # En mode maintenance, on respecte l'ordre suivant :
            # 1. VM-to-Host (si hôte autorisé != hôte en maintenance)
            # 2. Affinité (si hôte cible != hôte en maintenance)
            # 3. Anti-affinité (best effort)
            # 4. Meilleur hôte disponible (FALLBACK OBLIGATOIRE)

            $bestTarget = $null
            $migrationReason = "équilibrage"

            # Priorité 1: VM-to-Host (seulement si hôte cible valide et pas en maintenance)
            $vmToHostTarget = Get-VmToHostTargetHost -VMName $vm.Name -VmToHostRules $VmToHostRules -ClusterName $ClusterName -VM $vm
            if ($vmToHostTarget -and ($compatibleTargets.Name -contains $vmToHostTarget.Name)) {
                $bestTarget = Get-HostLoad -ESXHost $vmToHostTarget -IncludeNetwork:$IncludeNetwork
                $migrationReason = "VM-TO-HOST"
                Write-Log -Message "[EVACUATION][VM-TO-HOST] VM '$($vm.Name)' dirigée vers '$($vmToHostTarget.Name)' (règle respectée)"
            } elseif ($vmToHostTarget) {
                Write-Log -Message " -Level Warning[EVACUATION][VM-TO-HOST] VM '$($vm.Name)' devrait aller sur '$($vmToHostTarget.Name)' mais cet hôte est en maintenance ou incompatible. Règle VM-to-Host SUSPENDUE pour évacuation."
            }

            # Priorité 2: Affinité (seulement si hôte cible valide et pas en maintenance)
            if (-not $bestTarget) {
                $affinityHost = Get-AffinityTargetHost -VMName $vm.Name -AffinityGroups $AffinityGroups -ClusterName $ClusterName -VM $vm
                if ($affinityHost -and ($compatibleTargets.Name -contains $affinityHost.Name)) {
                    $bestTarget = Get-HostLoad -ESXHost $affinityHost -IncludeNetwork:$IncludeNetwork
                    $migrationReason = "AFFINITE"
                    Write-Log -Message "[EVACUATION][AFFINITE] VM '$($vm.Name)' dirigée vers '$($affinityHost.Name)' (groupe respecté)"
                } elseif ($affinityHost) {
                    Write-Log -Message " -Level Warning[EVACUATION][AFFINITE] VM '$($vm.Name)' devrait aller sur '$($affinityHost.Name)' mais cet hôte est en maintenance ou incompatible. Règle d'affinité SUSPENDUE pour évacuation."
                }
            }

            # Priorité 3: Anti-affinité (best effort)
            if (-not $bestTarget) {
                $antiAffinityTargets = Get-AntiAffinityCompatibleHosts -VM $vm -TargetHosts $compatibleTargets -AntiAffinityGroups $AntiAffinityGroups -ClusterName $ClusterName
                
                if ($antiAffinityTargets -and $antiAffinityTargets.Count -gt 0) {
                    $bestTarget = Get-BestTargetHost -ESXHosts $antiAffinityTargets -IncludeNetwork:$IncludeNetwork
                    $migrationReason = "ANTI-AFFINITE"
                    Write-Log -Message "[EVACUATION][ANTI-AFFINITE] VM '$($vm.Name)' vers hôte respectant anti-affinité"
                } else {
                    Write-Log -Message "[EVACUATION][ANTI-AFFINITE] Aucun hôte disponible respectant les contraintes d'anti-affinité pour '$($vm.Name)'. Règle SUSPENDUE pour évacuation."
                }
            }

            # FALLBACK OBLIGATOIRE : Si aucune règle n'a donné de cible valide
            if (-not $bestTarget) {
                $bestTarget = Get-BestTargetHost -ESXHosts $compatibleTargets -IncludeNetwork:$IncludeNetwork
                $migrationReason = "EVACUATION-FORCEE"
                Write-Log -Message "[EVACUATION][FORCE] VM '$($vm.Name)' vers meilleur hôte disponible (règles d'affinité/VM-to-Host suspendues)"
            }

            # Vérification finale : Si toujours pas de cible (ne devrait jamais arriver)
            if (-not $bestTarget -or -not $bestTarget.ESXHost) {
                Write-Log -Message " -Level Warning[EVACUATION][ERREUR CRITIQUE] Impossible de trouver un hôte cible pour '$($vm.Name)'. Migration annulée."
                Write-Log -Message " -Level Warning[EVACUATION][DEBUG] compatibleTargets Count: $($compatibleTargets.Count)"
                continue
            }

            $msg = "[EVACUATION][$migrationReason] VM '$($vm.Name)' (Mem: $($vm.MemoryGB)GB) : $($vm.VMHost.Name) → $($bestTarget.ESXHost.Name) (charge: $($bestTarget.LoadScore))"

            if ($DryRun) {
                Write-Log -Message "[DRYRUN] $msg"
            } else {
                Write-Host $msg
                try {
                    Move-VM -VM $vm -Destination $bestTarget.ESXHost -RunAsync -ErrorAction Stop | Out-Null
                    Write-Log -Message "[EVACUATION] ✓✓✓ Migration lancée avec succès ✓✓✓"
                } catch {
                    Write-Log -Message " -Level Warning[EVACUATION] ✗✗✗ Erreur lors de la migration de '$($vm.Name)': $_"
                    continue
                }
            }

            $movesThisLoop++
            Write-Log -Message "-----------------------------------------"
        }
    }

    if ($movesThisLoop -gt 0) {
        Write-Log -Message "========================================="
        Write-Log -Message "EVACUATION: $movesThisLoop migration(s) lancée(s) pour évacuation"
        Write-Log -Message "========================================="
    }
}

# ---------- Rééquilibrage cluster ----------

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
        Write-Log -Message "Pas de déséquilibre significatif détecté."
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

            # Vérifier VM-to-Host
            $vmToHostTarget = Get-VmToHostTargetHost -VMName $candidate.Name -VmToHostRules $VmToHostRules -ClusterName $ClusterName -VM $candidate
            if ($vmToHostTarget -and $vmToHostTarget.Name -ne $dst.ESXHost.Name) {
                Write-Log -Message "[VM-TO-HOST] VM '$($candidate.Name)' doit aller sur '$($vmToHostTarget.Name)'. Rééquilibrage annulé."
                continue
            }

            # Vérifier affinité
            $affinityHost = Get-AffinityTargetHost -VMName $candidate.Name -AffinityGroups $AffinityGroups -ClusterName $ClusterName -VM $candidate
            if ($affinityHost -and $affinityHost.Name -ne $dst.ESXHost.Name) {
                Write-Log -Message "[AFFINITE] VM '$($candidate.Name)' doit rester avec son groupe. Rééquilibrage annulé."
                continue
            }

            # Vérifier anti-affinité
            $compatibleHosts = Get-AntiAffinityCompatibleHosts -VM $candidate -TargetHosts @($dst.ESXHost) -AntiAffinityGroups $AntiAffinityGroups -ClusterName $ClusterName
            if (-not $compatibleHosts) {
                Write-Log -Message "[ANTI-AFFINITE] VM '$($candidate.Name)' ne peut pas aller sur '$($dst.ESXHost.Name)'. Rééquilibrage annulé."
                continue
            }

            $msg = "Rééquilibrage $($candidate.Name) : $($src.ESXHost.Name) -> $($dst.ESXHost.Name)"

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

# ---------- Boucle principale ----------

while ($true) {
    try {
        Write-Log -Message "---- Itération $(Get-Date) : cluster $clusterNameLocal ----"

        # Recharger les fichiers toutes les 5 minutes
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

        # Application des règles à chaque cycle
        
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
                    Write-Log -Message "*** Passage en mode évacuation (boucle courte ${EvacLoopSleepSeconds}s) ***"
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
                    Write-Log -Message "*** EVACUATION TERMINÉE ! Retour au mode normal (${NormalLoopSleepSeconds}s). ***"
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
                Write-Log -Message "*** Plus d'hôtes en maintenance détectés. Retour au mode normal. ***"
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
        Write-Log -Message " -Level WarningErreur dans la boucle pseudo-DRS (cluster $clusterNameLocal) : $_"
        $sleep = $NormalLoopSleepSeconds
    }

    Write-Log -Message "Pause de $sleep secondes..."
    Start-Sleep -Seconds $sleep
}
