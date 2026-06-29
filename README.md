# DRS simulator - Custom DRS for VMware vSphere

## Overview

DRS simulator is a PowerShell-based custom DRS (Distributed Resource Scheduler) implementation for VMware vSphere environments.
It provides advanced VM placement and load-balancing capabilities with support for affinity rules, anti-affinity constraints, and VM-to-host pinning.

## Key Features

- **Affinity Rules**: Keep related VMs on the same host
- **Anti-Affinity Rules**: Ensure VMs run on separate hosts for improved availability
- **VM-to-Host Rules**: Pin specific VMs to designated hosts
- **Host Evacuation**: Automatic VM migration when a host enters maintenance mode
- **Load Balancing**: Distribute VMs across hosts based on dynamic CPU, memory, and network metrics (weighted towards memory)
- **Centralized Logging**: Syslog integration (RFC 3164) for monitoring and auditing
- **Blacklist Support**: Exclude VMs from automated migration logic by name pattern or vCenter tags
- **Dry-Run Mode**: Test changes without performing actual VM migrations

## Version History

### v1.39 (2026-06-29)
- **Rules Check Throttling Adjustment**: Increased the rules check throttling interval (`$RulesCheckEveryXLoops`) to 23 loops by default to further minimize file I/O and CPU overhead in stable environments.
- **Project Baseline**: Main loop optimization and script header alignment for the 2026 release.

### v1.38
- **Multi-Core CPU Calculation Bug Fix**: Resolved a critical calculation bug in `Get-HostLoad` where `OverallCpuUsage` (total MHz across all cores) was divided only by `CpuMhz`, leading to incorrect percentages of 300%–700% on multi-core hosts. The formula now correctly divides by `(CpuMhz * NumCpuCores)`, fixing silent failures in threshold comparisons and delta balancing.

### v1.37
- **Delta-Based Balancing Triggers**: Shifted cluster balancing logic from hard thresholds to a dynamic delta-based mechanism (`$DeltaTriggerCpu` and `$DeltaTriggerMem` set to 15). A host is now flagged as a migration source or target if it deviates from the cluster average by more than this value, preventing aggressive or unnecessary vMotions.
- **Memory-Weighted Load Score**: Updated the load score formula to address memory as the primary bottleneck in the cluster. The calculation now heavily weights memory available on targets.

### v1.35 (2026-02-16)
- **Cluster Data Caching**: Cached cluster VMs and hosts (refresh every 30s) to reduce vCenter API usage by ~50–60%.
- **Host Load Cache (TTL)**: Cached CPU, memory, and network load for 30s with a `-BypassCache` option for real-time data.
- **Evacuation Queue System**: Persistent evacuation queue across loops with tracking of remaining VMs, dedicated handling for powered-off VMs, and live vMotion count safety checks.
- **Intelligent Evacuation Targeting**: Priority-based host selection (rules → affinity → anti-affinity → best host) with mandatory storage compatibility validation.
- **Stability & Memory Optimizations**: Reduced GC interval (1h) and vCenter recycle interval (2h) with automated memory usage monitoring and alerts if exceeding 2 GB.

### v1.34 (2026-01-16)
- **Rules Check Throttling System** (`$RulesCheckEveryXLoops`): Cached parsed rules in memory and implemented smart file monitoring via `LastWriteTime` to reduce file I/O operations by ~93%.

### v1.33 (2026-01-16)
- Migrations enhanced for host evacuation.

### v1.32 (2025-12-16)
- Automated garbage collection, vCenter session recycling with auto-reconnection, proper UDP socket disposal in Syslog functions, and statistics cache cleanup.

### v1.31 (2025-12-02)
- Added RFC 3164 Syslog support via UDP for centralized logging while preserving console output in parallel.

## Requirements

- PowerShell 5.1 or later
- VMware PowerCLI module
- vCenter Server 6.5 or later
- Appropriate vCenter permissions (VM migration, host management)

## How It Works

1. **Initialization**: Connects to vCenter using secured credentials and loads initial placement rules.
2. **Continuous Loop**:
   - Monitors and tracks hosts entering maintenance mode.
   - Enforces VM-to-Host pinning rules.
   - Enforces Affinity groups.
   - Resolves Anti-Affinity rule violations.
   - Runs delta-based cluster load balancing if no evacuation tasks are active.
3. **Logging**: Dispatches structured logs to the local console and optionally to a centralized Syslog server.

### Load Calculation

To accurately balance the cluster, a **Load Score** is calculated for each host using a memory-centric distribution formula:

$$\text{Load Score} = (0.25 \times \text{CPU}\%) + (0.65 \times \text{Memory}\%) + (0.10 \times \text{Normalized Network}\%)$$

*Note: Since memory is the primary resource bottleneck in high-density virtualized environments, a heavier weight is assigned to it to guarantee optimal target selection.*

## Advanced Features

### Blacklisting

Exclude specific virtual machines from being moved or managed by the script:

**By name pattern:**
<pre>-NameBlacklistPatterns @("vCLS", "NOMOVE")</pre>

**By vCenter tag:**
<pre>-TagBlacklistNames @("No-DRS")</pre>

### Storage Compatibility

Before executing any vMotion command, the script validates shared datastore accessibility on the destination host to proactively mitigate migration failures.

### Priority System

During host evacuations, candidate target hosts are chosen strictly adhering to the following hierarchy:

1. **VM-to-Host rules** (Hard pinning constraint)
2. **Affinity rules** (Grouping constraints)
3. **Anti-Affinity rules** (Separation constraints on a best-effort basis)
4. **Best available host** (Fallback based on the lowest Load Score)

## Monitoring & Logging

### Syslog Integration

Configure your target logging system or SIEM to receive UDP traffic on port 514 (or your designated custom port). Logged structural data includes:
- Triggered migration details (vMotions)
- Active rule violations
- Maintenance and host evacuation status steps
- Resource rebalancing alerts and warnings

### Log Levels

- **Error (3)**: Critical script or migration failures.
- **Warning (4)**: Potential resource issues or temporary rules suspensions.
- **Info (6)**: Standard operational tracking loop logs.
- **Debug (7)**: Granular troubleshooting performance metrics.

## Installation

1. Clone this repository:
<pre>git clone https://github.com/denisfoulon/DRS-Simulator.git</pre>

2. Install VMware PowerCLI (if missing):
<pre>Install-Module -Name VMware.PowerCLI -Scope CurrentUser</pre>

3. Create your secure credential XML file:
<pre>Get-Credential | Export-Clixml -Path "C:\Scripts\DRS\vcenter_credentials.xml"</pre>

## Configuration

### Basic Parameters
<pre>$VCenter = "vcenter.example.com"
$ClusterName = "production_cluster"</pre>

### Timing & Throttling
<pre>$NormalLoopSleepSeconds = 60
$EvacLoopSleepSeconds = 20
$RulesCheckEveryXLoops = 23</pre>

### Migration Limits
<pre>$MaxMigrationsBalancePerLoop = 3
$MaxMigrationsEvacTotal = 8</pre>

### Balancing Triggers (Delta-based)
<pre>$DeltaTriggerCpu = 15
$DeltaTriggerMem = 15</pre>

### Syslog Setup
<pre>$SyslogServer = "syslog.example.com"
$SyslogPort = 514
$EnableSyslog = $true</pre>

## Usage

### Standard Production Mode
<pre>.\DRS_simulator.ps1 -VCenter "vcenter.example.com" -ClusterName "production_cluster"</pre>

### Dry-Run Mode (Simulation without movements)
<pre>.\DRS_simulator.ps1 -DryRun</pre>

### Include Network Metrics in Calculations
<pre>.\DRS_simulator.ps1 -IncludeNetwork</pre>

### Disable Syslog Output
<pre>.\DRS_simulator.ps1 -EnableSyslog:$false</pre>

### Rule Files Syntax

The script expects three flat configuration text files:

#### Affinity Rules (`liste_affinite.txt`)
*VMs listed on the same line will be grouped onto the same host.*
<pre>vm-web-01 vm-web-02 vm-web-03
vm-db-01 vm-db-02</pre>

#### Anti-Affinity Rules (`liste_antiaffinite.txt`)
*VMs listed on the same line will be forced onto distinct hosts.*
<pre>vm-dc-01 vm-dc-02
vm-k8s-node01 vm-k8s-node02</pre>

#### VM-to-Host Rules (`list_vm_to_host.txt`)
*Format: `VM_Name Host_Name` to pin a VM to a given ESXi server.*
<pre>vm-license-server esxi-host-01.example.com
vm-backup-proxy esxi-host-04.example.com</pre>

## Troubleshooting

### Common Issues

#### Cannot connect to vCenter
- Verify the generated CLI-XML credential path and decryption permissions.
- Validate port 443 connectivity to the vCenter FQDN.

#### No migrations occurring
- Ensure target VMs are not matching `$NameBlacklistPatterns` or tagged with `$TagBlacklistNames`.
- Confirm that target destination hosts have shared storage compatibility with the source datastores.
- Verify that cluster hosts do not violate current delta trigger thresholds.

#### Rules not being applied correctly
- Ensure rule file paths in the script parameters block match your local infrastructure layout.
- Review text file syntax for hidden characters or incorrect spacing.

## Contributing

Contributions are welcome! Please fork the repository, make your modifications in a separate feature branch, test your changes thoroughly within a non-production lab environment, and submit a detailed Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

⚠️ **This script is provided AS-IS without warranty of any kind.** Always thoroughly test script execution in a staging or non-production environment first. The author assumes no liability for any automated operational damage resulting from its use.

## Support

For issues, questions, or feature suggestions, please open a formal issue tracking ticket directly on the GitHub project repository.
