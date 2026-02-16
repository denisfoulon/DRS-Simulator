# DRS simulator - Custom DRS for VMware vSphere

## Overview

DRS simulator is a PowerShell-based custom DRS (Distributed Resource Scheduler) implementation for VMware vSphere environments.
It provides advanced VM placement and load-balancing capabilities with support for affinity rules, anti-affinity constraints, and VM-to-host pinning.

## Key Features

- **Affinity Rules**: Keep related VMs on the same host
- **Anti-Affinity Rules**: Ensure VMs run on separate hosts for improved availability
- **VM-to-Host Rules**: Pin specific VMs to designated hosts
- **Host Evacuation**: Automatic VM migration when a host enters maintenance mode
- **Load Balancing**: Distribute VMs across hosts based on CPU, memory, and network usage
- **Centralized Logging**: Syslog integration for monitoring and auditing
- **Blacklist Support**: Exclude VMs from automated migration logic
- **Dry-Run Mode**: Test changes without performing actual VM migrations

## Version History
### v1.35 (2026-02-16)

#### Cluster Data Caching
- Cached cluster VMs and hosts (refresh every 30s)
- Eliminates repeated `Get-VM` / `Get-VMHost` calls
- ~50–60% reduction in vCenter API usage

#### Host Load Cache (TTL)
- Host CPU, memory and network load cached for 30s
- Avoids redundant `Get-Stat` calls
- `-BypassCache` option for real-time data

#### Evacuation Queue System
- Persistent evacuation queue across loops
- Real-time progress tracking (evacuated vs remaining VMs)
- Dedicated handling for powered-off VMs
- vMotion slot protection via live vMotion count checks

#### Intelligent Evacuation Targeting
- Priority-based host selection (rules → affinity → anti-affinity → best host)
- Migration reason logged for full transparency
- Storage compatibility validated before migration

#### Stability & Memory Optimizations
- GC interval reduced (12h → 1h)
- vCenter recycle interval reduced (24h → 2h)
- Improved reconnect and error handling


### v1.34 (2026-01-16)
#### **Rules Check Throttling System** (`$RulesCheckEveryXLoops`)
- **Problem solved**: Continuous file reading and rule parsing every 60 seconds created unnecessary CPU/IO overhead
- **New behavior**: Rules are now checked every **X loops** instead of every loop (default: 15 loops = 15 minutes)
- **Smart file monitoring**: Rules are only reloaded if file `LastWriteTime` changed since last check
- **Memory optimization**: Rules cached in `$script:affinityGroups`, `$script:antiAffinityGroups`, `$script:vmToHostRules` between checks
- **Performance gain**: ~93% reduction in file I/O operations (1 check per 15 minutes vs 1 per minute)
- **Configuration**: Set `$RulesCheckEveryXLoops = 1` to restore original behavior (check every loop)

### v1.33 (2026-01-16)
- Migrations enhanced for evacuation

### v1.32 (2025-12-16)
- Automatic garbage collection every 12h
- vCenter recycling every 24h with automatic reconnection
- Proper UDP disposal (Close + Dispose) in Send-SyslogMessage
- Automatic Get-Stat cleanup after each use
- Memory monitoring every hour with alerts
- Automatic statistics cache cleanup
- Automatic alerts if memory exceeds 2 GB

### v1.31 (2025-12-02)

- Added Syslog support for centralized logging
- All logs now sent via UDP to the remote Syslog server
- Console output preserved in parallel
- Syslog parameters (server, port, facility) are now fully configurable

## Requirements

- PowerShell 5.1 or later
- VMware PowerCLI module
- vCenter Server 6.5 or later
- Appropriate vCenter permissions (VM migration, host management)


## How It Works

1. **Initialization**: Connects to vCenter and loads rule files
2. **Continuous Loop**:
   - Detects hosts entering maintenance mode
   - Applies affinity rules
   - Enforces anti-affinity rules
   - Applies VM-to-host pinning
   - Runs load balancing if no evacuation is in progress
3. **Logging**: All actions are logged to the console and optionally to a Syslog server

### Load Calculation

Load score = (0.4 × CPU%) + (0.4 × Memory%) + (0.2 × normalized Network%)

The script migrates VMs from overloaded hosts to underloaded hosts while respecting all placement rules.

## Advanced Features

### Blacklisting

Exclude VMs from automated management:

**By name pattern:**
<pre>-NameBlacklistPatterns @("vCLS", "NOMOVE")</pre>

### Storage Compatibility

Before migration, the script automatically checks datastore accessibility to avoid failed vMotions.

### Priority System

During host evacuation, rules are applied in this order:

1. VM-to-Host rules (if possible)
2. Affinity rules
3. Anti-affinity rules (best effort)
4. Best available host (mandatory fallback)

## Monitoring

### Syslog Integration

Configure your Syslog server to receive UDP traffic on port 514 (or a custom port).

Logged events include:

- Migration operations
- Detected rule violations
- Host evacuation steps
- Load balancing actions
- Errors and warnings

### Log Levels

- **Info (6)**: Normal operational messages
- **Warning (4)**: Potential issues, temporary rule suspensions
- **Error (3)**: Failed operations
- **Debug (7)**: Detailed troubleshooting data

## Installation

1. Clone this repository:
<pre>git clone https://github.com/denisfoulon/DRS-Simulator.git</pre>

2. Install VMware PowerCLI (if not already installed):
<pre>Install-Module -Name VMware.PowerCLI -Scope CurrentUser</pre>

3. Create a credential file:
<pre>Get-Credential | Export-Clixml -Path "C:\MyawesomeProject\vcenter_credentials.xml"</pre>


## Configuration

### Basic Parameters
<pre>$VCenter = "vcenter.example.com"
$ClusterName = "production_cluster"</pre>

### Timing
<pre>$NormalLoopSleepSeconds = 60
$EvacLoopSleepSeconds = 20</pre>

### Migration limits
<pre>$MaxMigrationsBalancePerLoop = 3
$MaxMigrationsEvacTotal = 8</pre>

### Syslog
<pre>$SyslogServer = "syslog.example.com"
$SyslogPort = 514
$EnableSyslog = $true</pre>

## Usage

### Standard Mode
<pre>.\DRS_simulator.ps1 -VCenter "vcenter.example.com" -ClusterName "production_cluster"</pre>


### Dry-Run Mode (Test without migrations)
<pre>.\DRS_simulator.ps1 -DryRun</pre>


### With Network Metrics
<pre>.\DRS_simulator.ps1 -IncludeNetwork</pre>


### Disable Syslog
<pre>.\DRS_simulator.ps1 -EnableSyslog:$false</pre>


### Rule Files

Create three text files for your placement rules:

#### Affinity Rules (affinity_rules.txt)
<pre>vm-web-01 vm-web-02 vm-web-03
vm-db-01 vm-db-02</pre>

#### Anti-Affinity Rules (`anti_affinity_rules.txt`)
<pre>vm-license-server esxi-host-01.example.com
vm-backup-proxy esxi-host-04.example.com</pre>

#### VM-to-Host Rules (`vm_to_host_rules.txt`)
<pre>vm-license-server esxi-host-01.example.com
vm-backup-proxy esxi-host-04.example.com</pre>



## How It Works

1. **Initialization**: Connects to vCenter and loads rule files
2. **Continuous Loop**:
   - Detects hosts entering maintenance mode
   - Applies affinity rules
   - Enforces anti-affinity rules
   - Applies VM-to-host pinning
   - Runs load balancing if no evacuation is in progress
3. **Logging**: All actions are logged to the console and optionally to a Syslog server

### Load Calculation
Load score = (0.4 × CPU%) + (0.4 × Memory%) + (0.2 × normalized Network%)


The script migrates VMs from overloaded hosts to underloaded hosts while respecting all placement rules.

## Advanced Features

### Blacklisting

Exclude VMs from automated management:

**By name pattern:**
<pre>-NameBlacklistPatterns @("vCLS", "NOMOVE")</pre>

**By vCenter tag:**
<pre>-TagBlacklistNames @("No-DRS")</pre>

### Storage Compatibility

Before migration, the script automatically checks datastore accessibility to avoid failed vMotions.

### Priority System

During host evacuation, rules are applied in this order:

1. VM-to-Host rules (if possible)
2. Affinity rules
3. Anti-affinity rules (best effort)
4. Best available host (mandatory fallback)

## Troubleshooting

### Common Issues

#### Cannot connect to vCenter

- Verify the credential file
- Check network connectivity
- Ensure PowerCLI is installed

#### No migrations occurring

- Check if VMs are blacklisted
- Ensure enough hosts are available
- Verify datastore compatibility
- Check migration limits

#### Rules not being applied correctly

- Check rule file syntax
- Ensure relevant VMs exist and are powered on
- Look for conflicting rules
- Confirm datastore accessibility

## Contributing

Contributions are welcome!

To contribute:

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Test in a lab environment
5. Submit a pull request

## License

This project is licensed under the MIT License see the LICENSE file for details.

## Disclaimer

⚠️ **This script is provided AS-IS without warranty of any kind.**

Always test in a non-production environment.

The author assumes no liability for any damage resulting from its use.

## Support

For issues, questions, or suggestions, please open an issue on GitHub.
