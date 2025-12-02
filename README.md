"""# DRS simulator - Custom DRS for VMware vSphere

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

## Installation

Clone this repository:



### Rule Files

Create three text files for your placement rules:

#### Affinity Rules (affinity_rules.txt)


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

By name pattern:


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

This project is licensed under the MIT License — see the LICENSE file for details.

## Disclaimer

This script is provided AS-IS without warranty of any kind.

Always test in a non-production environment.

The author assumes no liability for any damage resulting from its use.

## Support

For issues, questions, or suggestions, please open an issue on GitHub.
"""

