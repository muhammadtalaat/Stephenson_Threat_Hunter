# Stephenson_Threat_Hunter

## Description

This PowerShell script is designed to facilitate threat hunting by scanning local and remote systems for various indicators of compromise (IOCs) such as registry keys, event log entries, files, and hashes. The script can be executed either locally or remotely, providing flexibility in how threat hunting activities are conducted.

## Key Features

- **Local and Remote Scanning**: Choose between local or remote scanning for flexibility in different network environments.
- **Registry Scans**: Search for specific registry keys and values that may indicate malicious activity.
- **Event Viewer Scans**: Analyze event logs for suspicious entries.
- **File Scans**: Search for specific files by name or hash across entire partitions or specific directories.
- **Hash Scans**: Validate files against a list of known malicious hashes using MD5, SHA1, or SHA256.
- **CSV Reporting**: Export scan results to CSV files for easy analysis and record-keeping.

## Prerequisites

### For Remote Scan

1. **Firewall Rules**:
   - Allow inbound port TCP-135 (in Windows firewall, endpoint firewall, and network firewalls).
   - Permit outbound random ports ranging from 1022-5000 and 49152-65535.
   - Ensure inbound port TCP-445 for SMB (RPC dependency) is open.

2. **High-Privilege User**:
   - Use a user account with high privileges for remote registry access and event log reading.

### For Local Scan

1. **High-Privilege User**:
   - Use a user account with high privileges for remote registry access and event log reading.

## Installation

### Ensure PowerShell Execution Policy

Open PowerShell with administrative privileges and set the execution policy to allow running the script.

```sh
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
# Usage

## Run the Script

### Open PowerShell:

1. Navigate to the directory where the script is located.
2. Execute the script:

    ```sh
    .\Stephenson.ps1
    ```

### Follow Prompts

1. Choose between local or remote scanning.
2. Select the type of scan (Registry, Event Viewer, File, or Hash).
3. Provide necessary inputs such as registry paths, log names, file paths, and hash file paths based on the selected scan type.
4. Review and export the scan results, which will be saved in CSV format.

## Screenshots

### Initial Prompt

### Local Registry Scan

### Remote Event Viewer Scan

## Mini Description

The Stephenson PowerShell script provides a comprehensive toolkit for threat hunters to scan and identify potential security threats within their network. Whether it's searching for malicious registry keys, identifying suspicious event log entries, locating specific files, or validating file hashes against known threats, this script streamlines the threat detection process with automated, customizable scans and detailed CSV reports.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

