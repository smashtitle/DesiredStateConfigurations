# DesiredStateConfigurations
A collection of Desired State Configurations (DSC v1.1) for use in detection labs and attack ranges.

## BaselineConfiguration.ps1
This PowerShell Desired State Configuration (DSC) optimises Windows 11 for detection lab use by removing non-essential components and enabling comprehensive logging. The intent is to maximally reduce resource consumption while enabling detection-relevant telemetry.

### Usage
If your use case is like mine, you'll need to disable Real-Time Protection and Tamper Protection, then render Defender inert using [DefendNot](https://github.com/es3n1n/defendnot). Then run `Bootstrap.ps1`, followed by `BaselineConfiguration.ps1`. Note that the latter script grabs remote resources, like a modified Sysmon config from [my repo](https://github.com/smashtitle/TelemetryForge/blob/main/sysmonconfig-research.xml), a Sysmon installer from the Sysinternals site, and [RPCFirewall](ttps://github.com/zeronetworks/rpcfirewall) from GitHub.

The script creates a working directory at `C:\Tools\` for downloaded components and logs execution output to `C:\Tools\dsc-execution.log`. Unfortunately, the output is quite long at ~5000 lines, but you can search for errors if you encounter any unusual issues. At this time, there are no errors, but I can't guarantee this will remain the case (downloads may become unavailable, for instance). I tested against the Azure Windows 11 SKU `win11-25h2-pron` version `26200.6584.250915`. `-pron` denotes Windows 11 Pro N, which is designed for the European market and identical to Windows 11 Pro, but excludes media-related technologies like Windows Media Player, Movies & TV, Groove Music, Skype, and Voice Recorder.

> [!WARNING]
> This script embeds [default credentials](https://github.com/smashtitle/DesiredStateConfigurations/blob/9cf4776b7423ed42d7dfb030a1e94d1d3bd072cf/BaselineConfiguration.ps1#L573-L574) at the end. 

### Windows Features
The configuration disables the following Windows features through registry modifications and service configuration:
- Windows Update and related services
- Windows Search and Cortana
- SmartScreen filtering and threat protection
- Windows phone-home telemetry
- OneDrive file sync
- Xbox gaming features and overlay services
- Maps auto-update and notifications
- Mobile Device Management (MDM) enrollment
- Delivery Optimization peer-to-peer services
- Microsoft Edge startup boost and background mode
- Cross-device synchronization services (Connected Devices Platform, Sync Host, Contact Data, User Data Storage, User Data Access)
- Windows Push Notifications

### Services
The script disables about 30 services including:
- Windows Update components
- Print Spooler
- Windows Audio
- Geolocation and Sensor services
- Volume Shadow Copy
- Plug and Play
- Various Hyper-V integration services
- Smart Card enumeration
- SSDP Discovery and Network Connected Devices Auto-Setup

### Scheduled Tasks
The configuration disables about 20 scheduled tasks related to:
- App compatibility telemetry collection
- Customer Experience Improvement Program (CEIP)
- Disk diagnostics
- Xbox Live synchronization
- Windows Maps updates
- Network location awareness
- Enterprise and MDM policy refresh tasks
- .NET Framework assembly optimization
- OneDrive and Microsoft Edge maintenance tasks

### Applications
The script removes almost 50 provisioned and installed AppX packages including:
- Microsoft Store and Store Purchase App
- OneDrive
- Microsoft Edge
- Xbox applications and services
- Built-in Windows apps (Calculator, Camera, Alarms, Photos, Sound Recorder, Notepad, Terminal)
- Office Hub and Outlook
- Feedback Hub and Get Help
- Weather, News, and Widget Platform
- Media codec extensions (HEVC, HEIF, RAW, VP9, WebP, AV1, MPEG2)
- Teams, Clipchamp, and Quick Assist

### Event Log Configuration
The configuration enables/configures these logs:
```
Windows PowerShell
PowerShellCore/Operational
Microsoft-Windows-PowerShell/Operational
Microsoft-Windows-WMI-Activity/Operational
Microsoft-Windows-TaskScheduler/Operational
Microsoft-Windows-SMBServer/Operational
Microsoft-Windows-SMBServer/Security
Microsoft-Windows-SMBClient/Security
Microsoft-Windows-SMBClient/Connectivity
Microsoft-Windows-DNS-Client/Operational
Microsoft-Windows-LSA/Operational
Microsoft-Windows-CAPI2/Operational
Microsoft-Windows-NTLM/Operational
Microsoft-Windows-CodeIntegrity/Operational
Microsoft-Windows-Bits-Client/Operational
Microsoft-Windows-DriverFrameworks-UserMode/Operational
Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
Microsoft-Windows-Security-Mitigations/KernelMode
Microsoft-Windows-Security-Mitigations/UserMode
Microsoft-Windows-WinRM/Operational
Microsoft-Windows-Shell-Core/Operational
Microsoft-Windows-VHDMP-Operational
Microsoft-Windows-Winlogon/Operational
Microsoft-Windows-UniversalTelemetryClient/Operational
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
Microsoft-Windows-Diagnosis-Scripted/Operational
Microsoft-Windows-AppModel-Runtime/Admin
Microsoft-Windows-Kernel-EventTracing/Admin
Microsoft-Windows-Sysmon/Operational
```

### Audit Policies
The script configures audit policies across multiple categories. This is based on Yamato Security's [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/main/YamatoSecurityConfigureWinEventLogs.bat) work.

**Account Logon:** Credential Validation, Kerberos Authentication Service, and Kerberos Service Ticket Operations (Success and Failure)

**Account Management:** Computer Account Management, Other Account Management Events, Security Group Management, and User Account Management (Success and Failure where applicable)

**Detailed Tracking:** Plug and Play Events, Process Creation, Process Termination, RPC Events, and Token Right Adjusted Events (Success and Failure)

**Windows Filtering Platform** Connection logging

### Enhanced PowerShell, Firewall Logging, Process Auditing
The configuration enables:
- PowerShell Module logging for all modules
- PowerShell Script Block logging
- PowerShell Transcripts
- Windows Firewall connection logging
- Process command line auditing (includes full command line in Event ID 4688)

### Sysmon
The script downloads and installs Sysmon64 with a configuration focused on detection research, based on an updated version of Olaf Hartong's `sysmonconfig-research`. You can find my configuration [here](https://github.com/smashtitle/TelemetryForge/blob/main/sysmonconfig-research.xml), and a link to Olaf's Sysmon configs repo in the references section.

### RPC Firewall
The configuration deploys Zero Networks RPC Firewall (version 2.2.5) to monitor Remote Procedure Call traffic. You can find RPC Filter events in Event ID: 5712 in `Security`, and Firewall logs in `Application/RPCFW`. Additionally, here's a link to some related [Sigma rules](https://github.com/SigmaHQ/sigma/tree/master/rules/application/rpc_firewall). 

I also recommend Zero Networks LDAP Firewall, although it isn't included in this DSC.

### Implementation Notes
This configuration applies settings at the system level through the Local Configuration Manager with the following parameters:

`Configuration Mode: ApplyOnly`
This means the configuration will only be applied once. There are two other modes: `ApplyAndMonitor` will apply then audit the configuration at regular intervals (default every 15m) and write to the `Microsoft-Windows-DSC` event provider. `ApplyAndAutoCorrect` will apply, audit at regular intervals, and attempt to re-apply if there is any configuration drift.

`Reboot Node If Needed: True`
Windows will reboot automatically if the configuration requires it. This will happen once.

`Action After Reboot: ContinueConfiguration`
Configuration will resume after reboot.

### References
Many thanks to: 

[Yamato Security](https://github.com/Yamato-Security) for their extensive documentation and tooling for auditing Windows event logs.

[Zero Networks](https://github.com/zeronetworks/rpcfirewall) for their excellent RPC and LDAP Firewall tool.

[Olaf Hartong](https://github.com/olafhartong/sysmon-modular) for their Sysmon configurations.

[Raphire](https://github.com/Raphire/Win11Debloat) for their debloating PowerShell script that provided insight into which components are safe to remove.
