# BaselineConfiguration.ps1
# Common baseline configuration for all workstations and servers
# Apply this first before machine-specific configurations

Configuration BaselineConfiguration
{
  param(
    [Parameter(Mandatory)]
    [string]$NodeName,
    
    [Parameter(Mandatory)]
    [pscredential]$LocalAdminCredential
  )

  Import-DscResource -ModuleName xPSDesiredStateConfiguration
  Import-DscResource -ModuleName PSDscResources
  Import-DscResource -ModuleName ComputerManagementDsc
  Import-DscResource -ModuleName AuditPolicyDsc
  Import-DscResource -ModuleName NetworkingDsc
  Import-DscResource -ModuleName DSCR_AppxPackage

  Node $NodeName
  {
    LocalConfigurationManager
    {
      ConfigurationMode = 'ApplyOnly'
      RebootNodeIfNeeded = $true
      AllowModuleOverwrite = $true
      ActionAfterReboot = 'ContinueConfiguration'
    }

    # registry Settings
    $registrySettings = @(
        # disable Windows Update
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; ValueName = 'NoAutoUpdate'; ValueType = 'Dword'; ValueData = '1'; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName = 'DoNotConnectToWindowsUpdateInternetLocations'; ValueType = 'Dword'; ValueData = 1; Ensure = 'Present' }
        @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'; ValueName = 'Start'; ValueType = 'Dword'; ValueData = 4; Ensure = 'Present' }

        # disable Search UI
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; ValueName = 'AllowCortana'; ValueType = 'Dword'; ValueData = 0; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; ValueName = 'DisableSearch'; ValueType = 'Dword'; ValueData = 1; Ensure = 'Present' }
        
        # disable SmartScreen
        @{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'; ValueName = 'SmartScreenEnabled'; ValueType = 'String'; ValueData = 'Off'; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; ValueName = 'EnableSmartScreen'; ValueType = 'Dword'; ValueData = 0; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen'; ValueName = 'ConfigureAppInstallControlEnabled'; ValueType = 'Dword'; ValueData = 0; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen'; ValueName = 'ConfigureAppInstallControl'; ValueType = 'String'; ValueData = 'Anywhere'; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'; ValueName = 'EnabledV9'; ValueType = 'Dword'; ValueData = 0; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; ValueName = 'PUAProtection'; ValueType = 'Dword'; ValueData = 0; Ensure = 'Present' }
        @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc'; ValueName = 'Start'; ValueType = 'Dword'; ValueData = 4; Ensure = 'Present' }

        # remove SecurityHealth from startup
        @{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; ValueName = 'SecurityHealth'; Ensure = 'Absent' }

        # disable Consumer Features
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; ValueName = 'DisableWindowsConsumerFeatures'; ValueType = 'Dword'; ValueData = 1; Ensure = 'Present' }

        # disable Windows telemetry
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; ValueName = 'AllowTelemetry'; ValueType = 'Dword'; ValueData = '0'; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; ValueName = 'AllowDeviceNameInTelemetry'; ValueType = 'Dword'; ValueData = '0'; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; ValueName = 'AllowTelemetry'; ValueType = 'Dword'; ValueData = '0'; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; ValueName = 'AllowTelemetry'; ValueType = 'Dword'; ValueData = '0'; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows'; ValueName = 'CEIPEnable'; ValueType = 'Dword'; ValueData = '0'; Ensure = 'Present' }

        # disable OneDrive
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'; ValueName = 'DisableFileSyncNGSC'; ValueType = 'Dword'; ValueData = '1'; Ensure = 'Present' }

        # disable Xbox
        @{ Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR'; ValueName = 'AppCaptureEnabled'; ValueType = 'Dword'; ValueData = '0'; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'; ValueName = 'AllowGameDVR'; ValueType = 'Dword'; ValueData = '0'; Ensure = 'Present' }

        # disable Maps
        @{ Key = 'HKLM:\SYSTEM\Maps'; ValueName = 'AutoUpdateEnabled'; ValueType = 'Dword'; ValueData = '0'; Ensure = 'Present' }

        # disable MDM
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM'; ValueName = 'DisableRegistration'; ValueType = 'Dword'; ValueData = '1'; Ensure = 'Present' }

        # disable Delivery Optimisation
        @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc'; ValueName = 'Start'; ValueType = 'Dword'; ValueData = 4; Ensure = 'Present' }

        # disable Edge startup boost and bg mode
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; ValueName = 'StartupBoostEnabled'; ValueType = 'Dword'; ValueData = 0; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; ValueName = 'BackgroundModeEnabled'; ValueType = 'Dword'; ValueData = 0; Ensure = 'Present' }

        # disable Connected Devices Platform (cross-device sync and activities)
        @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc'; ValueName = 'Start'; ValueType = 'Dword'; ValueData = 4; Ensure = 'Present' }

        # disable Sync Host (syncs Mail, Contacts, Calendar, and other app data)
        @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc'; ValueName = 'Start'; ValueType = 'Dword'; ValueData = 4; Ensure = 'Present' }

        # disable Contact Data indexing
        @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc'; ValueName = 'Start'; ValueType = 'Dword'; ValueData = 4; Ensure = 'Present' }

        # disable User Data Storage (stores structured user data for apps)
        @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\UnistoreSvc'; ValueName = 'Start'; ValueType = 'Dword'; ValueData = 4; Ensure = 'Present' }

        # disable User Data Access (provides apps access to email, contacts, calendar)
        @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\UserDataSvc'; ValueName = 'Start'; ValueType = 'Dword'; ValueData = 4; Ensure = 'Present' }

        # disable Windows Push Notifications
        @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService'; ValueName = 'Start'; ValueType = 'Dword'; ValueData = 4; Ensure = 'Present' }

        # enable PowerShell Logging
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; ValueName = 'EnableModuleLogging'; ValueType = 'Dword'; ValueData = 1; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; ValueName = '1'; ValueType = 'String'; ValueData = '*'; Ensure = 'Present' }
        @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; ValueName = 'EnableScriptBlockLogging'; ValueType = 'Dword'; ValueData = 1; Ensure = 'Present' }
        
        # enable Process Command Line Auditing
        @{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; ValueName = 'ProcessCreationIncludeCmdLine_Enabled'; ValueType = 'Dword'; ValueData = 1; Ensure = 'Present' }
    )

    foreach ($reg in $registrySettings) {
        $resourceName = (($reg.Key -replace '[:\\\/]', '_') + '_' + $reg.ValueName) -replace '\s+', ''
        
        if ($reg.Ensure -eq 'Absent') {
            Registry $resourceName {
                Key       = $reg.Key
                ValueName = $reg.ValueName
                Ensure    = 'Absent'
                Force     = $true
            }
        }
        else {
            Registry $resourceName {
                Key       = $reg.Key
                ValueName = $reg.ValueName
                ValueType = $reg.ValueType
                ValueData = $reg.ValueData
                Ensure    = 'Present'
                Force     = $true
            }
        }
    }

    # disable services we don't need for this environment
    $services = @(
      'wuauserv',                       # Windows Update
      'UsoSvc',                         # Windows Update Orchestrator
      'Spooler',                        # Print Spooler
      'Audiosrv',                       # Windows Audio
      'WpnService',                     # Windows Push Notifications
      'wlidsvc',                        # Microsoft Sign In
      'SensrSvc',                       # Sensor Service
      'lfsvc',                          # Geolocation
      'PlugPlay',                       # Plug and Play
      'VSS',                            # Volume Shadow Copy
      'MapsBroker',                     # Downloaded Maps Manager
      'DiagTrack',                      # Connected User Experiences Telemetry
      'WSearch',                        # Windows Search
      'wisvc',                          # Windows Insider Service
      'TokenBroker',                    # Web Account Manager
      'webthreatdefsvc',                # Web Threat Defense
      'vmickvpexchange',                # Hyper-V Data Exchange
      'vmicshutdown',                   # Hyper-V Guest Shutdown
      'vmicheartbeat',                  # Hyper-V Heartbeat
      'vmictimesync',                   # Hyper-V Time Sync
      'CDPSvc',                         # Connected Devices Platform Service
      'SSDPSRV',                        # SSDP Discovery
      'NcdAutoSetup',                   # Network Connected Devices Auto-Setup
      'MicrosoftEdgeElevationService',  # Edge Elevation Service
      'edgeupdatem',                    # Edge update service
      'edgeupdate',                     # Edge update service
      'ShellHWDetection',               # Notifications for Auto-Play hardware events
      'ScDeviceEnum'                    # Smart Card Device Enumeration Service
    )

    foreach ($serviceName in $services) {
      Service "Disable_$serviceName"
      {
        Name        = $serviceName
        State       = 'Stopped'
        StartupType = 'Disabled'
        Ensure      = 'Present'
      }
    }

    Script DisableScheduledTasks
    {
      GetScript = {
        return @{ Result = "Tasks configuration checked" }
      }
      TestScript = {
        return $false
      }
      SetScript = {
        # disable tasks with error handling
        function Disable-Task {
          param($Task, $Description)
          try {
            if ($Task) {
              Disable-ScheduledTask -InputObject $Task -ErrorAction Stop
              Write-Host "Disabled: $Description"
            }
          }
          catch { Write-Warning "Failed to disable ${Description}: $_" }
        }
        $explicitTasks = @(
          # compatibility data and telemetry for Windows upgrade readiness assessment
          @{ Path = '\Microsoft\Windows\Application Experience\'; Name = 'Microsoft Compatibility Appraiser' },
          # program telemetry information
          @{ Path = '\Microsoft\Windows\Application Experience\'; Name = 'ProgramDataUpdater' },
          # application compatibility information at startup
          @{ Path = '\Microsoft\Windows\Application Experience\'; Name = 'StartupAppTask' },
          # sends usage data to Microsoft as part of CEIP
          @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\'; Name = 'Consolidator' },
          # USB device statistics sent to Microsoft as part of CEIP
          @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\'; Name = 'UsbCeip' },
          # disk diagnostic data
          @{ Path = '\Microsoft\Windows\DiskDiagnostic\'; Name = 'Microsoft-Windows-DiskDiagnosticDataCollector' },
          # related to Customer Experience Improvement Program
          @{ Path = '\Microsoft\Windows\Autochk\'; Name = 'Proxy' },
          # Xbox Live game save synchronization
          @{ Path = '\Microsoft\Windows\XblGameSave\'; Name = 'XblGameSaveTask' },
          # Windows Maps notifications
          @{ Path = '\Microsoft\Windows\Maps\'; Name = 'MapsToastTask' },
          # Windows Maps updates
          @{ Path = '\Microsoft\Windows\Maps\'; Name = 'MapsUpdateTask' },
          # wireless network synchronization
          @{ Path = '\Microsoft\Windows\WlanSvc\'; Name = 'CDSSync' },
          # network location awareness WiFi tasks
          @{ Path = '\Microsoft\Windows\NlaSvc\'; Name = 'WiFiTask' },
          # Enterprise Data Protection policies
          @{ Path = '\Microsoft\Windows\AppID\'; Name = 'EDP Policy Manager' },
          # AppID policies
          @{ Path = '\Microsoft\Windows\AppID\'; Name = 'PolicyConverter' },
          # refreshes BitLocker Mobile Device Management policies
          @{ Path = '\Microsoft\Windows\BitLocker\'; Name = 'BitLocker MDM policy Refresh' },
          # refreshes Exploit Guard Mobile Device Management policies
          @{ Path = '\Microsoft\Windows\ExploitGuard\'; Name = 'ExploitGuard MDM policy Refresh' },
          # collects feedback and diagnostic data for CEIP
          @{ Path = '\Microsoft\Windows\Feedback\Siuf\'; Name = 'DmClient' },
          # optimises .NET Framework assemblies (32-bit)
          @{ Path = '\Microsoft\Windows\.NET Framework\'; Name = '.NET Framework NGEN v4.0.30319' },
          # optimises .NET Framework assemblies (64-bit)
          @{ Path = '\Microsoft\Windows\.NET Framework\'; Name = '.NET Framework NGEN v4.0.30319 64' }
        )
        # disable tasks
        foreach ($t in $explicitTasks) {
          $task = Get-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -ErrorAction SilentlyContinue
          Disable-Task -Task $task -Description "$($t.Path)$($t.Name)"
        }
        # disable OneDrive and Edge with SID/GUID names
        $patterns = @('OneDrive *', 'MicrosoftEdge*')
        foreach ($pattern in $patterns) {
          $matchingTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like $pattern }
          foreach ($task in $matchingTasks) {
            Disable-Task -Task $task -Description "$($task.TaskPath)$($task.TaskName)"
          }
        }
      }
    }

    # remove Appx packages. more detailed comments per line probably not necessary
    $AppxNames = @(
      'Microsoft.OneDrive',
      'Microsoft.WindowsStore',
      'Microsoft.ZuneMusic',
      'Microsoft.WindowsCamera',
      'Microsoft.WindowsCalculator',
      'Microsoft.WindowsAlarms',
      'Microsoft.Windows.Photos',
      'Microsoft.WindowsSoundRecorder',
      'Microsoft.WindowsNotepad',
      'Microsoft.WindowsTerminal',
      'MicrosoftWindows.Client.WebExperience',
      'Microsoft.Edge.GameAssist',
      'Microsoft.PowerAutomateDesktop',
      'Microsoft.Paint',
      'Microsoft.ScreenSketch',
      'Microsoft.Todos',
      'Microsoft.YourPhone',
      'MicrosoftCorporationII.QuickAssist',
      'Microsoft.WindowsFeedbackHub',
      'Microsoft.GetHelp',
      'Microsoft.Windows.DevHome',
      'Microsoft.OutlookForWindows',
      'Microsoft.GamingApp',
      'Microsoft.XboxGamingOverlay',
      'Microsoft.XboxIdentityProvider',
      'Microsoft.XboxSpeechToTextOverlay',
      'Microsoft.Xbox.TCUI',
      'Microsoft.MicrosoftStickyNotes',
      'Microsoft.MicrosoftSolitaireCollection',
      'Microsoft.MicrosoftOfficeHub',
      'Microsoft.BingWeather',
      'Microsoft.BingNews',
      'Microsoft.BingSearch',
      'Microsoft.WidgetsPlatformRuntime',
      'Microsoft.HEVCVideoExtension',
      'Microsoft.HEIFImageExtension',
      'Microsoft.RawImageExtension',
      'Microsoft.VP9VideoExtensions',
      'Microsoft.WebpImageExtension',
      'Microsoft.WebMediaExtensions',
      'Microsoft.MPEG2VideoExtension',
      'Microsoft.AVCEncoderVideoExtension',
      'Microsoft.AV1VideoExtension',
      'Microsoft.StorePurchaseApp',
      'Microsoft.MicrosoftEdge.Stable',
      'Clipchamp.Clipchamp',
      'MSTeams'
    )

    # remove packages from the image so they don't install for new users
    cAppxProvisionedPackageSet Provisioned_Absent
    {
      Ensure      = 'Absent'
      PackageName = $AppxNames
      AllUsers    = $true
    }

    # remove already-installed packages for users
    cAppxPackageSet Installed_Absent
    {
      Ensure = 'Absent'
      Name   = $AppxNames
    }

    # define event log configurations
    $eventLogs = @(
      @{ LogName = 'Security'; MaxSize = 4GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'System'; MaxSize = 4GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Application'; MaxSize = 4GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-WMI-Activity/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-SMBServer/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-SMBServer/Security'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-SMBClient/Security'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-LSA/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-CAPI2/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-NTLM/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-GroupPolicy/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-WinRM/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-Diagnosis-Scripted/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = $null }
      @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; MaxSize = 2GB; IsEnabled = $true; DependsOn = '[Script]WaitForSysmonLog' }
      @{ LogName = 'Anchors'; MaxSize = 2GB; IsEnabled = $true; DependsOn = '[Script]EnsureAnchorSource' }
    )

    foreach ($log in $eventLogs)
    {
      $resourceName = $log.LogName -replace '[/-]', ''
      
      if ($log.DependsOn) {
        WindowsEventLog $resourceName { 
          LogName = $log.LogName
          LogMode = 'Circular'
          MaximumSizeInBytes = $log.MaxSize
          IsEnabled = $log.IsEnabled
          DependsOn = $log.DependsOn
        }
      }
      else {
        WindowsEventLog $resourceName { 
          LogName = $log.LogName
          LogMode = 'Circular'
          MaximumSizeInBytes = $log.MaxSize
          IsEnabled = $log.IsEnabled
        }
      }
    }

    # Audit Policy configuration
    # Account Logon
    AuditPolicySubcategory APS_CredentialValidation_S { Name = 'Credential Validation'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_CredentialValidation_F { Name = 'Credential Validation'; AuditFlag = 'Failure' }
    AuditPolicySubcategory APS_KerberosAuthSvc_S { Name = 'Kerberos Authentication Service'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_KerberosAuthSvc_F { Name = 'Kerberos Authentication Service'; AuditFlag = 'Failure' }
    AuditPolicySubcategory APS_KerberosST_S { Name = 'Kerberos Service Ticket Operations'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_KerberosST_F { Name = 'Kerberos Service Ticket Operations'; AuditFlag = 'Failure' }

    # Account Management
    AuditPolicySubcategory APS_ComputerAcctMgmt_S { Name = 'Computer Account Management'; AuditFlag = 'Success' }
    AuditPolicySubcategory APD_ComputerAcctMgmt_F { Name = 'Computer Account Management'; AuditFlag = 'Failure'; Ensure = 'Absent' }
    AuditPolicySubcategory APS_OtherAcctMgmt_S { Name = 'Other Account Management Events'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_OtherAcctMgmt_F { Name = 'Other Account Management Events'; AuditFlag = 'Failure' }
    AuditPolicySubcategory APS_SecGroupMgmt_S { Name = 'Security Group Management'; AuditFlag = 'Success' }
    AuditPolicySubcategory APD_SecGroupMgmt_F { Name = 'Security Group Management'; AuditFlag = 'Failure'; Ensure = 'Absent' }
    AuditPolicySubcategory APS_UserAcctMgmt_S { Name = 'User Account Management'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_UserAcctMgmt_F { Name = 'User Account Management'; AuditFlag = 'Failure' }

    # Detailed Tracking
    AuditPolicySubcategory APS_PnP_S { Name = 'Plug and Play Events'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_PnP_F { Name = 'Plug and Play Events'; AuditFlag = 'Failure' }
    AuditPolicySubcategory APS_ProcessCreation_S { Name = 'Process Creation'; AuditFlag = 'Success' }
    AuditPolicySubcategory APD_ProcessCreation_F { Name = 'Process Creation'; AuditFlag = 'Failure'; Ensure = 'Absent' }
    AuditPolicySubcategory APS_ProcessTermination_S { Name = 'Process Termination'; AuditFlag = 'Success' }
    AuditPolicySubcategory APD_ProcessTermination_F { Name = 'Process Termination'; AuditFlag = 'Failure'; Ensure = 'Absent' }
    AuditPolicySubcategory APS_RPCEvents_S { Name = 'RPC Events'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_RPCEvents_F { Name = 'RPC Events'; AuditFlag = 'Failure' }
    AuditPolicySubcategory APS_TokenRightAdjusted_S { Name = 'Token Right Adjusted Events'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_TokenRightAdjusted_F { Name = 'Token Right Adjusted Events'; AuditFlag = 'Failure' }

    # create dirs
    $toolsDir = 'C:\Tools\'
    $downloadsDir = Join-Path -Path $toolsDir -ChildPath 'Downloads'

    File EnsureToolsFolder
    {
      Ensure = 'Present'
      Type = 'Directory'
      DestinationPath = $toolsDir
    }

    File EnsureToolsDLFolder
    {
      Ensure = 'Present'
      Type = 'Directory'
      DestinationPath = $downloadsDir
      DependsOn = '[File]EnsureToolsFolder'
    }

    # RPC Firewall download and installation
    xRemoteFile GetRPCFW
    {
      DestinationPath = 'C:\Tools\Downloads\RPCFW_2.2.5.zip'
      Uri = 'https://github.com/zeronetworks/rpcfirewall/releases/download/v2.2.5/RPCFW_2.2.5.zip'
      DependsOn = '[File]EnsureToolsDLFolder'
    }

    Archive UnzipRPCFW
    {
      Path = 'C:\Tools\Downloads\RPCFW_2.2.5.zip'
      Destination = 'C:\Tools\'
      Ensure = 'Present'
      Force = $true
      DependsOn = '[xRemoteFile]GetRPCFW'
    }

    Script InstallRPCFW
    {
      GetScript = {
        $service = Get-Service -Name 'rpcFw*' -ErrorAction SilentlyContinue
        @{ Result = ($service -ne $null) }
      }
      TestScript = {
        $service = Get-Service -Name 'rpcFw*' -ErrorAction SilentlyContinue
        return ($service -ne $null)
      }
      SetScript = {
        $exe = 'C:\Tools\RPCFW_2.2.5\rpcFwManager.exe'
        Start-Process -FilePath $exe -ArgumentList '/install' -Wait
        Start-Process -FilePath $exe -ArgumentList '/start' -Wait
      }
      DependsOn = '[Archive]UnzipRPCFW'
    }

    # Sysmon download and installation
    xRemoteFile GetSysmonZip
    {
      DestinationPath = 'C:\Tools\Downloads\Sysmon.zip'
      Uri = 'https://download.sysinternals.com/files/Sysmon.zip'
      DependsOn = '[File]EnsureToolsDLFolder'
    }

    Archive UnzipSysmon
    {
      Path = 'C:\Tools\Downloads\Sysmon.zip'
      Destination = 'C:\Tools\Sysmon'
      Ensure = 'Present'
      Force = $true
      DependsOn = '[xRemoteFile]GetSysmonZip'
    }

    xRemoteFile GetSysmonConfig
    {
      DestinationPath = 'C:\Tools\Sysmon\sysmonconfig-research2.xml'
      Uri = 'https://raw.githubusercontent.com/smashtitle/TelemetryForge/refs/heads/main/sysmonconfig-research.xml'
      DependsOn = '[Archive]UnzipSysmon'
    }

    Script InstallSysmon
    {
      GetScript = { @{ Result = (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) -ne $null } }
      TestScript = { (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) -ne $null }
      SetScript = {
        $dest = 'C:\Tools\Sysmon'
        $exe = Join-Path $dest 'Sysmon64.exe'
        if (-not (Test-Path $exe)) { throw "Sysmon64 executable not found at $dest" }

        $cfg = Join-Path $dest 'sysmonconfig-research2.xml'
        if (-not (Test-Path $cfg)) { throw "Sysmon config not found" }

        Start-Process -FilePath $exe -ArgumentList '-accepteula', '-i', "`"$cfg`"" -Wait
      }
      DependsOn = '[xRemoteFile]GetSysmonConfig'
    }

    # remove OneDrive
    Script RemoveOneDrive
    {
      GetScript = {
        $installed = (Get-Process OneDrive -ErrorAction SilentlyContinue) -or
                     (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe")
        @{ Result = $installed }
      }
      TestScript = {
        -not ((Get-Process OneDrive -ErrorAction SilentlyContinue) -or
              (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe"))
      }
      SetScript = {
        # stop OneDrive processes
        Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force
        # uninstall
        $setup = "$env:SystemRoot\System32\OneDriveSetup.exe"
        if (Test-Path $setup) {
          Start-Process -FilePath $setup -ArgumentList '/uninstall' -Wait -WindowStyle Hidden
        }
        # remove per-user OneDrive folders
        $profiles = Get-CimInstance Win32_UserProfile | Where-Object { 
          $_.LocalPath -like 'C:\Users\*' -and -not $_.Special 
        }
        foreach ($profile in $profiles) {
          @(
            (Join-Path $profile.LocalPath 'AppData\Local\Microsoft\OneDrive'),
            (Join-Path $profile.LocalPath 'OneDrive')
          ) | ForEach-Object {
            if (Test-Path $_) {
              Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue
            }
          }
        }
      }
    }

    # clean up temp files
    Script CleanupTemps
    {
      GetScript = {
        if (Test-Path 'C:\Tools\.cleanup.done')
        {
          @{ Result = 'present' }
        }
        else
        {
          @{ Result = 'absent' }
        }
      }
      TestScript = {
        Test-Path 'C:\Tools\.cleanup.done'
      }
      SetScript = {
        $paths = @(
          "$env:windir\Temp\*",
          "C:\Windows\SoftwareDistribution\Download\*",
          "C:\Windows\Prefetch\*",
          "C:\Windows\SystemTemp\*",
          "$env:ProgramData\Temp\*",
          "C:\Tools\Downloads\*"
        )
        foreach ($p in $paths)
        {
          Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType File -Path "C:\Tools\.cleanup.done" -Force | Out-Null
      }
    }
  }
}

$ConfigData = @{
  AllNodes = @(
    @{
      NodeName = 'localhost'
      PSDscAllowPlainTextPassword = $true
    }
  )
}

$SecurePassword = ConvertTo-SecureString 'HelloP@ssw0rd123!' -AsPlainText -Force
$Credential     = [PSCredential]::new('admin', $SecurePassword)

# compile
$OutPath = Join-Path $PSScriptRoot 'MOF'
New-Item -ItemType Directory -Path $OutPath -Force | Out-Null

$params = @{
  NodeName              = 'localhost'
  LocalAdminCredential  = $Credential
  ConfigurationData     = $ConfigData
  OutputPath            = $OutPath
}
BaselineConfiguration @params

# apply
Start-DscConfiguration -Path $OutPath -Wait -Verbose -Debug -Force *> C:\Tools\dsc-execution.log
