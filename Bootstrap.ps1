Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# enforce TLS2.0, install NuGet and PSGallery
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop

# install required DSC modules
$modules = @(
  'PSDscResources',
  'xPSDesiredStateConfiguration',
  'ComputerManagementDsc',
  'AuditPolicyDsc',
  'NetworkingDsc',
  'DSCR_AppxPackage'
)

foreach ($m in $modules) {
  if (-not (Get-Module -ListAvailable -Name $m)) {
    Install-Module -Name $m -Scope AllUsers -Force -AllowClobber -SkipPublisherCheck -ErrorAction Stop
  }
}

# set network profile to Private to support WinRM configuration
Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' } | 
  Set-NetConnectionProfile -NetworkCategory Private

# Start-DscConfiguration requires WinRM/CIM to push configurations
Enable-PSRemoting -Force
winrm quickconfig -force
