# Adapted from Chris Titus's script: https://github.com/ChrisTitusTech/win10script
# Additional configurations from: https://github.com/LeDragoX/Win-Debloat-Tools/blob/main/src/configs/shutup10/ooshutup10.cfg

Import-Module BitsTransfer

# Function to download files from the internet
function Download-FileFromWeb {
    [CmdletBinding()]
    [OutputType([String[]])]
    param (
        [Alias('URL')]
        [Parameter(Position = 0, Mandatory)]
        [String] $DownloadURL,

        [Alias('DestinationFolder', 'OutputDirectory')]
        [Parameter(Position = 1)]
        [String] $SaveFolder = "$($env:TEMP)\downloads",

        [Alias('Filename', 'OutputFile')]
        [Parameter(Position = 2, Mandatory)]
        [String] $SaveAs
    )

    # Ensure the output directory exists
    If (!(Test-Path $SaveFolder)) {
        Write-Host "Creating directory: $SaveFolder"
        New-Item -Path $SaveFolder -ItemType Directory -Force | Out-Null
    }

    $FullFilePath = Join-Path -Path $SaveFolder -ChildPath $SaveAs

    Write-Host "Downloading from: '$DownloadURL'"
    Invoke-WebRequest -Uri $DownloadURL -OutFile $FullFilePath

    return "$FullFilePath"
}

# Function to improve SSD longevity
function Improve-SSDSettings {
    Write-Host "Applying SSD optimization settings..."
    fsutil behavior set DisableLastAccess 1
    fsutil behavior set EncryptPagingFile 0
}
Improve-SSDSettings

# Function to create a system restore point
function Create-SystemRestorePoint {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String] $RestorePointName
    )

    Write-Host "Creating system restore point: $RestorePointName"
    Checkpoint-Computer -Description $RestorePointName -RestorePointType "MODIFY_SETTINGS"
}

# Function to run system debloating tools
function Run-SystemDebloat {
    [CmdletBinding()]
    param (
        [Switch] $UndoChanges
    )

    If (!$UndoChanges) {
        # Download and run Malwarebytes AdwCleaner
        $AdwCleanerURL = "https://downloads.malwarebytes.com/file/adwcleaner"
        [String] $AdwCleanerPath = (Download-FileFromWeb -DownloadURL $AdwCleanerURL -SaveAs "adwcleaner.exe")
        Write-Host "Launching Malwarebytes AdwCleaner..."
        Start-Process -FilePath "$AdwCleanerPath" -ArgumentList "/eula", "/clean", "/noreboot" -Wait
    }

    # Download and run O&O ShutUp10++
    $ShutUp10URL = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
    [String] $ShutUp10Path = Download-FileFromWeb -DownloadURL $ShutUp10URL -SaveAs "OOSU10.exe"
    $ShutUp10Config = Download-FileFromWeb -DownloadURL "https://raw.githubusercontent.com/LeDragoX/Win-Debloat-Tools/main/src/configs/shutup10/ooshutup10.cfg" -SaveAs "ooshutup10.cfg"

    # Push-Location should be called with a proper directory path
    $ShutUp10Folder = Split-Path -Path $ShutUp10Path
    Push-Location -Path $ShutUp10Folder

    If ($UndoChanges) {
        Write-Host "Reverting settings using O&O ShutUp10++..."
        Start-Process -FilePath "$ShutUp10Path" -ArgumentList "ooshutup10-default.cfg", "/quiet" -Wait
    } Else {
        Write-Host "Applying recommended settings with O&O ShutUp10++..."
        Start-Process -FilePath "$ShutUp10Path" -ArgumentList "ooshutup10.cfg", "/quiet" -Wait
    }

    Pop-Location
    Remove-Item -Path $ShutUp10Folder -Force -Recurse
}

# Create a system restore point before making changes
Create-SystemRestorePoint -RestorePointName "Pre-Debloat Optimization"

If (!$UndoChanges) {
    Run-SystemDebloat # Execute debloating tools and scans
} Else {
    Run-SystemDebloat -UndoChanges
}

$MouseSettingsPath = "HKCU:\Control Panel\Mouse"
$NewsAndInterestsUserPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"
$NewsAndInterestsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Feeds"

# Functions to manage mouse settings
function TurnOff-MouseAcceleration {
    Write-Host "Turning off mouse acceleration..."
    Set-ItemProperty -Path $MouseSettingsPath -Name "MouseSpeed" -Type String -Value "0"
    Set-ItemProperty -Path $MouseSettingsPath -Name "MouseThreshold1" -Type String -Value "0"
    Set-ItemProperty -Path $MouseSettingsPath -Name "MouseThreshold2" -Type String -Value "0"
}

function TurnOn-MouseAcceleration {
    Write-Host "Turning on mouse acceleration..."
    Set-ItemProperty -Path $MouseSettingsPath -Name "MouseSpeed" -Type String -Value "1"
    Set-ItemProperty -Path $MouseSettingsPath -Name "MouseThreshold1" -Type String -Value "6"
    Set-ItemProperty -Path $MouseSettingsPath -Name "MouseThreshold2" -Type String -Value "10"
}

# Functions to manage News and Interests feature
function Hide-NewsAndInterests {
    Write-Host "Disabling 'News and Interests' on the taskbar..."
    Set-ItemProperty -Path $NewsAndInterestsUserPath -Name "ShellFeedsTaskbarOpenOnHover" -Type DWord -Value 0
    Set-ItemProperty -Path $NewsAndInterestsPolicyPath -Name "EnableFeeds" -Type DWord -Value 0
}

function Show-NewsAndInterests {
    Write-Host "Enabling 'News and Interests' on the taskbar..."
    Set-ItemProperty -Path $NewsAndInterestsUserPath -Name "ShellFeedsTaskbarOpenOnHover" -Type DWord -Value 1
    Remove-ItemProperty -Path $NewsAndInterestsPolicyPath -Name "EnableFeeds" -ErrorAction SilentlyContinue
}

# Function to manage Windows optional features
function Configure-OptionalFeatures {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateSet('Disable', 'Enable')]
        [String] $Action,

        [Parameter(Position = 1, Mandatory)]
        [String[]] $FeaturesList
    )

    foreach ($Feature in $FeaturesList) {
        $FeatureInfo = Get-WindowsOptionalFeature -Online -FeatureName $Feature -ErrorAction SilentlyContinue
        if ($FeatureInfo) {
            if ($Action -eq 'Disable' -and $FeatureInfo.State -eq 'Enabled') {
                Write-Host "Disabling feature: $Feature"
                Disable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart -Remove
            } elseif ($Action -eq 'Enable' -and $FeatureInfo.State -eq 'Disabled') {
                Write-Host "Enabling feature: $Feature"
                Enable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart
            }
        } else {
            Write-Host "Feature not found: $Feature"
        }
    }
}

# Function to optimize Windows features
function Optimize-WindowsComponents {
    [CmdletBinding()]
    param (
        [Switch] $UndoChanges
    )

    $FeaturesToManage = @(
        "FaxServicesClientPackage",             # Windows Fax and Scan
        "IIS-ASPNET",                           # Internet Information Services components
        "Internet-Explorer-Optional-amd64",     # Internet Explorer
        "MediaPlayback",                        # Windows Media Player
        "MicrosoftWindowsPowerShellV2",         # PowerShell 2.0
        "MicrosoftWindowsPowerShellV2Root",     # PowerShell 2.0 Root
        "WorkFolders-Client"                    # Work Folders Client
    )

    If ($UndoChanges) {
        Configure-OptionalFeatures -Action 'Enable' -FeaturesList $FeaturesToManage
    } Else {
        Configure-OptionalFeatures -Action 'Disable' -FeaturesList $FeaturesToManage
    }
}

If (!$UndoChanges) {
    Optimize-WindowsComponents
} Else {
    Optimize-WindowsComponents -UndoChanges
}

# Performance tweaks
Write-Host "Applying performance enhancements..."

# Enable NDU and set SvcHostSplitThresholdInKB
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Type DWord -Value 2
$TotalRAMInKB = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type QWord -Value $TotalRAMInKB

# Disable Edge background processes
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "UpdateDefault" -Type DWord -Value 0

# Adjust network throttling settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff

# Modify desktop settings for performance
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Type String -Value "1"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0

# Configure gaming-related system profile settings
$GamingProfilePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
If (!(Test-Path $GamingProfilePath)) {
    New-Item -Path $GamingProfilePath -Force | Out-Null
}
Set-ItemProperty -Path $GamingProfilePath -Name "GPU Priority" -Type DWord -Value 8
Set-ItemProperty -Path $GamingProfilePath -Name "Priority" -Type DWord -Value 6
Set-ItemProperty -Path $GamingProfilePath -Name "Scheduling Category" -Type String -Value "High"

# Disable clearing page file at shutdown
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Type DWord -Value 0

# Remove unnecessary registry entries
$RegistryKeysToRemove = @(
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\*",
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\*",
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\*",
    "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\*"
)

foreach ($RegistryPattern in $RegistryKeysToRemove) {
    $RegistryEntries = Get-ChildItem -Path $RegistryPattern -ErrorAction SilentlyContinue
    foreach ($Entry in $RegistryEntries) {
        Remove-Item -Path $Entry.PSPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Function to optimize services
function Optimize-SystemServices {
    param (
        [Switch]$UndoChanges
    )

    Write-Host "Adjusting Windows services for optimal performance..."

    # Services to disable
    $ServicesToDisable = @(
        "DiagTrack",
        "dmwappushservice",
        "Fax",
        "MapsBroker",
        "RemoteRegistry",
        "RetailDemo",
        "SysMain",
        "WSearch"
    )

    # Services to set to manual
    $ServicesToManual = @(
        "BITS",
        "edgeupdate",
        "edgeupdatem",
        "WpnService",
        "XblAuthManager",
        "XblGameSave",
        "XboxGipSvc",
        "XboxNetApiSvc"
    )

    # Services to set to automatic
    $ServicesToAutomatic = @(
        "Ndu"
    )

    if ($UndoChanges) {
        foreach ($Service in $ServicesToDisable) {
            Set-Service -Name $Service -StartupType Manual -ErrorAction SilentlyContinue
        }
    } else {
        foreach ($Service in $ServicesToDisable) {
            Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }

    foreach ($Service in $ServicesToManual) {
        Set-Service -Name $Service -StartupType Manual -ErrorAction SilentlyContinue
    }

    foreach ($Service in $ServicesToAutomatic) {
        Set-Service -Name $Service -StartupType Automatic -ErrorAction SilentlyContinue
    }
}

If (!$UndoChanges) {
    Optimize-SystemServices
} Else {
    Optimize-SystemServices -UndoChanges
}

# Function to optimize scheduled tasks
function Optimize-ScheduledTasks {
    param (
        [Switch]$UndoChanges
    )

    Write-Host "Modifying scheduled tasks for better performance..."

    # Tasks to disable
    $TasksToDisable = @(
        "\Microsoft\Office\OfficeTelemetryAgentLogOn",
        "\Microsoft\Office\OfficeTelemetryAgentFallBack",
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\Maps\MapsUpdateTask",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
        "\Microsoft\Windows\Shell\FamilySafetyMonitor",
        "\Microsoft\Windows\Shell\FamilySafetyRefresh",
        "\Microsoft\Windows\Shell\FamilySafetyUpload"
    )

    # Tasks to enable
    $TasksToEnable = @(
        "\Microsoft\Windows\Defrag\ScheduledDefrag",
        "\Microsoft\Windows\Maintenance\WinSAT",
        "\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )

    if ($UndoChanges) {
        foreach ($Task in $TasksToDisable) {
            $TaskPath = Split-Path $Task -Parent
            $TaskName = Split-Path $Task -Leaf
            try {
                Enable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
            } catch {}
        }
    } else {
        foreach ($Task in $TasksToDisable) {
            $TaskPath = Split-Path $Task -Parent
            $TaskName = Split-Path $Task -Leaf
            try {
                Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
            } catch {}
        }
    }

    foreach ($Task in $TasksToEnable) {
        $TaskPath = Split-Path $Task -Parent
        $TaskName = Split-Path $Task -Leaf
        try {
            Enable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
        } catch {}
    }
}

If (!$UndoChanges) {
    Optimize-ScheduledTasks
} Else {
    Optimize-ScheduledTasks -UndoChanges
}

# Apply mouse and taskbar settings
TurnOff-MouseAcceleration
Hide-NewsAndInterests

# Final message
Write-Host "System optimization script has completed successfully!"
