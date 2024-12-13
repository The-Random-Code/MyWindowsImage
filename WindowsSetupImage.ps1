# Adapted from Chris Titus's script: https://github.com/ChrisTitusTech/win10script
# Also using a recommended config from LeDragoX: https://github.com/LeDragoX/Win-Debloat-Tools/blob/main/src/configs/shutup10/ooshutup10.cfg
# The overall idea: streamline Windows, remove unwanted extras, and apply some performance tweaks.

Import-Module BitsTransfer

# Function that handles file downloads. This is handy when we need external tools or configs
# without having to open a browser or do manual steps.
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

    # Make sure the download directory exists. If not, we just go ahead and create it.
    If (!(Test-Path $SaveFolder)) {
        Write-Host "Creating directory: $SaveFolder"
        New-Item -Path $SaveFolder -ItemType Directory -Force | Out-Null
    }

    $FullFilePath = Join-Path -Path $SaveFolder -ChildPath $SaveAs

    Write-Host "Downloading from: '$DownloadURL'"
    Invoke-WebRequest -Uri $DownloadURL -OutFile $FullFilePath

    # Return the path of the downloaded file so we can easily use it later on.
    return "$FullFilePath"
}

# Function to tweak SSD settings. The idea is to reduce unnecessary disk writes
# and avoid doing stuff that might wear out the SSD over time.
function Improve-SSDSettings {
    Write-Host "Applying SSD optimization settings..."
    fsutil behavior set DisableLastAccess 1
    fsutil behavior set EncryptPagingFile 0
}
Improve-SSDSettings

# Before making system changes, we create a restore point.
# This gives us a quick fallback if something unexpected happens.
function Create-SystemRestorePoint {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String] $RestorePointName
    )

    Write-Host "Creating system restore point: $RestorePointName"
    Checkpoint-Computer -Description $RestorePointName -RestorePointType "MODIFY_SETTINGS"
}

# Main "debloat" function. If we're not undoing changes, we'll run cleanup tools.
# If we are undoing, we revert what we can.
function Run-SystemDebloat {
    [CmdletBinding()]
    param (
        [Switch] $UndoChanges
    )

    If (!$UndoChanges) {
        # Pull down Malwarebytes AdwCleaner and run it to remove adware and junk.
        # This is a quick way to tidy up the system before we apply other improvements.
        $AdwCleanerURL = "https://downloads.malwarebytes.com/file/adwcleaner"
        [String] $AdwCleanerPath = (Download-FileFromWeb -DownloadURL $AdwCleanerURL -SaveAs "adwcleaner.exe")
        Write-Host "Launching Malwarebytes AdwCleaner..."
        Start-Process -FilePath "$AdwCleanerPath" -ArgumentList "/eula", "/clean", "/noreboot" -Wait
    }

    # Next, O&O ShutUp10++ is used to apply recommended privacy settings.
    # We download it on the fly and run it with a config file to automate the process.
    $ShutUp10URL = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
    [String] $ShutUp10Path = Download-FileFromWeb -DownloadURL $ShutUp10URL -SaveAs "OOSU10.exe"
    $ShutUp10Config = Download-FileFromWeb -DownloadURL "https://raw.githubusercontent.com/LeDragoX/Win-Debloat-Tools/main/src/configs/shutup10/ooshutup10.cfg" -SaveAs "ooshutup10.cfg"

    # We need to run OOSU10 in its own directory.
    $ShutUp10Folder = Split-Path -Path $ShutUp10Path
    Push-Location -Path $ShutUp10Folder

    If ($UndoChanges) {
        # If we're rolling back changes, we apply the default config from OOSU10.
        Write-Host "Reverting settings using O&O ShutUp10++..."
        Start-Process -FilePath "$ShutUp10Path" -ArgumentList "ooshutup10-default.cfg", "/quiet" -Wait
    } Else {
        # Otherwise, we apply our recommended set of tweaks for privacy and performance.
        Write-Host "Applying recommended settings with O&O ShutUp10++..."
        Start-Process -FilePath "$ShutUp10Path" -ArgumentList "ooshutup10.cfg", "/quiet" -Wait
    }

    Pop-Location
    # After we’re done, we remove OOSU10 and related files. Keeps things clean.
    Remove-Item -Path $ShutUp10Folder -Force -Recurse
}

# We create a restore point before starting any major changes.
Create-SystemRestorePoint -RestorePointName "Pre-Debloat Optimization"

If (!$UndoChanges) {
    Run-SystemDebloat # Actually do the cleaning and privacy setups.
} Else {
    Run-SystemDebloat -UndoChanges
}

$MouseSettingsPath = "HKCU:\Control Panel\Mouse"
$NewsAndInterestsUserPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"
$NewsAndInterestsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Feeds"

# Functions that tweak mouse acceleration. Some prefer it off for better precision, especially in gaming.
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

# The "News and Interests" widget can be distracting.
# We'll hide it to keep the taskbar clean and less cluttered.
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

# Managing Windows optional features. We can enable or disable certain built-in components
# that we might never use (e.g., Fax Services).
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
            # Toggle the feature state based on what we want and what it currently is.
            if ($Action -eq 'Disable' -and $FeatureInfo.State -eq 'Enabled') {
                Write-Host "Disabling feature: $Feature"
                Disable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart -Remove
            } elseif ($Action -eq 'Enable' -and $FeatureInfo.State -eq 'Disabled') {
                Write-Host "Enabling feature: $Feature"
                Enable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart
            }
        } else {
            # If a feature doesn’t exist, just let the user know. No harm done.
            Write-Host "Feature not found: $Feature"
        }
    }
}

# We gather a bunch of optional features and disable them, or re-enable them if we’re undoing.
# The goal: reduce resource usage and remove unnecessary components.
function Optimize-WindowsComponents {
    [CmdletBinding()]
    param (
        [Switch] $UndoChanges
    )

    $FeaturesToManage = @(
        "FaxServicesClientPackage",             # Windows Fax and Scan: rarely used nowadays
        "IIS-ASPNET",                           # IIS components we likely don't need on a desktop
        "Internet-Explorer-Optional-amd64",     # IE is outdated, better to have it off
        "MediaPlayback",                        # Can remove if you have no use for WMP
        "MicrosoftWindowsPowerShellV2",         # Legacy PowerShell 2.0 components
        "MicrosoftWindowsPowerShellV2Root",     # Root component for PowerShell 2.0
        "WorkFolders-Client"                    # Not commonly used in personal setups
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

# Now we do some performance tweaks.
# The idea here is to set various registry values and services to improve system responsiveness.
Write-Host "Applying performance enhancements..."

# Enabling NDU can improve network performance. We also adjust SvcHostSplitThresholdInKB based on RAM.
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Type DWord -Value 2
$TotalRAMInKB = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type QWord -Value $TotalRAMInKB

# Disable Edge preloading and background activities to free up some resources.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "UpdateDefault" -Type DWord -Value 0

# Adjust network throttling to avoid artificially limiting our bandwidth.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff

# Tell Windows to end tasks automatically rather than waiting. Speeds up shutdowns and logoffs.
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Type String -Value "1"

# Adjust system responsiveness to ensure smoother performance, especially under load.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0

# Tweak system profile settings for gaming. Increase GPU priority and scheduling to favor performance.
$GamingProfilePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
If (!(Test-Path $GamingProfilePath)) {
    New-Item -Path $GamingProfilePath -Force | Out-Null
}
Set-ItemProperty -Path $GamingProfilePath -Name "GPU Priority" -Type DWord -Value 8
Set-ItemProperty -Path $GamingProfilePath -Name "Priority" -Type DWord -Value 6
Set-ItemProperty -Path $GamingProfilePath -Name "Scheduling Category" -Type String -Value "High"

# Don’t clear the page file at shutdown—speeds up the shutdown process.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Type DWord -Value 0

# Remove registry entries associated with extensions we don’t need. Just a bit of decluttering.
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

# Function to manage and optimize system services.
# Disabling certain services can reduce overhead and free up resources.
function Optimize-SystemServices {
    param (
        [Switch]$UndoChanges
    )

    Write-Host "Adjusting Windows services for optimal performance..."

    # Services we consider non-essential for normal desktop usage are disabled.
    # If undoing changes, we set them back to manual.
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

    # These services go to manual since we might need them occasionally but don't want them always running.
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

    # This service stays on automatic because we actually need it.
    $ServicesToAutomatic = @(
        "Ndu"
    )

    if ($UndoChanges) {
        # Going back to a safer default: manual start rather than disabled.
        foreach ($Service in $ServicesToDisable) {
            Set-Service -Name $Service -StartupType Manual -ErrorAction SilentlyContinue
        }
    } else {
        # Just turn these off so they're not running constantly in the background.
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

# Function to tweak scheduled tasks.
# We disable tasks that aren't critical and just eat resources or send data we don't need.
function Optimize-ScheduledTasks {
    param (
        [Switch]$UndoChanges
    )

    Write-Host "Modifying scheduled tasks for better performance..."

    # These tasks either track usage, gather telemetry, or do things we don’t want running regularly.
    # If we're reverting, we turn them back on.
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

    # Tasks we consider beneficial or harmless to keep active.
    $TasksToEnable = @(
        "\Microsoft\Windows\Defrag\ScheduledDefrag",
        "\Microsoft\Windows\Maintenance\WinSAT",
        "\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )

    if ($UndoChanges) {
        # Re-enabling tasks that were previously disabled.
        foreach ($Task in $TasksToDisable) {
            $TaskPath = Split-Path $Task -Parent
            $TaskName = Split-Path $Task -Leaf
            try {
                Enable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
            } catch {}
        }
    } else {
        # Disabling tasks we don't want constantly running behind the scenes.
        foreach ($Task in $TasksToDisable) {
            $TaskPath = Split-Path $Task -Parent
            $TaskName = Split-Path $Task -Leaf
            try {
                Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
            } catch {}
        }
    }

    # Ensuring that the tasks we actually want are enabled.
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

# Turn off mouse acceleration for better pointer precision, especially useful for gaming and design work.
TurnOff-MouseAcceleration

# Hide that "News and Interests" thing on the taskbar. Just reduces clutter and distraction.
Hide-NewsAndInterests
Write-Host "System optimization script has completed successfully!"
