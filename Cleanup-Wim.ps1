Param (
    [Parameter(Mandatory)]
    [String]
    $WimFile,
    [Int]
    $Index,
    [String]
    $MountDir,
    [Switch]
    $DryRun
)

$packages = @(
"Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~amd64~~10.0.19041.1"
"Microsoft-Windows-OneDrive-Setup-WOW64-Package~31bf3856ad364e35~amd64~~10.0.19041.1"
)

$appxs = @(
"Microsoft.549981C3F5F10_1.1911.21713.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.GetHelp_10.1706.13331.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.Getstarted_8.2.22942.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.Microsoft3DViewer_6.1908.2042.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.MicrosoftOfficeHub_18.1903.1152.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.MicrosoftSolitaireCollection_4.4.8204.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.MicrosoftStickyNotes_3.6.73.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.MixedReality.Portal_2000.19081.1301.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.MSPaint_2019.729.2301.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.Office.OneNote_16001.12026.20112.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.People_2019.305.632.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.SkypeApp_14.53.77.0_neutral_~_kzf8qxf38zg5c"
"Microsoft.StorePurchaseApp_11811.1001.1813.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.Wallet_2.4.18324.0_neutral_~_8wekyb3d8bbwe"
"microsoft.windowscommunicationsapps_16005.11629.20316.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.WindowsFeedbackHub_2019.1111.2029.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.WindowsMaps_2019.716.2316.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.WindowsStore_11910.1002.513.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.Xbox.TCUI_1.23.28002.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.XboxApp_48.49.31001.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.XboxIdentityProvider_12.50.6001.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.XboxSpeechToTextOverlay_1.17.29001.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.YourPhone_2019.430.2026.0_neutral_~_8wekyb3d8bbwe"
)


function processWimFileAtIndex {
    dism /Mount-Wim /WimFile:$WimFile /Index:$Index /MountDir:$MountDir

    # Preprocess registry to remove packages with DISM
    REG LOAD "HKLM\SOFTWARE-$RunId" "$MountDir\Windows\System32\config\SOFTWARE"
    foreach ($package in $packages) {
        "Removing Package Owners: $package"
        REG DELETE "HKLM\SOFTWARE-$RunId\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\$package\Owners" /f
    }
    REG UNLOAD "HKLM\SOFTWARE-$RunId"

    # Remove components with DISM
    foreach ($package in $packages) {
        "Removing Package: $package"
        dism /Image:$MountDir /Remove-Package /PackageName:$package /Quiet
    }
    
    # Remove appxs
    foreach ($appx in $appxs) {
        "Removing Provisioned Appx Package: $appx"
        dism /Image:$MountDir /Remove-ProvisionedAppxPackage /PackageName:$appx /Quiet
    }

    # Scheduled tasks cleanup

    # Services cleanup

    # Various registry hacks
                $RegMountPathSoftware   = "HKLM\SOFTWARE-$RunId"
                $RegMountPathSystem     = "HKLM\SYSTEM-$RunId"
                $RegMountPathSecurity   = "HKLM\SECURITY-$RunId"
                $RegMountPathSam        = "HKLM\SAM-$RunId"
                $RegMountPathComponents = "HKLM\COMPONENTS-$RunId"
                $RegMountPathDrivers    = "HKLM\DRIVERS-$RunId"
                $RegMountPathDefault    = "HKLM\DEFAULT-$RunId"
                $RegMountPathNTUser     = "HKLM\NTUSER-$RunId"
                $RegMountPathSchema     = "HKLM\SCHEMA-$RunId"
    REG LOAD    $RegMountPathSoftware     "$MountDir\Windows\System32\config\SOFTWARE"
    REG LOAD    $RegMountPathSystem       "$MountDir\Windows\System32\config\SYSTEM"
    REG LOAD    $RegMountPathSecurity     "$MountDir\Windows\System32\config\SECURITY"
    REG LOAD    $RegMountPathSam          "$MountDir\Windows\System32\config\SAM"
    REG LOAD    $RegMountPathComponents   "$MountDir\Windows\System32\config\COMPONENTS"
    REG LOAD    $RegMountPathDrivers      "$MountDir\Windows\System32\config\DRIVERS"
    REG LOAD    $RegMountPathDefault      "$MountDir\Windows\System32\config\DEFAULT"
    REG LOAD    $RegMountPathNTUser       "$MountDir\Users\Default\NTUSER.DAT"
    REG LOAD    $RegMountPathSchema       "$MountDir\Windows\System32\smi\store\Machine\SCHEMA.DAT"

    REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-310091" /f
    REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-310092" /f
    REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338380" /f
    REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338381" /f
  # REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338387" /f # Windows Spotlight lock screen, without Windows tips
    REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338388" /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SlideshowEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 # Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what's new and suggested
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d 0 # Show My People app suggestions
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 # Show suggestions occasionally in Start
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 # Get tips, tricks, and suggestions as you use Windows
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 # Show me suggested content in the Settings app
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 # Show me suggested content in the Settings app
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 # Show me suggested content in the Settings app
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 # Show suggestions in your timeline
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 # Suggest ways I can finish settings up my device to get the most out of Windows
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d 0
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /v "HideSCAMeetNow" /t REG_DWORD /d 1
    
    REG ADD    "$RegMountPathSoftware\Microsoft\PCHC" /v "PreviousUninstall" /t REG_DWORD /d 1 # Mark PC Health Check as previously uninstalled, so it doesn't get automatically installed
    REG ADD    "$RegMountPathSoftware\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0
    REG ADD    "$RegMountPathSoftware\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d 0

    REG UNLOAD  $RegMountPathSoftware
    REG UNLOAD  $RegMountPathSystem
    REG UNLOAD  $RegMountPathSecurity
    REG UNLOAD  $RegMountPathSam
    REG UNLOAD  $RegMountPathComponents
    REG UNLOAD  $RegMountPathDrivers
    REG UNLOAD  $RegMountPathDefault
    REG UNLOAD  $RegMountPathNTUser
    REG UNLOAD  $RegMountPathSchema

    If ($DryRun) {
        "The script is now paused to allow you to inspect the image."
        Pause
        dism /Unmount-Wim /MountDir:$MountDir /Discard
    }
    else {
        dism /Unmount-Wim /MountDir:$MountDir /Commit
    }
}

If (-not (Test-Path -Path $WimFile -PathType Leaf)) {
    Write-Error "WimFile must be a file"
    Exit
}
If (-not $PSBoundParameters.ContainsKey('Index')) {
    "Index is empty, gonna process all indexes"
    $ProcessAllImages = $True
}

# Generate Run ID
$WimFileFullPath = Get-ChildItem $WimFile
$stringAsStream = [System.IO.MemoryStream]::new()
$writer = [System.IO.StreamWriter]::new($stringAsStream)
$writer.write("nanFHna9$nR4BEe0")
$writer.write($WimFileFullPath)
$writer.Flush()
$stringAsStream.Position = 0
$RunId = (Get-FileHash -InputStream $stringAsStream | Select-Object Hash)."Hash".Substring(0, 16)


$RegMountPathSoftware   ="HKLM\SOFTWARE-$RunId"
$RegMountPathSystem     ="HKLM\SYSTEM-$RunId"
$RegMountPathSecurity   ="HKLM\SECURITY-$RunId"
$RegMountPathSam        ="HKLM\SAM-$RunId"
$RegMountPathComponents ="HKLM\COMPONENTS-$RunId"
$RegMountPathDrivers    ="HKLM\DRIVERS-$RunId"
$RegMountPathDefault    ="HKLM\DEFAULT-$RunId"
$RegMountPathNTUser     ="HKLM\NTUSER-$RunId"
$RegMountPathSchema     ="HKLM\SCHEMA-$RunId"

# If mount directory is not specified, generate one and create it
If (-not $PSBoundParameters.ContainsKey('MountDir')) {
    $MountDir = "C:\WIMMOUNT-" + $RunId
    New-Item -Path $MountDir -ItemType Directory | Out-Null
}

""
"Run ID: $RunID"
"Mount Directory: $MountDir"

If ($ProcessAllImages) {
    $ImageCount = (dism /Get-WimInfo /WimFile:$WimFile /English | Select-String -pattern "Index : .*" | Measure-Object -Line)."Lines"
    for ($Index=1; $Index -le $ImageCount; $Index++) {
        "Processing Image Index: $Index"
        processWimFileAtIndex -WimFile $WimFile -Index $Index -MountDir $MountDir -RunId $RunId
    }
} Else {
    processWimFileAtIndex -WimFile $WimFile -Index $Index -MountDir $MountDir -RunId $RunId
}

If (-not $PSBoundParameters.ContainsKey('MountDir')) {
    Remove-Item -Path $MountDir
}
