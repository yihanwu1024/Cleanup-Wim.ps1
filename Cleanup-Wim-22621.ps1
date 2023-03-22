Param (
    [Parameter(Mandatory)]
    [String]
    $WimFile,
    [Int]
    $Index,
    [String]
    $MountDir,
    [Switch]
    $Pause,
    [Switch]
    $DryRun
)


<#
  [FEATURES]
  - innovative HKCU load, no need for reg load / unload ping-pong; programs get the user profile
  - sets ownership privileges, high priority, and explorer support; get System if TI unavailable   
  - accepts special characters in paths for which default run as administrator fails
  - can copy-paste snippet directly in powershell console then use it manually
  [USAGE]
  - First copy-paste RunAsTI snippet before .ps1 script content
  - Then call it anywhere after to launch programs with arguments as TI
    RunAsTI regedit
    RunAsTI powershell '-noprofile -nologo -noexit -c [environment]::Commandline'
    RunAsTI cmd '/k "whoami /all & color e0"'
    RunAsTI "C:\System Volume Information"
  - Or just relaunch the script once if not already running as TI:
    if (((whoami /user)-split' ')[-1]-ne'S-1-5-18') {
      RunAsTI powershell "-f $($MyInvocation.MyCommand.Path) $($args[0]) $($args[1..99])"; return
    }
  2022.01.28: workaround for 11 release (22000) hindering explorer as TI
#>

#########################################################
# copy-paste RunAsTI snippet before .ps1 script content #
#########################################################

function RunAsTI ($cmd,$arg) { $id='RunAsTI'; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
} # lean & mean snippet by AveYo, 2022.01.28


$Packages = @(
"Microsoft-Windows-Not-Supported-On-LTSB-Package~31bf3856ad364e35~amd64~~10.0.22621.1"
"Microsoft-Windows-Not-Supported-On-LTSB-WOW64-Package~31bf3856ad364e35~amd64~~10.0.22621.1"
# Unlike Windows 10, removing Not-Supported-On-LTSB-Package here will not break Windows Update (as of January 2023).
#"Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~amd64~~10.0.22621.1"
#"Microsoft-Windows-OneDrive-Setup-WOW64-Package~31bf3856ad364e35~amd64~~10.0.22621.1"
)

$ProvisionedAppxPackages = @(
"Clipchamp.Clipchamp_2.2.8.0_neutral_~_yxz26nhyzhsrt"
"Microsoft.549981C3F5F10_3.2204.14815.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.BingNews_4.2.27001.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.BingWeather_4.53.33420.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.GamingApp_2021.427.138.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.GetHelp_10.2201.421.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.Getstarted_2021.2204.1.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.MicrosoftOfficeHub_18.2204.1141.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.MicrosoftSolitaireCollection_4.12.3171.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.MicrosoftStickyNotes_4.2.2.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.People_2020.901.1724.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.PowerAutomateDesktop_10.0.3735.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.StorePurchaseApp_12008.1001.113.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.Todos_2.54.42772.0_neutral_~_8wekyb3d8bbwe"
"microsoft.windowscommunicationsapps_16005.14326.20544.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.WindowsFeedbackHub_2022.106.2230.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.WindowsMaps_2022.2202.6.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.WindowsStore_22204.1400.4.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.Xbox.TCUI_1.23.28004.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.XboxGameOverlay_1.47.2385.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.XboxGamingOverlay_2.622.3232.0_neutral_~_8wekyb3d8bbwe"  # Screen recording available in Snipping Tool after March 2023 update
"Microsoft.XboxIdentityProvider_12.50.6001.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.XboxSpeechToTextOverlay_1.17.29001.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.YourPhone_1.22022.147.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.ZuneVideo_2019.22020.10021.0_neutral_~_8wekyb3d8bbwe"
"MicrosoftCorporationII.MicrosoftFamily_0.1.28.0_neutral_~_8wekyb3d8bbwe"
"MicrosoftCorporationII.QuickAssist_2022.414.1758.0_neutral_~_8wekyb3d8bbwe"
"MicrosoftWindows.Client.WebExperience_421.20070.195.0_neutral_~_cw5n1h2txyewy"  # Will be reinstalled in March 2023 update
)


function processWimFileAtIndex {
    dism /Mount-Wim /WimFile:$WimFile /Index:$Index /MountDir:$MountDir

    # Preprocess registry to remove packages with DISM
    REG LOAD "HKLM\SOFTWARE-$RunId" "$MountDir\Windows\System32\config\SOFTWARE"
    foreach ($package in $Packages) {
        "Removing Package Owners: $package"
        REG DELETE "HKLM\SOFTWARE-$RunId\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\$package\Owners" /f
    }
    REG UNLOAD "HKLM\SOFTWARE-$RunId"

    # Remove components with DISM
    foreach ($package in $Packages) {
        "Removing Package: $package"
        dism /Image:$MountDir /Remove-Package /PackageName:$package /Quiet
    }
    
    # Remove appxs
    foreach ($appx in $ProvisionedAppxPackages) {
        "Removing Provisioned Appx Package: $appx"
        dism /Image:$MountDir /Remove-ProvisionedAppxPackage /PackageName:$appx /Quiet
    }

    # Scheduled tasks cleanup

    # Services cleanup

    # Various registry hacks
                $RegMountPathSoftware     = "HKLM\SOFTWARE-$RunId"
                $RegMountPathSystem       = "HKLM\SYSTEM-$RunId"
                $RegMountPathSecurity     = "HKLM\SECURITY-$RunId"
                $RegMountPathSam          = "HKLM\SAM-$RunId"
                $RegMountPathComponents   = "HKLM\COMPONENTS-$RunId"
                $RegMountPathDrivers      = "HKLM\DRIVERS-$RunId"
                $RegMountPathDefault      = "HKLM\DEFAULT-$RunId"
                $RegMountPathSchema       = "HKLM\SCHEMA-$RunId"
                $RegMountPathNTUser       = "HKLM\NTUSER-$RunId"
    REG LOAD    $RegMountPathSoftware     "$MountDir\Windows\System32\config\SOFTWARE"
    REG LOAD    $RegMountPathSystem       "$MountDir\Windows\System32\config\SYSTEM"
    REG LOAD    $RegMountPathSecurity     "$MountDir\Windows\System32\config\SECURITY"
    REG LOAD    $RegMountPathSam          "$MountDir\Windows\System32\config\SAM"
    REG LOAD    $RegMountPathComponents   "$MountDir\Windows\System32\config\COMPONENTS"
    REG LOAD    $RegMountPathDrivers      "$MountDir\Windows\System32\config\DRIVERS"
    REG LOAD    $RegMountPathDefault      "$MountDir\Windows\System32\config\DEFAULT"
    REG LOAD    $RegMountPathSchema       "$MountDir\Windows\System32\smi\store\Machine\SCHEMA.DAT"
    REG LOAD    $RegMountPathNTUser       "$MountDir\Users\Default\NTUSER.DAT"

  # REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
  #  REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-310091" /f
  #  REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-310092" /f
  #  REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338380" /f
  #  REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338381" /f
  ## REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338387" /f # Windows Spotlight lock screen, with Windows tips or image description
  #  REG DELETE "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338388" /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SlideshowEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 # Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what's new and suggested
  # REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d 0 # Show My People app suggestions (Deprecated)
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 # Windows Spotlight wallpapers and tips
  # REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 # Show suggestions occasionally in Start (Deprecated)
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 # Get tips, tricks, and suggestions as you use Windows
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 # Show me suggested content in the Settings app
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 # Show me suggested content in the Settings app
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 # Show me suggested content in the Settings app
  # REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 # Show suggestions in your timeline (Deprecated)
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-80000326Enabled" /t REG_DWORD /d 0 # Desktop wallpaper from Bing
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 # Suggest ways I can finish settings up my device to get the most out of Windows
  # REG ADD    "$RegMountPathNTUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 # Turn off Widgets per user
    
    REG ADD    "$RegMountPathNTUser\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1


    REG ADD    "$RegMountPathSoftware\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d 2 # Turn off automatic updates from Microsoft Store
  # REG ADD    "$RegMountPathSoftware\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d 2 # Turn off automatic updates from Microsoft Store
  # REG ADD    "$RegMountPathSoftware\Policies\Microsoft\WindowsStore" /v "RemoveWindowsStore" /t REG_DWORD /d 2 # Turn off Microsoft Store
    REG ADD    "$RegMountPathSoftware\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d 3
    REG ADD    "$RegMountPathSoftware\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 # Disable Widgets with Group Policy
    REG ADD    "$RegMountPathSoftware\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d 0 # Disable Edge Bing button with Group Policy
    
  # REG ADD    "$RegMountPathSoftware\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0
  # reg add    "$RegMountPathSoftware\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
  # reg add    "$RegMountPathSoftware\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
  # reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f
  # reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
  # reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
  # reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
  # reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
  # reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
  # reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
  # reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
  # reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
  # reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
  # reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
  # reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
  # reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
  # reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
  # reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
  # reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
  # reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
  # reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f

  # $args="REG","ADD","$RegMountPathSoftware\Microsoft\Windows\CurrentVersion\Communications","/v","ConfigureChatAutoInstall","/t","REG_DWORD","/d","0","/f"
  # RunAsTI $args[0] $args[1..99]

       
    RunAsTI "REG" "ADD","$RegMountPathSoftware\Microsoft\Windows\CurrentVersion\Communications","/v","ConfigureChatAutoInstall","/t","REG_DWORD","/d","0","/f"
    timeout /t 5 # Make sure RunAsTI finishes

  # REG ADD    "$RegMountPathSoftware\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d 0 /f # Has to be added as TrustedInstaller
    REG ADD    "$RegMountPathSystem\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{A852AB92-E273-433C-B2BD-4990F5ED3BB1}" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=Out|App=%SystemRoot%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe|Name=Block StartMenuExperienceHost|" /f # Block StartMenuExperienceHost from using any network to disable promoted apps



    REG UNLOAD  $RegMountPathSoftware
    REG UNLOAD  $RegMountPathSystem
    REG UNLOAD  $RegMountPathSecurity
    REG UNLOAD  $RegMountPathSam
    REG UNLOAD  $RegMountPathComponents
    REG UNLOAD  $RegMountPathDrivers
    REG UNLOAD  $RegMountPathDefault
    REG UNLOAD  $RegMountPathSchema
    REG UNLOAD  $RegMountPathNTUser

    If ($Pause) {
        "The script is now paused to allow you to inspect the image."
        Pause
    }
    If ($DryRun) {
        dism /Unmount-Wim /MountDir:$MountDir /Discard
    }
    Else {
        dism /Unmount-Wim /MountDir:$MountDir /Commit
    }
}

If (-not (Test-Path -Path $WimFile -PathType Leaf)) {
    Write-Error "WimFile must be a file"
    Exit
}
If (-not $PSBoundParameters.ContainsKey('Index')) {
    "Index is empty, gonna process all indexes"
    $ProcessAllIndexes = $True
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
If ($DryRun) { $Pause = True }


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

If ($ProcessAllIndexes) {
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
