<#
.Synopsis
    ImageFactory 3.3
.DESCRIPTION
    ImageFactory 3.3
.EXAMPLE
    ImageFactoryV3-Verify-ShowContent.ps1
.NOTES
    Created:	 2016-11-24
    Version:	 3.1

    Updated:	 2017-02-23
    Version:	 3.2

    Updated:	 2017-09-27
    Version:	 3.3

    Author - Mikael Nystrom
    Twitter: @mikael_nystrom
    Blog   : http://deploymentbunny.com

    Disclaimer:
    This script is provided 'AS IS' with no warranties, confers no rights and 
    is not supported by the author.

    This script uses the PsIni module:
    Blog		: http://oliver.lipkau.net/blog/ 
	Source		: https://github.com/lipkau/PsIni
	http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91

.LINK
    http://www.deploymentbunny.com
#>
Import-Module C:\Setup\Functions\VIAHypervModule.psm1 -Force -Verbose

$adminPassword = "P@ssw0rd"
$domainName = "VIAMONSTRA"
$DomainAdminPassword = "P@ssw0rd"
$ReportPath = "C:\Setup\ImageFactoryV3ForHyper-V"
$LocalCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ".\Administrator", (ConvertTo-SecureString $adminPassword -AsPlainText -Force)
$DomainCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($domainName)\Administrator", (ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force)

$Items = Get-VM | Where-Object -Property Notes -Like -Value "VALIDATE*"
foreach($item in $items){
    Start-VM $item
    Wait-VIAVMIsRunning -VMname $item.Name
    Wait-VIAVMHaveICLoaded -VMname $item.Name
    Wait-VIAVMHaveIP -VMname $item.Name
    Wait-VIAVMHavePSDirect -VMname $item.Name -Credentials $LocalCred

    $Result = Invoke-Command -VMName $item.Name -Credential $LocalCred -ScriptBlock {
        $Hostname = Hostname.exe
        $Microsoft_BDD_Info = Get-WMIObject –Class Microsoft_BDD_Info | Select-Object CaptureMethod,CaptureTaskSequenceID,CaptureTaskSequenceName,CaptureTaskSequenceVersion,CaptureTimestamp,CaptureToolkitVersion
        $Win32_OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption,Buildnumber,CodeSet,CurrentTimeZone,MUILanguages,OSLanguage,Version
        $Win32_QuickFixEngineering = Get-WmiObject -class Win32_QuickFixEngineering | Select-Object HotFixID,Description,InstalledOn,InstalledBy
        $CurrentVersionUninstall = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Where-Object DisplayName -ne $null | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        $AppxPackage = Get-AppxPackage | Select-Object Name,Version
        $WindowsOptionalFeature = Get-WindowsOptionalFeature -Online -LogPath "C:\dismlog.log" | Where-Object State -EQ Enabled | Select-Object FeatureName


        $Hash =  [ordered]@{ 
            HostName = $($Hostname); 
            CaptureMethod = $($Microsoft_BDD_Info.CaptureMethod);
            CaptureTaskSequenceID = $($Microsoft_BDD_Info.CaptureTaskSequenceID);
            CaptureTaskSequenceName = $($Microsoft_BDD_Info.CaptureTaskSequenceName);
            CaptureTaskSequenceVersion = $($Microsoft_BDD_Info.CaptureTaskSequenceVersion);
            CaptureTimestamp = $($Microsoft_BDD_Info.CaptureTimestamp);
            CaptureToolkitVersion = $($Microsoft_BDD_Info.CaptureToolkitVersion);
            Caption = $($Win32_OperatingSystem.Caption);
            Buildnumber = $($Win32_OperatingSystem.Buildnumber);
            CodeSet = $($Win32_OperatingSystem.CodeSet);
            CurrentTimeZone = $($Win32_OperatingSystem.CurrentTimeZone);
            MUILanguages = $($Win32_OperatingSystem.MUILanguages);
            OSLanguage = $($Win32_OperatingSystem.OSLanguage);
            Version = $($Win32_OperatingSystem.Version);
            Win32_QuickFixEngineering = $($Win32_QuickFixEngineering);
            CurrentVersionUninstall = $($CurrentVersionUninstall);
            AppxPackage = $($AppxPackage);
            WindowsOptionalFeature = $($WindowsOptionalFeature);
            }
        $Data = New-Object PSObject -Property $Hash
        Return $Data
    }
    Stop-VM -VM $item
    
    #Create Report
    $ReportFile = New-Item -Path "$ReportPath\Report$($DateTime = (Get-Date).ToString('yyyyMMdd'))-$($Result.HostName).txt" -type File -Force
    Set-Content -Path $ReportFile -Value "HOSTNAME: $($Result.HostName)"
    Add-Content -Path $ReportFile -Value "CaptureMethod :$($Result.CaptureMethod)"
    Add-Content -Path $ReportFile -Value "CaptureTaskSequenceID: $($Result.CaptureTaskSequenceID)"
    Add-Content -Path $ReportFile -Value "CaptureTaskSequenceName: $($Result.CaptureTaskSequenceName)"
    Add-Content -Path $ReportFile -Value "CaptureTaskSequenceVersion: $($Result.CaptureTaskSequenceVersion)"
    Add-Content -Path $ReportFile -Value "CaptureTimestamp: $($Result.CaptureTimestamp)"
    Add-Content -Path $ReportFile -Value "CaptureToolkitVersion: $($Result.CaptureToolkitVersion)"
    Add-Content -Path $ReportFile -Value "Caption: $($Result.Caption)"
    Add-Content -Path $ReportFile -Value "Buildnumber: $($Result.Buildnumber)"
    Add-Content -Path $ReportFile -Value "CodeSet: $($Result.CodeSet)"
    Add-Content -Path $ReportFile -Value "CurrentTimeZone: $($Result.CurrentTimeZone)"
    Add-Content -Path $ReportFile -Value "MUILanguages: $($Result.MUILanguages)"
    Add-Content -Path $ReportFile -Value "OSLanguage: $($Result.OSLanguage)"
    Add-Content -Path $ReportFile -Value "Version: $($Result.Version)"
    foreach($Item in $Result.AppxPackage){
        Add-Content -Path $ReportFile -Value "AppX: $($Item.Name) - $($Item.Version)"
    }
    foreach($Item in $Result.Win32_QuickFixEngineering){
        Add-Content -Path $ReportFile -Value "HotFix: $($Item.HotFixID) - $($Item.Description) - $($Item.InstalledOn) - $($Item.InstalledBy)"
    }
    foreach($Item in $Result.CurrentVersionUninstall){
        Add-Content -Path $ReportFile -Value "App: $($Item.DisplayName) - $($Item.DisplayVersion) - $($Item.Publisher) - $($Item.InstallDate)"
    }
    foreach($Item in $Result.WindowsOptionalFeature){
        Add-Content -Path $ReportFile -Value "Feature: $($Item.FeatureName)"
    }
}


