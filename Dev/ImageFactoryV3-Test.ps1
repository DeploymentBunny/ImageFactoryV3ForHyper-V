<#
.Synopsis
    ImageFactory 3.1
.DESCRIPTION
    ImageFactory 3.1
.EXAMPLE
    ImageFactoryV3-Build.ps1
.NOTES
    Created:	 2016-11-24
    Version:	 3.1

    Author - Mikael Nystrom
    Twitter: @mikael_nystrom
    Blog   : http://deploymentbunny.com

    Disclaimer:
    This script is provided 'AS IS' with no warranties, confers no rights and 
    is not supported by the authors or Deployment Artist.

    This script uses the PsIni module:
    Blog		: http://oliver.lipkau.net/blog/ 
	Source		: https://github.com/lipkau/PsIni
	http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91

.LINK
    http://www.deploymentbunny.com
#>
[cmdletbinding(SupportsShouldProcess=$True)]
Param(
)

#Set start time
$StartTime = Get-Date

Function Get-VIARefTaskSequence
{
    Param(
    $RefTaskSequenceFolder
    )
    $RefTaskSequences = Get-ChildItem $RefTaskSequenceFolder
    Foreach($RefTaskSequence in $RefTaskSequences){
        New-Object PSObject -Property @{ 
        TaskSequenceID = $RefTaskSequence.ID
        Name = $RefTaskSequence.Name
        Comments = $RefTaskSequence.Comments
        Version = $RefTaskSequence.Version
        Enabled = $RefTaskSequence.enable
        LastModified = $RefTaskSequence.LastModifiedTime
        } 
    }
}
Function Test-VIAHypervConnection
{
    Param(
        $Computername,
        $ISOFolder,
        $VMFolder,
        $VMSwitchName
    )
    #Verify SMB access
    $Result = Test-NetConnection -ComputerName $Computername -CommonTCPPort SMB
    If ($Result.TcpTestSucceeded -eq $true){Write-Verbose "SMB Connection to $Computername is ok"}else{Write-Warning "SMB Connection to $Computername is NOT ok";Return $False}

    #Verify WinRM access
    $Result = Test-NetConnection -ComputerName $Computername -CommonTCPPort WINRM
    If ($Result.TcpTestSucceeded -eq $true){Write-Verbose "WINRM Connection to $Computername is ok"}else{Write-Warning "WINRM Connection to $Computername is NOT ok";Return $False}

    #Verify that Microsoft-Hyper-V-Management-PowerShell is installed
    Invoke-Command -ComputerName $Computername -ScriptBlock {
        $Result = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell)
        Write-Verbose "$($Result.DisplayName) is $($Result.State)"
        If($($Result.State) -ne "Enabled"){Write-Warning "$($Result.DisplayName) is not Enabled";Return $False}
    }

    #Verify that Microsoft-Hyper-V-Management-PowerShell is installed
    Invoke-Command -ComputerName $Computername -ScriptBlock {
        $Result = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V)
        If($($Result.State) -ne "Enabled"){Write-Warning "$($Result.DisplayName) is not Enabled";Return $False}
    }

    #Verify that Hyper-V is running
    Invoke-Command -ComputerName $Computername -ScriptBlock {
        $Result = (Get-Service -Name vmms)
        Write-Verbose "$($Result.DisplayName) is $($Result.Status)"
        If($($Result.Status) -ne "Running"){Write-Warning "$($Result.DisplayName) is not Running";Return $False}
    }

    #Verify that the ISO Folder is created
    Invoke-Command -ComputerName $Computername -ScriptBlock {
        Param(
        $ISOFolder
        )
        $result = New-Item -Path $ISOFolder -ItemType Directory -Force
    } -ArgumentList $ISOFolder

    #Verify that the VM Folder is created
    Invoke-Command -ComputerName $Computername -ScriptBlock {
        Param(
        $VMFolder
        )
        $result = New-Item -Path $VMFolder -ItemType Directory -Force
    } -ArgumentList $VMFolder

    #Verify that the VMSwitch exists
    Invoke-Command -ComputerName $Computername -ScriptBlock {
        Param(
        $VMSwitchName
        )
        if(((Get-VMSwitch | Where-Object -Property Name -EQ -Value $VMSwitchName).count) -eq "1"){Write-Verbose "Found $VMSwitchName"}else{Write-Warning "No switch with the name $VMSwitchName found";Return $False}
    } -ArgumentList $VMSwitchName
    Return $True
}
Function Global:Update-Log
{
    Param(
    [Parameter(
        Mandatory=$true, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0
    )]
    [string]$Data,

    [Parameter(
        Mandatory=$false, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0
    )]
    [string]$Solution = $Solution,

    [Parameter(
        Mandatory=$false, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1
    )]
    [validateset('Information','Warning','Error')]
    [string]$Class = "Information"

    )
    $LogString = "$Solution, $Data, $Class, $(Get-Date)"
    $HostString = "$Solution, $Data, $(Get-Date)"
    
    Add-Content -Path $Log -Value $LogString
    switch ($Class)
    {
        'Information'{
            Write-Host $HostString -ForegroundColor Gray
            }
        'Warning'{
            Write-Host $HostString -ForegroundColor Yellow
            }
        'Error'{
            Write-Host $HostString -ForegroundColor Red
            }
        Default {}
    }
}

#Inititial Settings
Clear-Host
$Log = "C:\Setup\ImageFactoryV3ForHyper-V\log.txt"
$XMLFile = "C:\setup\ImageFactoryV3ForHyper-V\ImageFactoryV3.xml"
$Solution = "IMF32"
Update-Log -Data "Imagefactory 3.2 (Hyper-V)"
Update-Log -Data "Logfile is $Log"
Update-Log -Data "XMLfile is $XMLfile"

#Importing modules
Update-Log -Data "Importing modules"
Import-Module 'C:\Program Files\Microsoft Deployment Toolkit\Bin\MicrosoftDeploymentToolkit.psd1' -ErrorAction Stop -WarningAction Stop

#Read Settings from XML
Update-Log -Data "Reading from $XMLFile"
[xml]$Settings = Get-Content $XMLFile -ErrorAction Stop -WarningAction Stop

#Verify Connection to DeploymentRoot
Update-Log -Data "Verify Connection to DeploymentRoot"
$Result = Test-Path -Path $Settings.Settings.MDT.DeploymentShare
If($Result -ne $true){Update-Log -Data "Cannot access $($Settings.Settings.MDT.DeploymentShare) , will break";break}

#Connect to MDT
Update-Log -Data "Connect to MDT"
$Root = $Settings.Settings.MDT.DeploymentShare
if((Test-Path -Path MDT:) -eq $false){
    $MDTPSDrive = New-PSDrive -Name MDT -PSProvider MDTProvider -Root $Root -ErrorAction Stop
    Update-Log -Data "Connected to $($MDTPSDrive.Root)"
}

#Get MDT Settings
Update-Log -Data "Get MDT Settings"
$MDTSettings = Get-ItemProperty MDT:

#Get TaskSequences
Update-Log -Data "Get TaskSequences"
$RefTaskSequenceIDs = (Get-VIARefTaskSequence -RefTaskSequenceFolder "MDT:\Task Sequences\$($Settings.Settings.MDT.RefTaskSequenceFolderName)" | where Enabled -EQ $true).TasksequenceID
if($RefTaskSequenceIDs.count -eq 0){
    Update-Log -Data "Sorry, could not find any TaskSequences to work with"
    BREAK
    }
Update-Log -Data "Found $($RefTaskSequenceIDs.count) TaskSequences to work on"

#Get detailed info
Update-Log -Data "Get detailed info about the task sequences"
$Result = Get-VIARefTaskSequence -RefTaskSequenceFolder "MDT:\Task Sequences\$($Settings.Settings.MDT.RefTaskSequenceFolderName)" | where Enabled -EQ $true
foreach($obj in ($Result | Select-Object TaskSequenceID,Name,Version)){
    $data = "$($obj.TaskSequenceID) $($obj.Name) $($obj.Version)"
    Update-Log -Data $data
}

$Result | Select-Object *


#Show the WIMfiles:
Update-Log -Data "Show the WIM's"
Foreach($Ref in $RefTaskSequenceIDs){
    $FullRefPath = $(("$Root\Captures\$ref") + ".wim")
    if((Test-Path -Path $FullRefPath) -eq $true){
        $Item = Get-Item -Path $FullRefPath
        Update-Log -Data "WIM: $($Item.FullName)"
    }else{
        Update-Log -Data "Could not find $FullRefPath, something wnet wrong" -Class Warning 
    }
}

#Verify Connection to Hyper-V host
Update-Log -Data "Verify Connection to Hyper-V host"
$Result = Test-VIAHypervConnection -Computername $Settings.Settings.HyperV.Computername -ISOFolder $Settings.Settings.HyperV.ISOLocation -VMFolder $Settings.Settings.HyperV.VMLocation -VMSwitchName $Settings.Settings.HyperV.SwitchName
If($Result -ne $true){Update-Log -Data "$($Settings.Settings.HyperV.Computername) is not ready, will break";break}

#Create the VM's on Host
Update-Log -Data "Create the VM's on Host"
Foreach($Ref in $RefTaskSequenceIDs){
    $VMName = $ref
    $VMMemory = [int]$($Settings.Settings.HyperV.StartUpRAM) * 1GB
    $VMPath = $($Settings.Settings.HyperV.VMLocation)
    $VMBootimage = $($Settings.Settings.HyperV.ISOLocation) + "\" +  $($MDTImage | Split-Path -Leaf)
    $VMVHDSize = [int]$($Settings.Settings.HyperV.VHDSize) * 1GB
    $VMVlanID = $($Settings.Settings.HyperV.VLANID)
    $VMVCPU = $($Settings.Settings.HyperV.NoCPU)
    $VMSwitch = $($Settings.Settings.HyperV.SwitchName)
    Invoke-Command -ComputerName $($Settings.Settings.HyperV.Computername) -ScriptBlock {
    Param(
        $VMName,
        $VMMemory,
        $VMPath,
        $VMBootimage,
        $VMVHDSize,
        $VMVlanID,
        $VMVCPU,
        $VMSwitch
    )        
    Write-Verbose "Hyper-V host is $env:COMPUTERNAME"
    Write-Verbose "Working on $VMName"
    #Check if VM exist
    if(!((Get-VM | Where-Object -Property Name -EQ -Value $VMName).count -eq 0)){Write-Warning -Message "VM exist";Break}

    #Create VM 
    $VM = New-VM -Name $VMName -MemoryStartupBytes $VMMemory -Path $VMPath -NoVHD -Generation 1
    Write-Verbose "$($VM.Name) is created"

    #Connect to VMSwitch 
    Connect-VMNetworkAdapter -VMNetworkAdapter (Get-VMNetworkAdapter -VM $VM) -SwitchName $VMSwitch
    Write-Verbose "$($VM.Name) is connected to $VMSwitch"

    #Set vCPU
    if($VMVCPU -ne "1"){
        $Result = Set-VMProcessor -Count $VMVCPU -VM $VM -Passthru
        Write-Verbose "$($VM.Name) has $($Result.count) vCPU"
    }
    
    #Set VLAN
    If($VMVlanID -ne "0"){
        $Result = Set-VMNetworkAdapterVlan -VlanId $VMVlanID -Access -VM $VM -Passthru
        Write-Verbose "$($VM.Name) is configured for VLANid $($Result.NativeVlanId)"
    }

    #Create empty disk
    $VHD = $VMName + ".vhdx"
    $result = New-VHD -Path "$VMPath\$VMName\Virtual Hard Disks\$VHD" -SizeBytes $VMVHDSize -Dynamic -ErrorAction Stop
    Write-Verbose "$($result.Path) is created for $($VM.Name)"

    #Add VHDx
    $result = Add-VMHardDiskDrive -VMName $VMName -Path "$VMPath\$VMName\Virtual Hard Disks\$VHD" -Passthru
    Write-Verbose "$($result.Path) is attached to $VMName"
    
    #Connect ISO 
    $result = Set-VMDvdDrive -VMName $VMName -Path $VMBootimage -Passthru
    Write-Verbose "$($result.Path) is attached to $VMName"

    #Set Notes
    Set-VM -VMName $VMName -Notes "REFIMAGE"

    } -ArgumentList $VMName,$VMMemory,$VMPath,$VMBootimage,$VMVHDSize,$VMVlanID,$VMVCPU,$VMSwitch
}

#Start VM's on Host
Update-Log -Data "Start VM's on Host"
Update-Log -Data "ConcurrentRunningVMs is set to: $ConcurrentRunningVMs"
Invoke-Command -ComputerName $($Settings.Settings.HyperV.Computername) -ScriptBlock {
    Param(
        $ConcurrentRunningVMs,
        $MDTServer = ""
    ) 
    #Import Function
    Function Get-MDTOData{
    <#
    .Synopsis
        Function for getting MDTOdata
    .DESCRIPTION
        Function for getting MDTOdata
    .EXAMPLE
        Get-MDTOData -MDTMonitorServer MDTSERVER01
    .NOTES
        Created:     2016-03-07
        Version:     1.0
 
        Author - Mikael Nystrom
        Twitter: @mikael_nystrom
        Blog   : http://deploymentbunny.com
 
    .LINK
        http://www.deploymentbunny.com
    #>
    Param(
    $MDTMonitorServer
    ) 
    $URL = "http://" + $MDTMonitorServer + ":9801/MDTMonitorData/Computers"
    $Data = Invoke-RestMethod $URL
    foreach($property in ($Data.content.properties) ){
        $Hash =  [ordered]@{ 
            Name = $($property.Name); 
            PercentComplete = $($property.PercentComplete.’#text’); 
            Warnings = $($property.Warnings.’#text’); 
            Errors = $($property.Errors.’#text’); 
            DeploymentStatus = $( 
            Switch($property.DeploymentStatus.’#text’){ 
                1 { "Active/Running"} 
                2 { "Failed"} 
                3 { "Successfully completed"} 
                Default {"Unknown"} 
                }
            );
            StepName = $($property.StepName);
            TotalSteps = $($property.TotalStepS.'#text')
            CurrentStep = $($property.CurrentStep.'#text')
            DartIP = $($property.DartIP);
            DartPort = $($property.DartPort);
            DartTicket = $($property.DartTicket);
            VMHost = $($property.VMHost.'#text');
            VMName = $($property.VMName.'#text');
            LastTime = $($property.LastTime.'#text') -replace "T"," ";
            StartTime = $($property.StartTime.’#text’) -replace "T"," "; 
            EndTime = $($property.EndTime.’#text’) -replace "T"," "; 
            }
        New-Object PSObject -Property $Hash
        }
    }

    #Get the VMs as Objects
    $RefVMs = Get-VM | Where-Object -Property Notes -Like -Value "REFIMAGE"
    foreach($RefVM in $RefVMs){
        Write-Verbose "REFVM $($RefVM.Name) is deployed on $($RefVM.ComputerName) at $($refvm.ConfigurationLocation)"
    }

    #Get the VMs as Objects
    $RefVMs = Get-VM | Where-Object -Property Notes -Like -Value "REFIMAGE"
    foreach($RefVM in $RefVMs){
    $StartedVM = Start-VM -VMName $RefVM.Name
    Write-Verbose "Starting $($StartedVM.name)"
    Do
        {
            $RunningVMs = $((Get-VM | Where-Object -Property Notes -EQ -Value "REFIMAGE" | Where-Object -Property State -EQ -Value Running))
            foreach($RunningVM in $RunningVMs){
                if($MDTServer -eq ""){
                    Write-Output "Currently running VM's : $($RunningVMs.Name) at $(Get-Date)"
                }
                else{
                    Get-MDTOData -MDTMonitorServer $MDTServer | Where-Object -Property Name -EQ -Value $RunningVM.Name | Select-Object Name,PercentComplete,Warnings,Errors,DeploymentStatus,StartTime,Lasttime | FT
                }
            }
            Start-Sleep -Seconds "30"
        }
    While((Get-VM | Where-Object -Property Notes -EQ -Value "REFIMAGE" | Where-Object -Property State -EQ -Value Running).Count -gt ($ConcurrentRunningVMs - 1))
    }
} -ArgumentList $($Settings.Settings.ConcurrentRunningVMs),$env:COMPUTERNAME

#Wait until they are done
Update-Log -Data "Wait until they are done"
Invoke-Command -ComputerName $($Settings.Settings.HyperV.Computername) -ScriptBlock {
    Param(
    $MDTServer = ""
    )
    #Import Function
    Function Get-MDTOData{
    <#
    .Synopsis
        Function for getting MDTOdata
    .DESCRIPTION
        Function for getting MDTOdata
    .EXAMPLE
        Get-MDTOData -MDTMonitorServer MDTSERVER01
    .NOTES
        Created:     2016-03-07
        Version:     1.0
 
        Author - Mikael Nystrom
        Twitter: @mikael_nystrom
        Blog   : http://deploymentbunny.com
 
    .LINK
        http://www.deploymentbunny.com
    #>
    Param(
    $MDTMonitorServer
    ) 
    $URL = "http://" + $MDTMonitorServer + ":9801/MDTMonitorData/Computers"
    $Data = Invoke-RestMethod $URL
    foreach($property in ($Data.content.properties) ){
        $Hash =  [ordered]@{ 
            Name = $($property.Name); 
            PercentComplete = $($property.PercentComplete.’#text’); 
            Warnings = $($property.Warnings.’#text’); 
            Errors = $($property.Errors.’#text’); 
            DeploymentStatus = $( 
            Switch($property.DeploymentStatus.’#text’){ 
                1 { "Active/Running"} 
                2 { "Failed"} 
                3 { "Successfully completed"} 
                Default {"Unknown"} 
                }
            );
            StepName = $($property.StepName);
            TotalSteps = $($property.TotalStepS.'#text')
            CurrentStep = $($property.CurrentStep.'#text')
            DartIP = $($property.DartIP);
            DartPort = $($property.DartPort);
            DartTicket = $($property.DartTicket);
            VMHost = $($property.VMHost.'#text');
            VMName = $($property.VMName.'#text');
            LastTime = $($property.LastTime.'#text') -replace "T"," ";
            StartTime = $($property.StartTime.’#text’) -replace "T"," "; 
            EndTime = $($property.EndTime.’#text’) -replace "T"," "; 
            }
        New-Object PSObject -Property $Hash
        }
    }
    Do{
        $RunningVMs = $((Get-VM | Where-Object -Property Notes -EQ -Value "REFIMAGE" | Where-Object -Property State -EQ -Value Running))
            foreach($RunningVM in $RunningVMs){
                if($MDTServer -eq ""){
                    Write-Output "Currently running VM's : $($RunningVMs.Name) at $(Get-Date)"
                }
                else{
                    Get-MDTOData -MDTMonitorServer $MDTServer | Where-Object -Property Name -EQ -Value $RunningVM.Name | Select-Object Name,PercentComplete,Warnings,Errors,DeploymentStatus,StartTime,Lasttime | FT
                }
            }
            Start-Sleep -Seconds "30"
    }until((Get-VM | Where-Object -Property Notes -EQ -Value "REFIMAGE" | Where-Object -Property State -EQ -Value Running).count -eq '0')
} -ArgumentList $MDTServer

#Cleanup VMs
Update-Log -Data "Cleanup VMs"
Invoke-Command -ComputerName $($Settings.Settings.HyperV.Computername) -ScriptBlock {
    $RefVMs = Get-VM | Where-Object -Property Notes -EQ -Value "REFIMAGE" 
    Foreach($RefVM in $RefVMs){
        $VM = Get-VM -VMName $RefVM.Name
        Write-Verbose "Deleting $($VM.Name) on $($VM.Computername) at $($VM.ConfigurationLocation)"
        Remove-VM -VM $VM -Force
        Remove-Item -Path $VM.ConfigurationLocation -Recurse -Force
    }
}

#Cleanup MDT Monitoring data
Update-Log -Data "Cleanup MDT Monitoring data"
if($EnableMDTMonitoring -eq $True){
    foreach($RefTaskSequenceID in $RefTaskSequenceIDs){
        Get-MDTMonitorData -Path MDT: | Where-Object -Property Name -EQ -Value $RefTaskSequenceID | Remove-MDTMonitorData -Path MDT:
    }
}



#Final update
$Endtime = Get-Date
Update-Log -Data "The script took $(($Endtime - $StartTime).Days):Days $(($Endtime - $StartTime).Hours):Hours $(($Endtime - $StartTime).Minutes):Minutes to complete."


