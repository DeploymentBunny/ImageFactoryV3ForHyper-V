<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>



[cmdletbinding(SupportsShouldProcess=$True)]

Param(
)

BREAK

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
    If ($Result.TcpTestSucceeded -eq $true){Write-Verbose "SMB Connection to $Computername is ok"}else{Write-Warning "SMB Connection to $Computername is NOT ok";BREAK}

    #Verify WinRM access
    $Result = Test-NetConnection -ComputerName $Computername -CommonTCPPort WINRM
    If ($Result.TcpTestSucceeded -eq $true){Write-Verbose "WINRM Connection to $Computername is ok"}else{Write-Warning "WINRM Connection to $Computername is NOT ok";BREAK}

    #Verify that Microsoft-Hyper-V-Management-PowerShell is installed
    Invoke-Command -ComputerName $Computername -ScriptBlock {
        $Result = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell)
        Write-Verbose "$($Result.DisplayName) is $($Result.State)"
        If($($Result.State) -ne "Enabled"){Write-Warning "$($Result.DisplayName) is not Enabled";BREAK}
    }

    #Verify that Microsoft-Hyper-V-Management-PowerShell is installed
    Invoke-Command -ComputerName $Computername -ScriptBlock {
        $Result = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V)
        If($($Result.State) -ne "Enabled"){Write-Warning "$($Result.DisplayName) is not Enabled";BREAK}
    }

    #Verify that Hyper-V is running
    Invoke-Command -ComputerName $Computername -ScriptBlock {
        $Result = (Get-Service -Name vmms)
        Write-Verbose "$($Result.DisplayName) is $($Result.Status)"
        If($($Result.Status) -ne "Running"){Write-Warning "$($Result.DisplayName) is not Running";BREAK}
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
        if(((Get-VMSwitch | Where-Object -Property Name -EQ -Value $VMSwitchName).count) -eq "1"){Write-Verbose "Found $VMSwitchName"}else{Write-Warning "No swtch with the name $VMSwitchName found";Break}
    } -ArgumentList $VMSwitchName
    Return $true
}

#Inititial Settings
Write-Verbose "Imagefactory 3.1 (Hyper-V)"
$XMLFile = "C:\setup\ImageFactoryV3ForHyper-V\ImageFactoryV3.xml"
Import-Module 'C:\Program Files\Microsoft Deployment Toolkit\Bin\MicrosoftDeploymentToolkit.psd1'

# Read Settings from XML
Write-Verbose "Reading from $XMLFile"
[xml]$Settings = Get-Content $XMLFile

#Verify Connection to DeploymentRoot
$Result = Test-Path -Path $Settings.Settings.MDT.DeploymentShare
If($Result -ne $true){Write-Warning "Cannot access $($Settings.Settings.MDT.DeploymentShare) , will break";break}

#Connect to MDT
$Root = $Settings.Settings.MDT.DeploymentShare
$MDTPSDrive = New-PSDrive -Name MDT -PSProvider MDTProvider -Root $Root -ErrorAction Stop
Write-Verbose "Connected to $($MDTPSDrive.Root)"

#Get MDT Settings
$MDTSettings = Get-ItemProperty MDT:

#Update boot image
Write-Verbose "Updating boot image, please wait"
Update-MDTDeploymentShare -Path MDT: -ErrorAction Stop

#Verify access to boot image
$MDTImage = $($Settings.Settings.MDT.DeploymentShare) + "\boot\" + $($MDTSettings.'Boot.x86.LiteTouchISOName')
if((Test-Path -Path $MDTImage) -eq $true){Write-Verbose "Access to $MDTImage is ok"}

#Get TaskSequences
$RefTaskSequenceIDs = (Get-VIARefTaskSequence -RefTaskSequenceFolder "MDT:\Task Sequences\$($Settings.Settings.MDT.RefTaskSequenceFolderName)" | where Enabled -EQ $true).TasksequenceID
Write-Verbose "Found $($RefTaskSequenceIDs.count) TaskSequences to work on"

#check task sequence count
if($RefTaskSequenceIDs.count -eq 0){Write-Warning "Sorry, could not find any TaskSequences to work with";BREAK}

#Verify Connection to Hyper-V host
$Result = Test-VIAHypervConnection -Computername $Settings.Settings.HyperV.Computername -ISOFolder $Settings.Settings.HyperV.ISOLocation -VMFolder $Settings.Settings.HyperV.VMLocation -VMSwitchName $Settings.Settings.HyperV.SwitchName
If($Result -ne $true){Write-Warning "$($Settings.Settings.HyperV.Computername) is not ready, will break";break}

#Upload boot image to Hyper-V host
$DestinationFolder = "\\" + $($Settings.Settings.HyperV.Computername) + "\" + $($Settings.Settings.HyperV.ISOLocation -replace ":","$")
Copy-Item -Path $MDTImage -Destination $DestinationFolder -Force

#Create the VM's on Host
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

#Remove old WIM files in the capture folder
Foreach($Ref in $RefTaskSequenceIDs){
    $FullRefPath = $(("$Root\Captures\$ref") + ".wim")
    if((Test-Path -Path $FullRefPath) -eq $true){
        Remove-Item -Path $FullRefPath -Force -ErrorAction Stop
        }
}

#Start VM's on Host
Invoke-Command -ComputerName $($Settings.Settings.HyperV.Computername) -ScriptBlock {
    Param(
        $ConcurrentRunningVMs
    ) 
    #Print out settings
    Write-Output "ConcurrentRunningVMs is set to: $ConcurrentRunningVMs"
    
    #Get the VMs as Objects
    $RefVMs = Get-VM | Where-Object -Property Notes -Like -Value "REFIMAGE"
    foreach($RefVM in $RefVMs){
        Write-Verbose "REFVM $($RefVM.Name) is allocated to $($RefVM.ComputerName) at $($refvm.ConfigurationLocation)"
    }

    #Get the VMs as Objects
    $RefVMs = Get-VM | Where-Object -Property Notes -Like -Value "REFIMAGE"
    foreach($RefVM in $RefVMs){
    $StartedVM = Start-VM -VMName $RefVM.Name
    Write-Verbose "Starting $($StartedVM.name)"
    Do
        {
            $RunningVMs = $((Get-VM | Where-Object -Property Notes -EQ -Value "REFIMAGE" | Where-Object -Property State -EQ -Value Running))
            Write-Output "Currently running VM's : $($RunningVMs.Name) at $(Get-Date)"
            Start-Sleep -Seconds "30"
        
        }
    While((Get-VM | Where-Object -Property Notes -EQ -Value "REFIMAGE" | Where-Object -Property State -EQ -Value Running).Count -gt ($ConcurrentRunningVMs - 1))
    }
} -ArgumentList $($Settings.Settings.ConcurrentRunningVMs)

#Wait until they are done
Invoke-Command -ComputerName $($Settings.Settings.HyperV.Computername) -ScriptBlock {
    Do{
        $RunningVMs = $((Get-VM | Where-Object -Property Notes -EQ -Value "REFIMAGE" | Where-Object -Property State -EQ -Value Running))
        Write-Output "Currently running VM's : $($RunningVMs.name) at $(Get-Date)"
        Start-Sleep -Seconds "30"
        
    }until((Get-VM | Where-Object -Property Notes -EQ -Value "REFIMAGE" | Where-Object -Property State -EQ -Value Running).count -eq '0')
}

#Cleanup VMs
Invoke-Command -ComputerName $($Settings.Settings.HyperV.Computername) -ScriptBlock {
    $RefVMs = Get-VM | Where-Object -Property Notes -EQ -Value "REFIMAGE" 
    Foreach($RefVM in $RefVMs){
        $VM = Get-VM -VMName $RefVM.Name
        Write-Verbose "Deleting $($VM.Name) on $($VM.Computername) at $($VM.ConfigurationLocation)"
        Remove-VM -VM $VM -Force
        Remove-Item -Path $VM.ConfigurationLocation -Recurse -Force
    }
}
