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
#Function Create-VIAHyperVVMBootFromISO
{
    Param(
    $VMName="REF",
    $ISOName="MDT Build Lab x86.iso",
    $VMNetworkName="Network-MGM",
    $VirtualHardDiskName="Blank Disk - Large.vhdx",
    $SCVMMServerName="SCVMM01.network.local",
    $SCVMMHostName = $Global:SCVMMHost
    )
    #Get Host
    $vmHost = Get-SCVMHost -ComputerName $SCVMMHostName

    #Generate GUID's
    $JobGroupID1 = [Guid]::NewGuid().ToString()
    $HardwareProfileID = [Guid]::NewGuid().ToString()
    $TemplateID = [Guid]::NewGuid().ToString()

    #Generate Hardware
    $ISO = Get-SCISO -VMMServer $SCVMMServerName | where {$_.Name -eq $ISOName}
    $VMNetwork = Get-SCVMNetwork -VMMServer $SCVMMServerName -Name $VMNetworkName
    $PortClassification = Get-SCPortClassification -VMMServer $SCVMMServerName | where {$_.Name -eq "High bandwidth"}
    $CPUType = Get-SCCPUType -VMMServer $SCVMMServerName | where {$_.Name -eq "3.60 GHz Xeon (2 MB L2 cache)"}
    $VirtualHardDisk = Get-SCVirtualHardDisk -VMMServer $SCVMMServerName | where {$_.Name -eq $VirtualHardDiskName} | where {$_.HostName -eq "$Global:SCVMMServerName"}
    New-SCVirtualScsiAdapter -VMMServer $SCVMMServerName -JobGroup $JobGroupID1 -AdapterID 7 -ShareVirtualScsiAdapter $false -ScsiControllerType DefaultTypeNoType 
    New-SCVirtualDVDDrive -VMMServer $SCVMMServerName -JobGroup $JobGroupID1 -Bus 1 -LUN 0 -ISO $ISO 
    New-SCVirtualNetworkAdapter -VMMServer $SCVMMServerName -JobGroup $JobGroupID1 -MACAddressType Dynamic -VLanEnabled $false -Synthetic -IPv4AddressType Dynamic -IPv6AddressType Dynamic -VMNetwork $VMNetwork -PortClassification $PortClassification 
    New-SCHardwareProfile -VMMServer $SCVMMServerName -CPUType $CPUType -Name "Profile$HardwareProfileID" -Description "Profile used to create a VM/Template" -CPUCount 2 -MemoryMB 3072 -DynamicMemoryEnabled $false -MemoryWeight 5000 -VirtualVideoAdapterEnabled $false -CPUExpectedUtilizationPercent 20 -DiskIops 0 -CPUMaximumPercent 100 -CPUReserve 0 -NumaIsolationRequired $false -NetworkUtilizationMbps 0 -CPURelativeWeight 100 -HighlyAvailable $false -DRProtectionRequired $false -NumLock $false -BootOrder "CD", "IdeHardDrive", "PxeBoot", "Floppy" -CPULimitFunctionality $false -CPULimitForMigration $false -Generation 1 -JobGroup $JobGroupID1
    New-SCVirtualDiskDrive -VMMServer $SCVMMServerName -IDE -Bus 0 -LUN 0 -JobGroup $JobGroupID1 -CreateDiffDisk $false -VirtualHardDisk $VirtualHardDisk -FileName "REF_Blank Disk - Large.vhdx" -VolumeType BootAndSystem 
    $HardwareProfile = Get-SCHardwareProfile -VMMServer $SCVMMServerName | where {$_.Name -eq "Profile$HardwareProfileID"}

    #Generate Template
    New-SCVMTemplate -Name "Temporary Template$TemplateID" -Generation 1 -HardwareProfile $HardwareProfile -JobGroup $JobGroupID1 -NoCustomization 

    #Generate Configuration
    $template = Get-SCVMTemplate -All | where { $_.Name -eq "Temporary Template$TemplateID" }
    $virtualMachineConfiguration = New-SCVMConfiguration -VMTemplate $template -Name $VMName
    Write-Output $virtualMachineConfiguration

    #Update Configuration W HostData
    Set-SCVMConfiguration -VMConfiguration $virtualMachineConfiguration -VMHost $vmHost
    Update-SCVMConfiguration -VMConfiguration $virtualMachineConfiguration

    #Update Configuration W Networkdata
    $AllNICConfigurations = Get-SCVirtualNetworkAdapterConfiguration -VMConfiguration $virtualMachineConfiguration
    Update-SCVMConfiguration -VMConfiguration $virtualMachineConfiguration

    #Create VM
    New-SCVirtualMachine -Name $VMName -VMConfiguration $virtualMachineConfiguration -JobGroup $JobGroupID1
    Set-SCVirtualMachine -Tag "REFIMAGE" -VM (Get-SCVirtualMachine -Name $VMName)
}
#Function Upload-VIAHypervMDTBootImage
{
    Param(
    $Computername,
    $ISOFolder,
    $HyperVHost,
    $DeploymentShare,
    $MDTISO
    )
    #Upload BootImage
    $DestinationFolder = $($Global:HyperVISOFolder -replace "C:","\\$Global:HyperVHost\C$")
    $SourceFolder = "$Global:DeploymentShare\Boot"
    $FileName = $MDTISO
    $Null = New-Item -ItemType Directory -Path $ISOFolder -Force -ErrorAction Stop
    $ReturnData = Copy-Item -Path $SourceFolder\$FileName -Destination $DestinationFolder\$MDTISO -Force -ErrorAction Stop -PassThru
    if((Test-Path -Path $ReturnData.FullName) -EQ $true){
        Write-Host "Upload ok."
    }
    else
    {
        Write-Warning "Upload failed."
        BREAK
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
    If ($Result.TcpTestSucceeded -eq $true){Write-Host "SMB Connection to $Computername is ok"}else{Write-Warning "SMB Connection to $Computername is NOT ok";BREAK}

    #Verify WinRM access
    $Result = Test-NetConnection -ComputerName $Computername -CommonTCPPort WINRM
    If ($Result.TcpTestSucceeded -eq $true){Write-Host "WINRM Connection to $Computername is ok"}else{Write-Warning "WINRM Connection to $Computername is NOT ok";BREAK}

    #Verify that Microsoft-Hyper-V-Management-PowerShell is installed
    Invoke-Command -ComputerName $Computername -ScriptBlock {
        $Result = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell)
        Write-Host "$($Result.DisplayName) is $($Result.State)"
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
        Write-Host "$($Result.DisplayName) is $($Result.Status)"
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
        if(((Get-VMSwitch | Where-Object -Property Name -EQ -Value $VMSwitchName).count) -eq "1"){Write-Host "Found $VMSwitchName"}else{Write-Warning "No swtch with the name $VMSwitchName found";Break}
    } -ArgumentList $VMSwitchName
    Return $true
}
Function New-VIALogEntry
{
    Param(
    $Message
    )
    Write-Host "$Message : " + (get-date) 
}
