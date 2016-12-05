Import-Module C:\setup\Functions\VIAHypervModule.psm1 -Force
Import-Module C:\setup\Functions\VIADeployModule.psm1 -Force
Import-Module C:\Setup\Functions\VIAUtilityModule.psm1 -Force

$RefTS = "REFWS2012R2-003"
$WIMfile = "D:\MDTBuildLab\Captures\$RefTS.wim"
$VHDImage = "C:\test\$RefTS.vhdx"
C:\Setup\HYDv10\Scripts\Convert-VIAWIM2VHD.ps1 -SourceFile $WIMfile -DestinationFile $VHDImage -Disklayout UEFI -SizeInMB 40000 -Index 1

$MountFolder = "C:\MountVHD"
$AdminPassword = "P@ssw0rd"
$VMLocation = "C:\VMs\TEST"
$VMMemory = 2GB
$VMSwitchName = "ViaMonstraNAT"
$localCred = new-object -typename System.Management.Automation.PSCredential -argumentlist "Administrator", (ConvertTo-SecureString $adminPassword -AsPlainText -Force)
$VIASetupCompletecmdCommand = "cmd.exe /c PowerShell.exe -Command New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest' -Name OSDeployment -Value Done -PropertyType String"
$SetupRoot = "C:\Setup"

If ((Test-VIAVMExists -VMname $RefTS) -eq $true){Write-Host "$RefTS already exist";Break}
Write-Host "Creating $RefTS"
$VM = New-VIAVM -VMName $RefTS -VMMem $VMMemory -VMvCPU 2 -VMLocation $VMLocation -VHDFile $VHDImage -DiskMode Diff -VMSwitchName $VMSwitchName -VMGeneration 2 -Verbose
$VIAUnattendXML = New-VIAUnattendXML -Computername $RefTS -OSDAdapter0IPAddressList DHCP -DomainOrWorkGroup Workgroup -ProtectYourPC 3 -Verbose
$VIASetupCompletecmd = New-VIASetupCompleteCMD -Command $VIASetupCompletecmdCommand -Verbose
$VHDFile = (Get-VMHardDiskDrive -VMName $RefTS).Path
Mount-VIAVHDInFolder -VHDfile $VHDFile -VHDClass UEFI -MountFolder $MountFolder 
New-Item -Path "$MountFolder\Windows\Panther" -ItemType Directory -Force | Out-Null
New-Item -Path "$MountFolder\Windows\Setup" -ItemType Directory -Force | Out-Null
New-Item -Path "$MountFolder\Windows\Setup\Scripts" -ItemType Directory -Force | Out-Null
Copy-Item -Path $VIAUnattendXML.FullName -Destination "$MountFolder\Windows\Panther\$($VIAUnattendXML.Name)" -Force
Copy-Item -Path $VIASetupCompletecmd.FullName -Destination "$MountFolder\Windows\Setup\Scripts\$($VIASetupCompletecmd.Name)" -Force
Dismount-VIAVHDInFolder -VHDfile $VHDFile -MountFolder $MountFolder
Remove-Item -Path $VIAUnattendXML.FullName
Remove-Item -Path $VIASetupCompletecmd.FullName
Get-VM -Name $RefTS -Verbose
Remove-VIAVM -VMName $RefTS


