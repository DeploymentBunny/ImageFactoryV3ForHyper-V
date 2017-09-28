<#
.Synopsis
    ImageFactory 3.3
.DESCRIPTION
    ImageFactory 3.3
.EXAMPLE
    ImageFactoryV3-ConvertToVHD.ps1
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


$DateTime = (Get-Date).ToString('yyyyMMdd')
$CaptureFolder = "D:\MDTBuildLab\Captures"
$VHDxFolder = "C:\Setup\VHD\$DateTime"
$UEFI = $true
$BIOS = $false
New-Item -Path $VHDxFolder -ItemType Directory -Force

$wims = Get-ChildItem -Path $CaptureFolder -Filter *.wim
foreach($wim in $wims){
    $WindowsImage = Get-WindowsImage -ImagePath $wim.FullName
    if ($WindowsImage.ImageDescription -ne ""){
        $ImageName = $WindowsImage.ImageDescription
    }else{
        $ImageName = $wim.BaseName
    }

    Write-Host "Working on $ImageName"
    if($UEFI -eq $True){
        #Create UEFI VHDX files
        $DestinationFile =  $VHDxFolder + "\" + $ImageName + "_UEFI.vhdx"
        if((Test-Path -Path $DestinationFile) -ne $true){
            Write-Host "About to create $DestinationFile"
            C:\Setup\ImageFactoryV3ForHyper-V\Convert-VIAWIM2VHD.ps1 -SourceFile $SourceFile -DestinationFile $DestinationFile -Disklayout UEFI -SizeInMB 80000 -Index 1
        }else{
            Write-Host "$DestinationFile already exists"
        }
    }

    if($BIOS -eq $True){
        #Create BIOS VHDX files
        $DestinationFile =  $VHDxFolder + "\" + $ImageName + "_BIOS.vhdx"
        if((Test-Path -Path $DestinationFile) -ne $true){
            Write-Host "About to create $DestinationFile"
            C:\Setup\ImageFactoryV3ForHyper-V\Convert-VIAWIM2VHD.ps1 -SourceFile $SourceFile -DestinationFile $DestinationFile -Disklayout BIOS -SizeInMB 80000 -Index 1
        }else{
            Write-Host "$DestinationFile already exists"
        }
    }
}
