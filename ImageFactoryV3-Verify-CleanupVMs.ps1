<#
.Synopsis
    ImageFactory 3.3
.DESCRIPTION
    ImageFactory 3.3
.EXAMPLE
    ImageFactoryV3-Verify-CleanupVMs.ps1
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

#Cleanup Validate VMs
Update-Log -Data "Cleanup Validate VMs"
Invoke-Command -ComputerName $($Settings.Settings.HyperV.Computername) -ScriptBlock {
    $ValVMs = Get-VM | Where-Object -Property Notes -Like -Value "VALIDATE*" 
    Foreach($ValVM in $ValVMs){
        $VM = Get-VM -VMName $ValVM.Name
        Write-Verbose "Deleting $($VM.Name) on $($VM.Computername) at $($VM.ConfigurationLocation)"
        Remove-VM -VM $VM -Force
        Remove-Item -Path $VM.ConfigurationLocation -Recurse -Force
    }
}

#Cleanup Reference VMs
Update-Log -Data "Cleanup Reference VMs"
Invoke-Command -ComputerName $($Settings.Settings.HyperV.Computername) -ScriptBlock {
    $ValVMs = Get-VM | Where-Object -Property Notes -Like -Value "REFIMAGE*" 
    Foreach($ValVM in $ValVMs){
        $VM = Get-VM -VMName $ValVM.Name
        Write-Verbose "Deleting $($VM.Name) on $($VM.Computername) at $($VM.ConfigurationLocation)"
        Remove-VM -VM $VM -Force
        Remove-Item -Path $VM.ConfigurationLocation -Recurse -Force
    }
}