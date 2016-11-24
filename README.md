# ImageFactoryV3ForHyper-V
ImageFactory V3.1 For Hyper-V

The image factory creates reference images using Microsoft Deployment Toolkit and PowerShell.
You run the script on the MDT server. The script will connect to a hyper-v host specified in the XML file and build one virtual machine for each task sequences in the REF folder.
It will then grab the BIOS serial number from each virtual machine, inject it into customsettings.ini, start the virtual machines, run the build and capture process, turn off the virtual machine and remove them all.

Modify the XML file to fit your enviroment and use the bootstrap.ini and customsettings.ini as sample files.

You need the following PowerShell Module https://github.com/lipkau/PsIni
/mike