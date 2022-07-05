 # Setup host
 **When your done with your setup restart the powershell universal service**  
   
1. Install PowerShell Universal version 3.0.6 or later
    - https://ironmansoftware.com/downloads
2. Install PowerShell 7.2.5  
    **Windows**  
    - https://github.com/PowerShell/PowerShell/releases/download/v7.2.5/PowerShell-7.2.5-win-x64.msi
      
    For other OS you can visit: https://github.com/PowerShell/PowerShell#get-powershell
3. Create a service account that will run PowerShell Universal service and change so that account are running PowerShell Universal service in the windows services.
    - https://docs.powershelluniversal.com/config/running-as-a-service-account#configuring-a-powershell-universal-service-to-run-as-the-account
4. Make sure that that service account has the right permissions for the AD, WinRM, CIM etc.
5. Make sure that you have the ActiveDirectory module installed, if you have RSAT installed then you already has that module installed also.
    - https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps
6. Copy all of the folders from this repo to C:\ProgramData\UniversalAutomation\Repository\ can download it from
    - https://github.com/rstolpe/Franky
    - https://www.stolpe.io/download-franky/
7. Run the FirstInstall.ps1 script on the host that you can find in this repo under the folder "Installation Scripts"

# Setup the appsettings.json file
You can find the file in the repo under the folder "Install Scripts"  
You need to make some changes so let's start with that.
1. Row 5 in the url you need to write your FQDN url as http:// for example http://psu.franky.com:80
2. Row 10 replace Franky.com with the value you did get from the installation script.
3. Row 8 in the url you need to write your FQDN as https:// for example https://psu.franky.com:443
4. Row 11 you need to write your password for the self signed certificated that was created with the "FirstInstall" script. If you don't remember it, it's saved under C:\Temp in the host.
5. Row 48 you need to write your FQDN url as https:// for example https://psu.franky.com:443  
  
When your done, copy the appsettings.json file to C:\ProgramData\PowerShellUniversal\ folder.

# Change in the .ps1 settings files for PowerShell Universal
## authentication.ps1
1. $AuthDomain write your domain with LDAP:// for example "LDAP://DC=Franky,DC=com"
2. $FrankyAccessSID here you need to write the SID that the FirstInstall script did return to you.

## roles.ps1
1. $RoleDomain write your LDAP:// here, for example LDAP://DC=Franky,DC=com
2. In each role you can find the $Searcher.Filter variable after memberOf= in $Searcher.Filter you need to replace it with the path to your group for example:  
CN=Franky.Reader,CN=Users,DC=Franky,DC=com  
This needs to be done in each role.

## Variables.ps1
It's important that you change the variables to match your own information in -Value in this file I do explain what each variable does and what you need to fill out.

## environments.ps1
We have decided to run Franky with PowerShell 7.2 but you can still use it with 5.1. Follow the instruction in this file.

## Dashboards\Franky\Dashboard.ps1
I'll not specify this as it's noted in the dashboard.ps1 file what you should do

# Logging
I have included logging that are stored in Eventlog on the host/s.
Before you activate the logging you need to run the InstallEventLog.ps1 that are located under the folder "Installation Scripts" in this repo so all the sources are created.
As default the LogName is set to Franky but if you want to change that just change the $EventLogName variable in both InstallEventLog.ps1 and in the variables.ps1 file.  
  
When that's done you just need to change [bool]$ActiveEventLog variable from $false to $true in the dashboard.ps1 file.  
As default it's set to $false

# Load Balancing
It's possible to run this dashboard with multiple hosts and use git for it if you follow the process below.  
It's also working if you have a VIP address and then attach the hosts to the VIP address.  
  
1. In PSU admin on each host create an AppToken. If you set an expiration date on the AppToken remember that date as it will stop working after that date and then the loadbalancing will also stop working.
    - https://docs.powershelluniversal.com/config/security/app-tokens
2. In the dashboard.ps1 file you should change [bool]$ActivateLoadBalancing to $true
3. Go in to the Component loadbalancing.psm1 file and change the host1 etc. and also add the AppToken for each host.
4. Change the needed information in variables.ps1 and also in appsettings.json file to your VIP address.  