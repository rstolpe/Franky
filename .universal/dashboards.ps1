﻿New-PSUDashboard -Name "Franky" -FilePath "dashboards\Franky\Dashboard.ps1" -BaseUrl "/" -Framework "UniversalDashboard:Latest" -Environment "Franky" -Authenticated -Role @('Administrator', 'Franky') -Component @("Reports:1.0", "LoadBalancing:1.0", "ADComputer:1.0", "ADUser:1.0", "ADFunctions:1.0", "ADGroup:1.0", "PSUSpecific:1.0", "Other:1.0") -SessionTimeout 660 -IdleTimeout 180 -AutoDeploy -Description "Franky Support Dashboard!" -Credential "Default"