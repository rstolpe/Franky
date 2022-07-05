# Environment
- I have migrated it to work with PowerShell Universal 3.0.6
- Updated PowerShell to 7.2.5
- Updated ImportExcel to 7.6.0
- Updated the code to work with PowerShell 7 as Franky now goes native PowerShell 7.

# Configuration files
- Added missing configuration .ps1 files under .universal folder
- Formated the .ps1 files after PSU 3.x standard
- Dashboard.ps1 has changed it so it don't re-write the hole $pages and instead following standard

# Setup and installation
- 

# New

# Updates
## All over
- Updated the GUI with icons on some places to make the GUI look better to attract more people to use it.
- Cleaned up the code

## Dashboard/pages
## #User
- Replaced some text with icons instead to make the GUI to look better

### Computer
- Replaced some text with icons instead to make the GUI to look better

### Group
- Replaced some text with icons instead to make the GUI to look better

## Functions
### Show process on COMPUTERNAME
- Converted it to CIM commands to speed things up!
- Toast message over the action button are showing what process it's stopping
- Added so you can see CommandLine
- Added commandLine and user to include when your searching in the table

### Show network adapters on COMPUTERNAME
- Converted it to CIM commands to speed things up!
- Added so the network adapter name are showing in toast message over the action buttons

### Restart Computer
- Added right order when the command are executed
- Added error message

### Logout current user from COMPUTERNAME
- Has added so it show what user that are logged in on the computer.
- Added error message

### Delete user profile from COMPUTERNAME
- Has been converted to CIM to speed things up!
- Added Not used for to show how many days the profile has not been used for.

### Delete Google Chrome settings
- Has been updated with CIM to speed things up!

### Delete Microsoft Edge settings
- Has been updated with CIM to speed things up!