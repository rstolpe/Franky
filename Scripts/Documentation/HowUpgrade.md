When your going to upgrade Franky to a new version you just replace the files from the new one over the old version in  
C:\ProgramData\UniversalAutomation\Repository\  
  
But remember that if you replace the .universal folder with the new one your settings will be replaced with the default one for Franky. I'll write in the release notes if something has changed in the .universal folder so you can manually replace the lines.  
  
It's important that you run InstallEventLog.ps1 after every upgrade so you’re adding the new sources to EventLog.