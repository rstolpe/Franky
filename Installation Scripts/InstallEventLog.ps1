﻿<#
    Copyright (C) 2022  KeepCodeOpen - The ultimate IT-Support dashboard

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#>

# With this script it adds all the Sources to eventlog so logging are working.
# IF you change the LogName from Franky it's important that you do the same at the Dashboard.ps1 also.
$EventLogName = 'Franky'

$EventSources = @("ChangeUserStreetAddress", "ChangeUserFAX", "ChangeUserOfficePhone", "ChangeUserMobilePhone", "ChangeUserHomePhone", "ChangeUserEmailAddress", "RemoveUserAsManagerFromObject", "ShowWhatUserManaging", "RemovedManageByFromGroup", "RemovedManageByFromComputer", "ChangeServiceStartUp", "EnableSchedualTask", "DisableSchedualTask", "RunSchedualTask", "CreateComputer", "SendPing", "LoginFailed", "CreateUser", "MoveUserObject", "SetUserChangePasswordNextLogin", "SetUserCannotChangePassword", "SetUserPasswordExpires", "UserSearch", "MoveComputerObject", "TempFileCleaning", "ChangeExperationDateForUser", "ChangePasswordForUser", "UnlockUserAccount", "RestartServices", "GroupSearch", "AddToGroup", "RemoveFromGroup", "DeleteGroup", "DeleteUser", "DeleteComputer", "EditGroupInfo", "ChangeGroupManagedBy", "ChangeUserDescription", "ChangeGroupDescription", "ChangeComputerDescription", "ChangeUserMail", "ChangeGroupMail", "ChangeComputerMail", "ChangeGroupSamAccountName", "ChangeGroupCN", "ChangeGroupDisplayName", "ChangeGroupScope", "ChangeGroupCategory", "CreatedGroup", "ComputerSearch", "LogOutUser", "RebootComputer", "ShowMonitorInfo", "ShowInstalledDrivers", "ShowNetworkAdapters", "ShowProcess", "ShowInstalledSoftware", "ShowAutostart", "ShowServices", "ShowSchedualTask", "DisableNetworkAdapter", "EnableNetworkAdapter", "RestartNetworkAdapter", "KillProcess", "StopServices", "StartServices", "DeletedUserProfile", "CompareComputerADGroups", "DisableComputerObject", "EnableComputerObject", "DisableUserObject", "EnableUserObject", "ChangeComputerCN", "ChangeComputerSamAccountName", "ChangeComputerDisplayName", "ChangeUserCN", "ChangeUserSamAccountName", "ChangeUserDisplayName", "ChangeComputerManagedBy", "ShowComputerUserProfiles")

foreach ($source in $EventSources) {
    New-EventLog -Source $source -LogName $EventLogName
}