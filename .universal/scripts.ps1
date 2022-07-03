﻿<#
    Copyright (C) 2022  KeepCodeOpen - The ultimate IT-Support dashboard
    <https://stolpe.io>

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

New-PSUScript -Name "CleanClient.ps1" -Description "Cleaning up temp folders and files on client" -Path "CleanClient.ps1" -Environment "Franky" -InformationAction "Continue" -MaxHistory 10 