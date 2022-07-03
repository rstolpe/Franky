<#
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

Set-PSUSetting -LoggingFilePath "C:\ProgramData\Universlogs\log.txt" -LogLevel "Informational" -MicrosoftLogLevel "Warning" -DefaultEnvironment "Integrated" -Telemetry -SecurityEnvironment "Integrated" -ApiEnvironment "Integrated" -DefaultPage "home" -ScriptBaseFolder "C:\ProgramData\UniversalAutomation\Repository\Scripts" -AdminConsoleTitle "Franky" #-AdminConsoleLogo "/pictures/"