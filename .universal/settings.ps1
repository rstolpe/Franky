$Parameters = @{
	LoggingFilePath = "C:\ProgramData\Universlogs\log.txt"
	LogLevel = "Informational"
	MicrosoftLogLevel = "Warning"
	DefaultEnvironment = "Franky"
	Telemetry = $true
	SecurityEnvironment = "Franky"
	ApiEnvironment = "Franky"
	DefaultPage = "home"
	ScriptBaseFolder = "C:\ProgramData\UniversalAutomation\Repository\Scripts"
	AdminConsoleTitle = "Franky"
}
Set-PSUSetting @Parameters