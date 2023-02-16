<#
    .SYNOPSIS
    Remote ShutDown Script for all DataCore Servers in a ServerGroup

    .DESCRIPTION
    This script is typically started from a a batch file triggered by an Uninterruptible Power Supply (UPS).
    It shuts down all DataCore Servers after all SAN-ClientConecctions are down (AllPathsDown). 
    This scripts securely stores the credentials for remote access to DataCore-Servers
    in Microsoft's Windows Credential Manager on its first run.
    After that, it performs the following process unattended:
    
    .FUNCTIONALITY
    1. Environemtal Check the following settings:
        a) Host-File with DataCore-Server Entry exists and DataCore-Server is reachable
        b) neccessary PowershellModules are installed and import them
    2. Connect to remote DataCore-Server
    3. Disable WriteCache on all DataCore-Servers
    2. Wait until all SAN-Clienthost-Paths are down
    3. Stop all DataCore-Servers in the Group
    4. Stop 'DataCore Executive' Services ('dcsx') on all DataCore-Servers
    5. Shutdown OS on all DataCore-Servers

    .INPUTS
    None. You cannot pipe objects to Add-Extension.

    .COMPONENT
    You need to Install the following Powershell Modules
    DataCore: "DataCore.Executive.Cmdlets"
    Microsoft: "CredentialManager"

    .EXAMPLE
    Start-DCS-Shutdown.ps1

    .LINK
    Online version: https://github.com/Kupferschmid/Start-DCS-Shutdown.ps1

    .NOTES
    Version    : 1.0.0
    Author     : Klaus Kupferschmid
    Created on : 2023-02-12
    License    : No License
    Copyright  : (c) 2023 tempero.it GmbH

#>

### Variables ###
$dcsHostName = "DCS1" # Hostname des 1. DataCoreServers
$CredManObj = [PSCustomObject]@{CredManName = "DataCoreLoginCred"; Username = "LocalAdmin"} #Username = lokaler Windows-Anmeldename der DataCoreServer 
$modules = @("CredentialManager","DataCore.Executive.Cmdlets")

function Approve-Environment {
    # check if hosts-file has an Entry for DataCore-Hostname or DNS-Resolution works
    if(Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern $dcsHostName){
        Write-Host "DNS-Eintrag in lokaler Hosts-Datei gefunden." -ForegroundColor "Green"
    }else{
        Write-Host "DNS-Eintrag wurde nicht in lokaler Hosts-Datei gefunden." -ForegroundColor "Yellow"
        Write-Host "Versuche DNS-Auflösung" -NoNewline -ForegroundColor "Green"
        Write-Host "..." -NoNewline
        try {
            $dcsIp = (ping -4 -a -n 1 $dcsHostName).Split('[')[2].split(']')[0]
            Write-Host $dcsIp -NoNewline -ForegroundColor "Green"
            Write-Host "OK" -ForegroundColor "Green"
        }
        catch {
            Write-Host "gescheitert! -ABBRUCH-" -ForegroundColor "red"
            exit
        }
    }

    # Import neccesary PowerShell-Modules
    Foreach ($moduleName in $modules) {
        $module =  Get-Module -Name $moduleName #-ListAvailable
        If (!$module) {
            # Get DataCore PowerShell ModuleName
            if ($moduleName -eq "DataCore.Executive.Cmdlets"){
                if ("HKLM:\Software\DataCore\PowershellSupport") {
                    $regKey = get-Item "HKLM:\Software\DataCore\PowershellSupport"
                    $installPath = $regKey.getValue('InstallPath')
                    if (Test-Path $installPath){
                        $moduleName = "$installPath\DataCore.Executive.Cmdlets.dll"
                    }
                }else {
                    Write-Host "DataCore-CmdLets sind nicht installiert!" -ForegroundColor Red
                    exit
                }
            }
            # Import neccesary PowerShell-Modules
            try {
                Import-Module $moduleName -DisableNameChecking -ErrorAction Stop
            }
            catch {
                Write-Host "Powershell-Module $moduleName wurde nicht unter $installPath gefunden." -ForegroundColor "Red"
                Write-Host "Versuche Installation von $moduleName"
                Install-Module -Name $moduleName -AcceptLicense -AllowClobber -Force -Verbose -Scope AllUsers
            }
            Write-Host "Successfully registered Cmdlets for $moduleName." -ForegroundColor "Green"
        }else{
            Write-Host "Modul $moduleName ist bereits importiert" -ForegroundColor "Green"
        }
    }
}
function Get-WindowsStoredCredentials {
    param (
        [parameter(Position=0,Mandatory=$true,ValueFromPipeline)] $StoredCredentialTarget
    )
    $error.clear()
    try {
        $credential = Get-StoredCredential -Target $StoredCredentialTarget -AsCredentialObject
        # Throw exception if no credential-Object exist
        If ($credential.UserName -eq $null){Write-Error -Exception "StoredCredentialTarge existieren nicht" -ErrorAction Stop }
    }
    catch {
            Write-Host "StoredCredential mit dem Namen $StoredCredentialTarget konnte nicht aus dem WindowsCredentialStore gelesen werden" -ForegroundColor "Yellow"
            Write-Host "Credential werden neu abgefragt und gespeichert" -ForegroundColor "Yellow"
            $null = Get-Credential -UserName $CredManObj.LoginName -Message "Enter password" | New-StoredCredential -Target $StoredCredentialTarget -Persist Enterprise
            Start-Sleep -Seconds 2
            $credential = Get-StoredCredential -Target $StoredCredentialTarget -AsCredentialObject
        }
    return $credential
} 
function Connect-DCS{
    ### Connect to DataCore-Server
    Write-Host "Verbindung mit: " -NoNewline -ForegroundColor "Green"
    $error.clear()
    try{
        $ip = Connect-DcsServer $dcsHostName -UserName $CredManObj.Username $dataCoreCred.Password
    }catch{
        switch -Regex ($error[0].Exception.InnerException.Message) {
            "Host nicht reagiert"  {
                                        Write-Host "DataCore-Dienst war auf $dcsHostName nicht erreichbar! -ABBRUCH-" -ForegroundColor "Red"
                                        Write-Host $error[0].Exception.Message -ForegroundColor "Red"; exit
                                    }
            "authentication failed" {
                                        Write-Host "Falscher Benutzername oder Passwort - Kennwort-Objekt im CredentialManager wird gelöscht:" -ForegroundColor Yellow
                                        if(Get-StoredCredential -Target $CredManObj.CredManName){
                                            Remove-StoredCredential -Target $CredManObj.CredManName
                                        }
                                        $dataCoreCred = Get-WindowsStoredCredentials -StoredCredentialTarget $CredManObj.CredManName
                                        $ip = Connect-DCS
                                    }
            Default                 {   Write-Host $error[0].Exception.Message -ForegroundColor "Red"; exit}
        }
    }
    Write-Host $ip
    # List Server and Status
    $dataCoreServers = Get-DcsServer
    return $dataCoreServers 
}

#### MAIN ####
# Compute Varaiales
$CredManObj | Add-Member -MemberType NoteProperty -Name 'LoginName' -Value ($dcsHostName+"\"+$CredManObj.Username)
$timeOut = $false
# Check Host-File & Load PSModules
Approve-Environment
# Read Credentials from CredentialManager
$dataCoreCred = Get-WindowsStoredCredentials -StoredCredentialTarget $CredManObj.CredManName
# Connect to DataCore Server with Remote Powershell
($dataCoreServers = Connect-DCS) | Format-List HostName, PowerState, State, CacheState
# Disable WriteCace on DataCore-Servers
foreach($dcs in $dataCoreServers){
    if ($dcs.CacheState -eq "WritebackGlobal") {
        Write-Host "Bei DataCore-Server $($dcs.HostName) wird der Schreib-Cache beendet" -NoNewline -ForegroundColor "Green"
        Write-Host "..." -NoNewline
        $res = Disable-DcsServerWriteCache -Server $dcs.HostName
        if ($res.CacheState -eq "WritethruGlobal"){
            Write-Host "OK" -ForegroundColor "Green"
        }
    }else{
        Write-Host "Bei DataCore-Server $($dcs.HostName) ist der Schreib-Cache bereits gestoppt" -ForegroundColor "Yellow"
    }
}
# Check if Hosts have aktive connections
$oldClientCount = $null
do {
    try {
        $onlineClients = Get-DcsClient | Where-Object State -eq PortsConnected
    }
    catch {
        Write-Host "Verbindungsstatus zu den angebunden Hosts kann nicht geprüft werden !!!Abbruch!!!" -ForegroundColor "Red"
        Write-Host $error[0] -ForegroundColor "Red"
        exit
    }
    
    if ($onlineClients){
        If ($onlineClients.count -gt 1 -and $onlineClients.count -ne $oldClientCount){
            Write-Host "Derzeit sind noch $($onlineClients.count) Clients verbunden - Warte auf Abschaltung." -ForegroundColor "Yellow"
            $oldClientCount = $onlineClients.count
        }
        if ($onlineClients.count -eq 1 -and $onlineClients.count -ne $oldClientCount) {
            Write-Host "Derzeit ist noch Client '"$onlineClients.HostName"' verbunden - Warte auf Abschaltung." -ForegroundColor "Yellow"
            $oldClientCount = $onlineClients.count
        }
        start-sleep -Seconds 10
    }else{
        Write-Host "Alle mit DataCore-Servern verbundene Clients sind getrennt." -ForegroundColor "Green"
    }
} until ($null -eq $onlineClients)
# Stop DataCore-Servers
foreach($dcs in $dataCoreServers){
    if($dcs.State -eq "Online"){
        Write-Host "DataCore-Server $($dcs.HostName) wird gestoppt" -NoNewline -ForegroundColor "Green"
        Write-Host "..." -NoNewline
        $null = Stop-DcsServer -Server $dcs.HostName
        if((Get-DcsServer -Server $dcs.HostName).State -eq "Offline"){
            Write-Host "OK" -ForegroundColor "Green"
        }
    }else{
        Write-Host "DataCore-Server $($dcs.HostName) ist bereits gestoppt" -ForegroundColor "Yellow"
    }
}
# Stop DCSX-Service and Shutdown DataCore-Servers
foreach($dcs in $dataCoreServers){
    # Create PSCredential-Opbejct
    $PWord = ConvertTo-SecureString -String $dataCoreCred.Password -AsPlainText -Force
    $User = $dcs.HostName+'\'+$CredManObj.Username
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
    # Collect DCSX-Service as WMIObject
    Write-Host "Der Windows Dienst 'DataCore Executive' wird als WmiObject auf $dcs.HostName abgerufen" -NoNewline -ForegroundColor "Green"
    Write-Host "..." -NoNewline
    try {
        $dcsx = Get-WmiObject -ComputerName $dcs.HostName -Class Win32_Service -Filter "Name='dcsx'" -Credential $Credential
    }
    catch {
        Write-Host "Fehler: "$error[0].Exception.Message -ForegroundColor "Red"
    }
    if($dcsx){
        Write-Host "OK" -ForegroundColor "Green"
        if($dcsx.State -eq "Running"){
            Write-Host "Der Windows Dienst 'DataCore Executive' wird auf $($dcs.HostName) gestoppt" -NoNewline -ForegroundColor "Green"
            Write-Host "..." -NoNewline
            $dcsxService = $dcsx.StopService()
            
            switch ($dcsxService.ReturnValue) {
                0 {
                    for ($i = 0; $dcsx.State -ne "Stopped" -and $timeOut -eq $false ; $i++) {
                        try {
                            $dcsx = Get-WmiObject -ComputerName $dcs.HostName -Class Win32_Service -Filter "Name='dcsx'" -Credential $Credential
                        }
                        catch {
                            Write-Host "WMI-Error: $($dcsxService.ReturnValue)" -ForegroundColor "Red"
                        }
                        Write-Host "." -NoNewline
                        if($i -ge 10){$timeOut = $true}
                    }
                    if($timeOut){
                        Write-Host "Rückmeldung TimeOut" -ForegroundColor "Red"
                    }else{
                        Write-Host "OK" -ForegroundColor "Green"
                    }
                  }
                2 {Write-Host "The user did not have the necessary access" -ForegroundColor "Red"}
                3 {Write-Host "The service cannot be stopped because other services that are running are dependent on it." -ForegroundColor "Red"}
                6 {Write-Host "The service has not been started." -ForegroundColor "Red"}
                Default {Write-Host "WMI-Error: $($dcsxService.ReturnValue)" -ForegroundColor "Red"}
            }
        }else{
            Write-Host "Der Windows Dienst 'DataCore Executive' ist auf $($dcs.HostName) nicht gestartet." -ForegroundColor "Yellow"
        }
    }
    Write-Host "Der DataCore Server $($dcs.HostName) wird abgeschaltet" -NoNewline -ForegroundColor "Green"
    Write-Host "..." -NoNewline
    try {
        Stop-Computer -ComputerName $dcs.HostName -Force -Credential $Credential
    }
    catch {
        Write-Host $error[0].Exception.Message -ForegroundColor "Red"
    }
    for ($i = 0; (Test-Connection -ComputerName $dcs.HostName -Quiet) -and $timeOut -eq $false ; $i++) {
        Write-Host "." -NoNewline
        if($i -ge 10){$timeOut = $true}
    }
    if($timeOut){
        Write-Host "Rückmeldung TimeOut" -ForegroundColor "Red"
    }else{
        Write-Host "OK" -ForegroundColor "Green"
    }
}
