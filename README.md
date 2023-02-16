# Start-DCS-Shutdown.ps1
Remote ShutDown Script for all DataCore Servers in a ServerGroup

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
