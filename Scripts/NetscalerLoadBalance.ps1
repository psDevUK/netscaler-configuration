﻿<#
   .Synopsis
    Automates the proceedure to disable a given computer name within Citrix Netscaler Traffic Management Load Balancer
    .Description
    This script was written to automate the process of disabling a server within Citrix Netscaler using the Nitro API wrapped in a PowerShell module. This script will also run a PERFMON trace of current user connections to all websites and display this to you so you can verify that the results have changed through each trace run on the PERFMON trace. This function only requires a COMPUTERNAME parameter to be passed to it, but as the examples show you can over-ride the default settings set on the other two parameters.
   .Example
    "QAHTEST01" | Disable-NetscalerServer
    This will disable the QAHTEST01 server with the default graceful exit of YES and a delay of 600 seconds, passing the COMPUTERNAME parameter via pipeline
    .Example
    Disable-NetscalerServer -ComputerName QAHTEST01 -DelayInSeconds "100"
    This will disable the QAHTEST01 server with the default graceful exit of YES and a delay of 100 seconds
    .Example
    Disable-NetscalerServer -ComputerName QAHTEST01 -Graceful "NO" -DelayInSeconds "0"
    This will disable the QAHTEST01 server with the default graceful exit of NO and a delay of 0 seconds all connections terminated immediately
   .Notes
    NAME: Disable-NetscalerServer
    AUTHOR: Adam Bacon
    LASTEDIT: 2022-04-16
    REFERENCE: https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/basic/service/
    KEYWORDS: Netscaler Automation
   .Link
    https://github.com/psDevUK/netscaler-configuration
#>
Function Disable-NetscalerServer {
    [CmdletBinding()]
    Param
    (
        # The computer name for the server you wish to disable in citrix traffic management load balancer
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, HelpMessage = "Enter the server name to disable in citrix traffic management load balancer")]
        [ValidateNotNullorEmpty()]
        [string]$ComputerName,

        # Graceful exit parameter defaulted to YES
        [Parameter(HelpMessage = "Shut down gracefully, not accepting any new connections, and disabling the service when all of its connections are closed.")]
        [ValidateSet("YES", "NO")]
        $Graceful = "YES",

        # Timeout period for exiting default 600
        [Parameter(HelpMessage = "Time, in seconds, allocated for a shutdown of the services in the service group. After the delay time expires, no requests are sent to the service, and the service is marked as unavailable (OUT OF SERVICE)")]
        [ValidatePattern("[0-9]")]
        [ValidateRange(0, 3)]
        $DelayInSeconds = 600
    )
    BEGIN {
        #log a start time to record script time
        $start = Get-Date
        $msg = "[$start] Starting $($myinvocation.MyCommand)"
        Write-Verbose $msg
        Write-Host -ForegroundColor Green "Checking if required module is present on machine..."
        #First need to check if the module is installed if not need to get this
        if ((Get-Module -ListAvailable | Where-Object { $_.Name -eq "NetScalerConfiguration" }).count -lt 1) {
            Write-Warning "Required module not installed, please wait whilst this is fixed"
            #Module is not listed in any of the default module folders
            #Get the current user session module path
            $modulepath = ($env:PSModulePath -split ';' | Select-String "Users") -replace '\s+', ''
            Set-Location $env:USERPROFILE
            Invoke-WebRequest -OutFile master.zip "https://github.com/psDevUK/netscaler-configuration/archive/refs/heads/master.zip"
            Unblock-File "$env:USERPROFILE\master.zip"
            Expand-Archive -Path "$env:USERPROFILE\master.zip" -OutputPath "$env:USERPROFILE\" -ShowProgress -Verbose
            Copy-Item -Path "$env:USERPROFILE\netscaler-configuration-master\Modules\NetScalerConfiguration" -Recurse -Destination "$modulepath"
            Remove-Item -Path "$env:USERPROFILE\master.zip" -Force
            Remove-Item -Path "$env:USERPROFILE\netscaler-configuration-master\" -Recurse -Force
            Write-Host -ForegroundColor Green "Module now installed script will proceed"
        } #End of if check to see if module was installed or not
    } # End of BEGIN block
    PROCESS {
        #Now ready to import the module so the real automation can begin
        Write-Host -ForegroundColor Green "About to import the netscaler module"
        Import-Module NetScalerConfiguration -WarningAction SilentlyContinue
        Write-Host -ForegroundColor Green "Now connecting to the Citrix Netscaler server"
        #Using try / catch block to gracefully catch the terminating error should one occur, will TRY to connect to the netscaler server via nitro API
        try {
            $usr = Read-Host "Enter your username that you use to connect to netscaler"
            $sec = Read-Host "Enter your password that you use to connect to netscaler" -AsSecureString
            $myNSSession = Connect-NSAppliance -NSAddress 10.11.12.13 -NSUserName $usr -NSPassword $sec -Verbose -ErrorAction Stop
        } # End of try block to see if you could connect to citrix netscaler server
        catch {
            Write-Host -ForegroundColor Yellow "Sorry something went wrong the exact error is:- $($_.exception.message)"
            break
        } # End of catch block for catching connection error
        Write-Host -ForegroundColor Green "You are now connected to the Citrix Netscaler Server, about to disable the required machine"
        #Get the user to confirm that they are happy to continue just in-case incorrect server name was entered, or a change of plan has happened in the time it took to start the script
        $Confirmation = Read-Host "Are you sure you want to disable $ComputerName y/n? Enter Y to continue or N to exit"
        # If the user answered y or Y then the following code will be run
        if ($Confirmation -match "[Yy]") {
            Write-Host -ForegroundColor Green "Thank you for confirming you wish to disable $ComputerName this will now be done with a graceful exit of $Graceful and a $DelayInSeconds second delay"
            #Adding Whatif support Using a try / catch block to gracefully catch the terminating error should one occur will TRY to POST the REST API action
            try {
                $payload = @{name = "$ComputerName"; delay = "$DelayInSeconds"; graceful = "$Graceful" }
                Invoke-NSNitroRestApi -NSSession $myNSSession -OperationMethod POST -ResourceType service -Payload $payload -Action disable -Verbose -ErrorAction Stop
            }
            catch {
                Write-Host -ForegroundColor Yellow "Sorry something went wrong the exact error is:- $($_.exception.message)"
                Disconnect-NSAppliance -NSSession $myNSSession
                #Removing below variables for security purposes
                Remove-Variable $usr
                Remove-Variable $sec
                break
            }
            Write-Host -ForegroundColor Green "All done now exiting netscaler session"
            Disconnect-NSAppliance -NSSession $myNSSession
            #Removing below variables for security purposes
            Remove-Variable $usr
            Remove-Variable $sec
            #Set a web counter as normally IIS servers for 600 seconds
            #so the below loop will complete a total of 12 times waiting 50 seconds between intervals to make sure number is going down on websites
            $ArrayHashData = @()
            For ($i = 1; $i -lt 12; $i++) {
                Write-Host -ForegroundColor Green "Checking current web connections to $ComputerName run $i of 12 stats will be refreshed automatically until complete"
                $HashData = [ordered]@{
                    Run   = $i;
                    Stats = (Get-Counter -ComputerName $ComputerName -Counter "\\$ComputerName\Web Service(*)\Current Connections").Countersamples
                }
                $ArrayHashData += $HashData
                #Make a delay visible to user
                For ($ii = 50; $ii -gt 1; $ii--) {
                    Write-Progress -Activity "Waiting until next run " -SecondsRemaining $ii
                    Start-Sleep 1
                } # End of INNER FOR loop
            } # End of FOR loop
            #Display some stats
            Write-Host -ForegroundColor Green "A total of $($ArrayHashData.Count) samples were taken"
            Write-Host -ForegroundColor Green "The first sample counter had a total of $($ArrayHashData[0].Stats) current connections"
            Write-Host -ForegroundColor Green "The last sample counter had a total of $($ArrayHashData[-1].Stats) current connections"
            Write-Host -ForegroundColor Green "The statistics of current connections of the total trace will now be shown from first to last trace samples"
            foreach ($stat in $ArrayHashData) {
                Write-Host -ForegroundColor Green "Run $($stat.Run) had $($stat.Stats) connections"
            }
        } # End of if block if you answered either y or Y to continue
        # If the user answered n or N or even anything other than y or Y the script will exit without anything being done
        else {
            Write-Host -ForegroundColor Yellow "Script will now exit"
            Disconnect-NSAppliance -NSSession $myNSSession
            #Removing below variables for security purposes
            Remove-Variable $usr
            Remove-Variable $sec
        } # End of else block if you didn't answer y or Y to the continue question with no action taken
    } # End of PROCESS Block
    END {
        $end = Get-Date
        $timespan = New-TimeSpan -start $start -end $end
        Write-Host -ForegroundColor Green "Finished in $($timespan.TotalSeconds)"
        $msg = "[$end] Ending $($myinvocation.MyCommand)"
        Write-Information $msg -Tags meta, end
        Write-Verbose $msg
        Write-Host -ForegroundColor Green "The script has now finished thank you for using it."
    } # End of END block
} #End of Function

<#
   .Synopsis
    Automates the proceedure to enable a given computer name within Citrix Netscaler Traffic Management Load Balancer
    .Description
    This script was written to automate the process of enabling a server within Citrix Netscaler using the Nitro API wrapped in a PowerShell module. This script will also run a PERFMON trace of current user connections to all websites and display this to you so you can verify that the results have changed through each trace run on the PERFMON trace. There is only one parameter required to run this function, which is the COMPUTERNAME parameter as shown in the example below.
   .Example
    Enable-NetscalerServer -ComputerName QAHTEST01
    This will enable the QAHTEST01 server immediately
   .Example
    "QAHTEST01" | Enable-NetscalerServer
    This will enable the QAHTEST01 server immediately passing the COMPUTERNAME parameter via the pipeline
   .Notes
    NAME: Enable-NetscalerServer
    AUTHOR: Adam Bacon
    LASTEDIT: 2022-04-16
    REFERENCE: https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/basic/service/
    KEYWORDS: Netscaler Automation
   .Link
    https://github.com/psDevUK/netscaler-configuration
#>
Function Enable-NetscalerServer {
    [CmdletBinding()]
    Param
    (
        # The computer name for the server you wish to enable in citrix traffic management load balancer
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, HelpMessage = "Enter the server name to enable in citrix traffic management load balancer")]
        [ValidateNotNullorEmpty()]
        [string]$ComputerName
    )

    BEGIN {
        #log time to dispay how long script took to complete
        $start = Get-Date
        $msg = "[$start] Starting $($myinvocation.MyCommand)"
        Write-Verbose $msg
        Write-Host -ForegroundColor Green "Checking if required module is present on machine..."
        #First need to check if the module is installed if not need to get this
        if ((Get-Module -ListAvailable | Where-Object { $_.Name -eq "NetScalerConfiguration" }).count -lt 1) {
            Write-Warning "Required module not installed, please wait whilst this is fixed"
            #Module is not listed in any of the default module folders
            #Get the current user session module path
            $modulepath = ($env:PSModulePath -split ';' | Select-String "Users") -replace '\s+', ''
            Set-Location $env:USERPROFILE
            Invoke-WebRequest -OutFile master.zip "https://github.com/psDevUK/netscaler-configuration/archive/refs/heads/master.zip"
            Unblock-File "$env:USERPROFILE\master.zip"
            Expand-Archive -Path "$env:USERPROFILE\master.zip" -OutputPath "$env:USERPROFILE\" -ShowProgress -Verbose
            Copy-Item -Path "$env:USERPROFILE\netscaler-configuration-master\Modules\NetScalerConfiguration" -Recurse -Destination "$modulepath"
            Remove-Item -Path "$env:USERPROFILE\master.zip" -Force
            Remove-Item -Path "$env:USERPROFILE\netscaler-configuration-master\" -Recurse -Force
            Write-Host -ForegroundColor Green "Module now installed script will proceed"
        } #End of if check to see if module was installed or not
    }
    PROCESS {
        #Now ready to import the module so the real automation can begin
        Write-Host -ForegroundColor Green "About to import the netscaler module"
        Import-Module NetScalerConfiguration -WarningAction SilentlyContinue
        Write-Host -ForegroundColor Green "Now connecting to the Citrix Netscaler server"
        #Using a TRY /CATCH block to see if a connection to the netscaler server can be made, and to gracefully catch the terminating error should one occur
        try {
            $usr = Read-Host "Enter your username that you use to connect to netscaler"
            #Securely store password in memory then discard it once finished for security purposes
            $sec = Read-Host "Enter your password that you use to connect to netscaler" -AsSecureString
            $myNSSession = Connect-NSAppliance -NSAddress 10.11.12.13 -NSUserName $usr -NSPassword $sec -Verbose -ErrorAction Stop
        } # End of try block to see if you could connect to citrix netscaler server
        catch {
            Write-Host -ForegroundColor Yellow "Sorry something went wrong the exact error is:- $($_.exception.message)"
            break
        } # End of catch block for catching connection error
        Write-Host -ForegroundColor Green "You are now connected to the Citrix Netscaler Server, about to enable the required machine"
        #Get user confirmation that they are happy with the computer name they have entered to ENABLE in the citrix traffic management load balancer
        $Confirmation = Read-Host "Are you sure you want to enable $ComputerName y/n? Enter Y to continue or N to exit"
        # If the user enters either y or Y the following code will be run
        if ($Confirmation -match "[Yy]") {
            Write-Host -ForegroundColor Green "Thank you for confirming you wish to enable $ComputerName this will be done now"
            #Adding Whatif support Using a TRY / CATCH block to POST to the REST API of citrix nitro to ENABLE the computer name specified, and should a terminating error happen to then grafully catch it
            try {
                $payload = @{name = "$ComputerName" }
                Invoke-NSNitroRestApi -NSSession $myNSSession -OperationMethod POST -ResourceType service -Payload $payload -Action enable -Verbose -ErrorAction Stop
            }
            catch {
                Write-Host -ForegroundColor Yellow "Sorry something went wrong the exact error is:- $($_.exception.message)"
                Disconnect-NSAppliance -NSSession $myNSSession
                #Removing below variables from powershell memory so they can no longer be used or read
                Remove-Variable $usr
                Remove-Variable $sec
                break
            }
            Write-Host -ForegroundColor Green "All done now exiting netscaler session"
            Disconnect-NSAppliance -NSSession $myNSSession
            #Removing below variables from powershell memory so they can no longer be used or read
            Remove-Variable $usr
            Remove-Variable $sec
            #Set a web counter as normally IIS servers for 120 seconds to monitor increase in web traffic on all websites
            #so the below loop will complete a total of 4 times waiting 30 seconds between intervals to make sure number is going down on websites
            $ArrayHashData = @()
            For ($i = 1; $i -lt 4; $i++) {
                Write-Host -ForegroundColor Green "Checking current web connections to $ComputerName run $i of 4 stats will be refreshed automatically until complete"
                $HashData = [ordered]@{
                    Run   = $i;
                    Stats = (Get-Counter -ComputerName $ComputerName -Counter "\\$ComputerName\Web Service(*)\Current Connections").Countersamples
                }
                $ArrayHashData += $HashData
                For ($ii = 30; $ii -gt 1; $ii--) {
                    Write-Progress -Activity "Waiting until next run " -SecondsRemaining $ii
                    Start-Sleep 1
                } # End of inner FOR loop
            } # End outer FOR loop
            #Display some stats
            Write-Host -ForegroundColor Green "A total of $($ArrayHashData.Count) samples were taken"
            Write-Host -ForegroundColor Green "The first sample counter had a total of $($ArrayHashData[0].Stats) current connections"
            Write-Host -ForegroundColor Green "The last sample counter had a total of $($ArrayHashData[-1].Stats) current connections"
            Write-Host -ForegroundColor Green "The statistics of current connections of the total trace will now be shown from first to last trace samples"
            foreach ($stat in $ArrayHashData) {
                Write-Host -ForegroundColor Green "Run $($stat.Run) had $($stat.Stats) connections"
            }
        } # End of if block if you answered either y or Y to continue
        # If the user entered n or N or anything other than Y or y then the below code is run and nothing is changed
        else {
            Write-Host -ForegroundColor Yellow "Script will now exit"
            Disconnect-NSAppliance -NSSession $myNSSession
            #Removing below variables for security purposes
            Remove-Variable $usr
            Remove-Variable $sec
        } # End of else block if you didn't answer y or Y to the continue question with no action taken
    } #End of PROCESS block
    END {
        $end = Get-Date
        $timespan = New-TimeSpan -start $start -end $end
        Write-Host -ForegroundColor Green "Finished in $($timespan.TotalSeconds)"
        $msg = "[$end] Ending $($myinvocation.MyCommand)"
        Write-Information $msg -Tags meta, end
        Write-Verbose $msg
        Write-Host -ForegroundColor Green "The script has now finished thank you for using it."
    } #End of END block
} #End of FUNCTION