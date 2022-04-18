<#
   .Synopsis
    Automates the proceedure to disable a given computer name within Citrix Netscaler Traffic Management Load Balancer
    .Description
    This script was written to automate the process of disabling a server within Citrix Netscaler using the Nitro API wrapped in a PowerShell module. This script will also has the capability to run a PERFMON trace of current user connections to all websites and display this to you so you can verify that the results have changed through each trace run on the PERFMON trace. You enable this by passing the SWITCH parameter -PerfmonWebTrace when running the function. This function only requires TWO paramters COMPUTERNAME parameter to be passed to it and a NETSCALERSERVERIPADDRESS which has 3 shorter aliases, but as the examples show you can over-ride the default settings set on the other two parameters. This function also supports the common variables such as -Confirm -Verbose -Whatif
   .Example
    "YOUR_SERVER_NAME" | Disable-NetscalerServer -IP "10.11.12.13" -Whatif
    This will display the whatif steps it will take to disable the YOUR_SERVER_NAME server with the default graceful exit of YES and a delay of 600 seconds, passing the COMPUTERNAME parameter via pipeline
   .Example
    Disable-NetscalerServer -ComputerName YOUR_SERVER_NAME -NetscalerServerIPAddress "10.0.0.1" -DelayInSeconds "100" -Confirm
    This will disable the YOUR_SERVER_NAME server with the default graceful exit of YES and a delay of 100 seconds, and prompt the user to continue or not at each whatif stage
   .Example
    Disable-NetscalerServer -ComputerName YOUR_SERVER_NAME -IP "10.0.0.2" -Graceful "NO" -DelayInSeconds "0" -PerfmonWebTrace
    This will disable the YOUR_SERVER_NAME server with the default graceful exit of NO and a delay of 0 seconds all connections terminated immediately this will then run a Perfmon trace on the remote computer to bring you back current web connections for all sites hosted on that machine
   .Example
    "YOUR_SERVER_NAME" | Disable-NetscalerServer -NS "10.11.12.13" -verbose
    This will display the verbose output whilst it disables the YOUR_SERVER_NAME server with the default graceful exit of YES and a delay of 600 seconds, passing the COMPUTERNAME parameter via pipeline
   .Notes
    NAME: Disable-NetscalerServer
    AUTHOR: Adam Bacon
    LASTEDIT: 2022-04-16
    REFERENCE: https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/basic/service/
    KEYWORDS: Netscaler Automation
   .Link
    https://github.com/psDevUK/netscaler-configuration
    https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/latest/configuration/basic/service/
#>
Function Disable-NetscalerServer {
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        # The computer name for the server you wish to disable in citrix traffic management load balancer
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, HelpMessage = "Enter the server name to disable in citrix traffic management load balancer")]
        [ValidateNotNullorEmpty()]
        [ValidatePattern("^\w+$")]
        [Alias("Server","Machine","Name")]
        [string]$ComputerName,

        [Parameter(Mandatory,Position=1)]
        [ValidateScript({$_ -match [IPAddress]$_ })]
        [ValidateNotNullorEmpty()]
        [Alias("Netscaler","IP","NS")]
        [string]$NetScalerServerIPAddress,

        # Graceful exit parameter defaulted to YES
        [Parameter(HelpMessage = "Shut down gracefully, not accepting any new connections, and disabling the service when all of its connections are closed.")]
        [ValidateSet("YES", "NO")]
        $Graceful = "YES",

        # Timeout period for exiting default 600
        [Parameter(HelpMessage = "Time, in seconds, allocated for a shutdown of the services in the service group. After the delay time expires, no requests are sent to the service, and the service is marked as unavailable (OUT OF SERVICE)")]
        [ValidatePattern("[0-9]")]
        [ValidateRange(0, 3)]
        $DelayInSeconds = "600",

        [Parameter(HelpMessage="Use this switch if you would like to include the perfmon trace in the function")]
        [switch] $PerfmonWebTrace
    )
    BEGIN {
        #log a start time to record script time
        $start = Get-Date
        $msg = "[$start] Starting $($myinvocation.MyCommand)"
        Write-Verbose $msg
        Write-Host -ForegroundColor Green "Checking if 'PSlogging' module is present on $($env:COMPUTERNAME) please wait.."
        if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Check if 'PSLogging' module installed to log output from script")){
      if ((Get-Module -ListAvailable | Where-Object { $_.Name -eq "PSLogging" }).count -lt 1) {
            Write-Warning "Required module not installed, please wait whilst this is fixed"
            #Module is not listed in any of the default module folders
            #Get the current user session module path
            $modulepath = ($env:PSModulePath -split ';' | Select-String "Users") -replace '\s+', ''
            Set-Location $env:USERPROFILE
            Invoke-WebRequest -OutFile "PSLogging-master.zip" "https://github.com/psDevUK/PSLogging/archive/refs/heads/master.zip"
            Unblock-File "$env:USERPROFILE\PSLogging-master.zip"
            Expand-Archive -Path "$env:USERPROFILE\PSLogging-master.zip" -OutputPath "$env:USERPROFILE\" -ShowProgress -Verbose
            Copy-Item -Path "$env:USERPROFILE\PSLogging-master\Module\PSLogging" -Recurse -Destination "$modulepath"
            Remove-Item -Path "$env:USERPROFILE\PSLogging-master.zip" -Force
            Remove-Item -Path "$env:USERPROFILE\PSLogging-master\" -Recurse -Force
         Write-Host -ForegroundColor Green "Module now installed script will proceed"
        } #End of if check to see if module was installed or not
    } #End should process check on downloading PSLogging module
        Write-Host -ForegroundColor Green "Checking if 'NetScalerConfiguration' module is present on $($env:COMPUTERNAME) please wait..."
        #First need to check if the module is installed if not need to get this
        if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Check if 'NetScalerConfiguration' module installed to run script")){
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
      } # End Whatif check for downloading module
    } # End of BEGIN block
    PROCESS {
        #Import PSLogging module to give an output of this session run no more need for write-host
        Import-Module PSLogging
        #Log File Info
        $fLogPath = "$env:TEMP\"
        $fLogName = "Disable-NetscalerServer-$($ComputerName).log"
        $fLogFile = Join-Path -Path $fLogPath -ChildPath $fLogName
        Write-Host -ForegroundColor Yellow "A LOG FILE WILL BE CREATED HERE:- $($fLogFile) TO RECORD OUTPUT FROM THIS SESSION OF RUNNING IT"
        Write-LogInfo -LogPath $fLogFile -Message "Started $($myinvocation.MyCommand) at $($start)"
        Write-LogInfo -LogPath $fLogFile -Message "PsLogging module imported and started" -TimeStamp -ToScreen
        #Now ready to import the module so the real automation can begin
        Write-LogInfo -LogPath $fLogFile -Message "About to import the netscaler module" -TimeStamp -ToScreen
        Import-Module NetScalerConfiguration -WarningAction SilentlyContinue
        Write-LogInfo -LogPath $fLogFile -Message "NetScaler module imported and started" -TimeStamp -ToScreen
        Write-LogInfo -LogPath $fLogFile -Message "Now connecting to the Netscaler server using IP $($NetScalerServerIPAddress)" -TimeStamp -ToScreen
        if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Will connect now to the netscaler server to invoke rest api command")){
        #Using try / catch block to gracefully catch the terminating error should one occur, will TRY to connect to the netscaler server via nitro API
        try {
            $usr = Read-Host "Enter your username that you use to connect to netscaler"
            $sec = Read-Host "Enter your password that you use to connect to netscaler" -AsSecureString
            $myNSSession = Connect-NSAppliance -NSAddress $NetScalerServerIPAddress -NSUserName $usr -NSPassword $sec -Verbose -ErrorAction Stop
        } # End of try block to see if you could connect to citrix netscaler server
        catch {
            Write-LogError -LogPath $fLogFile -Message "Something bad happened:- $($_.Exception.message)" -TimeStamp -ToScreen
            break
        } # End of catch block for catching connection error
       } # End Whatif Connection
        Write-LogInfo -LogPath $fLogFile -Message "$($usr) has now successfully connected to the remote Citrix NetScaler Server" -TimeStamp -ToScreen
        #Get the user to confirm that they are happy to continue just in-case incorrect server name was entered, or a change of plan has happened in the time it took to start the script
        $Confirmation = Read-Host "Are you sure you want to use a graceful request of $Graceful and a delay of $DelayInSeconds to disable $ComputerName in Citrix NetScaler y/n? ENTER Y TO CONTINUE OR N TO EXIT"
        # If the user answered y or Y then the following code will be run
        if ($Confirmation -match "[Yy]") {
        Write-LogInfo -LogPath $fLogFile -Message "$($env:USERNAME) has chosen to disable $($ComputerName) within Traffic Management Load Balance" -TimeStamp -ToScreen
            if($PSCmdlet.ShouldProcess($ComputerName,"About to disable the target computer name in traffic management load balance citrix netscaler")){
            Write-LogInfo -LogPath $fLogFile -Message "Thank you for confirming you wish to disable $ComputerName this will now be done with a graceful exit of $Graceful and a $DelayInSeconds second delay" -TimeStamp -ToScreen
            #Adding Whatif support Using a try / catch block to gracefully catch the terminating error should one occur will TRY to POST the REST API action
            try {
                $payload = @{name = "$ComputerName"; delay = "$DelayInSeconds"; graceful = "$Graceful" }
                Invoke-NSNitroRestApi -NSSession $myNSSession -OperationMethod POST -ResourceType service -Payload $payload -Action disable -Verbose -ErrorAction Stop
            }
            catch {
                Write-LogError -LogPath $fLogFile -Message "Something bad has happpend:- $($_.Exception.message)" -TimeStamp -ToScreen
                Disconnect-NSAppliance -NSSession $myNSSession -ErrorAction SilentlyContinue
                #Removing below variables for security purposes
               if(Test-Path variable:usr){Remove-Variable $usr}
                if(Test-Path variable:sec){Remove-Variable $sec}
                break
            }
            Write-LogInfo -LogPath $fLogFile -Message "$($ComputerName) has now been disabled within Traffic management Load Balance" -TimeStamp -ToScreen
            Disconnect-NSAppliance -NSSession $myNSSession -ErrorAction SilentlyContinue
            #Removing below variables for security purposes
            if(Test-Path variable:usr){Remove-Variable $usr}
            if(Test-Path variable:sec){Remove-Variable $sec}
            } # End Whatif POST API
            if ($PerfmonWebTrace.IsPresent){
            Write-LogInfo -LogPath $fLogFile -Message "PerfmonWebTrace parameter passed so now collecting Performance Monitor statistics" -TimeStamp -ToScreen
            if($PSCmdlet.ShouldProcess($ComputerName,"Will now monitor current web connections on all sites on target")){
            #Set a web counter as normally IIS servers for 600 seconds
            #so the below loop will complete a total of 12 times waiting 50 seconds between intervals to make sure number is going down on websites
            $ArrayHashData = @()
            For ($i = 1; $i -lt 12; $i++) {
                Write-LogInfo -LogPath $fLogFile -Message "Checking current web connections to $ComputerName run $i of 12 stats will be refreshed automatically until complete" -TimeStamp -ToScreen
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
            Write-LogInfo -LogPath $fLogFile -Message "A total of $($ArrayHashData.Count) samples were taken" -TimeStamp -ToScreen
            Write-LogInfo -LogPath $fLogFile -Message "The first sample counter had a total of $($ArrayHashData[0].Stats) current connections" -TimeStamp -ToScreen
            Write-LogInfo -LogPath $fLogFile -Message "The last sample counter had a total of $($ArrayHashData[-1].Stats) current connections" -TimeStamp -ToScreen
            Write-LogInfo -LogPath $fLogFile -Message "The statistics of current connections of the total trace will now be shown from first to last trace samples" -TimeStamp -ToScreen
            foreach ($stat in $ArrayHashData) {
                Write-LogInfo -LogPath $fLogFile -Message "Run $($stat.Run) had $($stat.Stats) connections" -TimeStamp -ToScreen
            }
        } # End of if block if you answered either y or Y to continue
      } #End of switch block
    } #End Whatif block on Y
        # If the user answered n or N or even anything other than y or Y the script will exit without anything being done
        else {
            Write-LogInfo -LogPath $fLogFile -Message "$($env:USERNAME) decided not to run this function against $($ComputerName) target" -TimeStamp -ToScreen
            if((Get-Variable -Name myNSSession -ErrorAction SilentlyContinue).Count -gt 0){
            Disconnect-NSAppliance -NSSession $myNSSession -ErrorAction SilentlyContinue
            }
            #Removing below variables for security purposes
            if((Get-Variable -Name usr -ErrorAction SilentlyContinue).Count -gt 0){Remove-Variable $usr}
            if((Get-Variable -Name sec -ErrorAction SilentlyContinue).Count -gt 0){Remove-Variable $sec}
        } # End of else block if you didn't answer y or Y to the continue question with no action taken
    } # End of PROCESS Block
    END {
        $end = Get-Date
        $timespan = New-TimeSpan -start $start -end $end
        Write-LogInfo -LogPath $fLogFile -Message "Finished in $(($timespan.TotalSeconds).ToString("#.##")) seconds" -TimeStamp -ToScreen
        $msg = "[$end] Ending $($myinvocation.MyCommand)"
        Write-Information $msg -Tags meta, end
        Write-Verbose $msg
        Write-LogInfo -LogPath $fLogFile -Message "Script has now ended $($end)"
        Write-Host -ForegroundColor Green "The script has now finished thank you for using it."
    } # End of END block
} #End of Function

<#
   .Synopsis
    Automates the procedure to enable a given computer name within Citrix Netscaler Traffic Management Load Balancer
    .Description
    This script was written to automate the process of enabling a server within Citrix Netscaler using the Nitro API wrapped in a PowerShell module. This script also has the capability to run a PERFMON trace of current user connections to all websites and display this to you so you can verify that the results have changed through each trace run on the PERFMON trace. You enable this with by passing the SWITCH parameter -PerfmonWebTrace. There are a total of 3 parameters and 2 required parameters to run this function, which is the COMPUTERNAME parameter and NETSCALERSERVERIPADDRESS as shown in the examples below. This function also supports the common variables such as -Confirm -Verbose -Whatif
   .Example
    Enable-NetscalerServer -ComputerName YOUR_SERVER_NAME -NetscalerServerIPAddress "10.11.11.12" -whatif
    This will show you the steps the script would take to enable the YOUR_SERVER_NAME machine without actually doing anything
   .Example
    "YOUR_SERVER_NAME" | Enable-NetscalerServer -IP "10.11.12.12" -Confirm
    This will prompt you at each process stage and will let you enable the YOUR_SERVER_NAME server immediately passing the COMPUTERNAME parameter via the pipeline
   .Example
    Enable-NetscalerServer -ComputerName YOUR_SERVER_NAME -NS "10.1.1.12" -verbose
    Will immediately enable YOUR_SERVER_NAME machine within the citrix netscaler traffic management load balance showing you verbose output along the way
   .Example
    Enable-NetscalerServer -ComputerName YOUR_SERVER_NAME -IP "10.11.11.12" -PerfmonWebTrace
    Will immediately enable YOUR_SERVER_NAME machine within the citrix netscaler traffic management load balance and run a perfmon current web connections trace on the remote machine and show statistics
   .Notes
    NAME: Enable-NetscalerServer
    AUTHOR: Adam Bacon
    LASTEDIT: 2022-04-16
    REFERENCE: https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/basic/service/
    KEYWORDS: Netscaler Automation
   .Link
    https://github.com/psDevUK/netscaler-configuration
    https://developer-docs.citrix.com/projects/netscaler-nitro-api/en/latest/configuration/basic/service/
#>
Function Enable-NetscalerServer {
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        # The computer name for the server you wish to enable in citrix traffic management load balancer
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, HelpMessage = "Enter the server name to enable in citrix traffic management load balancer")]
        [ValidateNotNullorEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory,Position=1)]
        [ValidateScript({$_ -match [IPAddress]$_ })]
        [ValidateNotNullorEmpty()]
        [Alias("Netscaler","IP","NS")]
        [string]$NetScalerServerIPAddress,

        [Parameter(HelpMessage="Use this switch if you would like to include the perfmon trace in the function")]
        [switch] $PerfmonWebTrace
    )

    BEGIN {
        #log time to dispay how long script took to complete
        $start = Get-Date
        $msg = "[$start] Starting $($myinvocation.MyCommand)"
        Write-Verbose $msg
        Write-Host -ForegroundColor Green "Checking if 'PSlogging' module is present on $($env:COMPUTERNAME) please wait.."
         if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Check if 'PSLogging' module installed to log output from script")){
      if ((Get-Module -ListAvailable | Where-Object { $_.Name -eq "PSLogging" }).count -lt 1) {
            Write-Warning "Required module not installed, please wait whilst this is fixed"
            #Module is not listed in any of the default module folders
            #Get the current user session module path
            $modulepath = ($env:PSModulePath -split ';' | Select-String "Users") -replace '\s+', ''
            Set-Location $env:USERPROFILE
            Invoke-WebRequest -OutFile "PSLogging-master.zip" "https://github.com/psDevUK/PSLogging/archive/refs/heads/master.zip"
            Unblock-File "$env:USERPROFILE\PSLogging-master.zip"
            Expand-Archive -Path "$env:USERPROFILE\PSLogging-master.zip" -OutputPath "$env:USERPROFILE\" -ShowProgress -Verbose
            Copy-Item -Path "$env:USERPROFILE\PSLogging-master\Module\PSLogging" -Recurse -Destination "$modulepath"
            Remove-Item -Path "$env:USERPROFILE\PSLogging-master.zip" -Force
            Remove-Item -Path "$env:USERPROFILE\PSLogging-master\" -Recurse -Force
         Write-Host -ForegroundColor Green "Module now installed script will proceed"
        } #End of if check to see if module was installed or not
    } #End should process check on downloading PSLogging module
        Write-Host -ForegroundColor Green "Checking if required module is present on machine..."
        if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Check if 'NetScalerConfiguration' module installed to run script")){
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
      } #End of whatif check to see if module was installed
    }
    PROCESS {
        #Import PSLogging module to give an output of this session run no more need for write-host
        Import-Module PSLogging
        #Log File Info
        $fLogPath = "$env:TEMP\"
        $fLogName = "Enable-NetscalerServer-$($ComputerName).log"
        $fLogFile = Join-Path -Path $fLogPath -ChildPath $fLogName
        Write-Host -ForegroundColor Yellow "A LOG FILE WILL BE CREATED HERE:- $($fLogFile) TO RECORD OUTPUT FROM THIS SESSION OF RUNNING IT"
        Write-LogInfo -LogPath $fLogFile -Message "Started $($myinvocation.MyCommand) at $($start)"
        Write-LogInfo -LogPath $fLogFile -Message "PsLogging module imported and started" -TimeStamp -ToScreen
        #Now ready to import the module so the real automation can begin
        Write-LogInfo -LogPath $fLogFile -Message "About to import the netscaler module" -TimeStamp -ToScreen
        Import-Module NetScalerConfiguration -WarningAction SilentlyContinue
        Write-LogInfo -LogPath $fLogFile -Message "Now connecting to the Citrix Netscaler server using IP $($NetScalerServerIPAddress)" -TimeStamp -ToScreen
        if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Will connect now to the netscaler server to invoke rest api command")){
        #Using a TRY /CATCH block to see if a connection to the netscaler server can be made, and to gracefully catch the terminating error should one occur
        try {
            $usr = Read-Host "Enter your username that you use to connect to netscaler"
            #Securely store password in memory then discard it once finished for security purposes
            $sec = Read-Host "Enter your password that you use to connect to netscaler" -AsSecureString
            $myNSSession = Connect-NSAppliance -NSAddress $NetScalerServerIPAddress -NSUserName $usr -NSPassword $sec -Verbose -ErrorAction Stop
        } # End of try block to see if you could connect to citrix netscaler server
        catch {
            Write-LogInfo -LogPath $fLogFile -Message "Sorry something went wrong the exact error is:- $($_.exception.message)" -TimeStamp -ToScreen
            break
        } # End of catch block for catching connection error
        Write-LogInfo -LogPath $fLogFile -Message "The user $($usr) is now connected to the Citrix Netscaler Server, about to enable the required machine" -TimeStamp -ToScreen
        } # End Whatif to connect to netscaler
        #Get user confirmation that they are happy with the computer name they have entered to ENABLE in the citrix traffic management load balancer
        $Confirmation = Read-Host "Are you sure you want to enable $ComputerName y/n? Enter Y to continue or N to exit"
        # If the user enters either y or Y the following code will be run
        if ($Confirmation -match "[Yy]") {
            Write-LogInfo -LogPath $fLogFile -Message "Thank you for confirming you wish to enable $ComputerName within Citrix Netscaler Traffic Management Load Balance. This will be done now" -TimeStamp -ToScreen
            if($PSCmdlet.ShouldProcess($ComputerName,"About to enable the target computer name in traffic management load balance citrix netscaler")){
            #Adding Whatif support Using a TRY / CATCH block to POST to the REST API of citrix nitro to ENABLE the computer name specified, and should a terminating error happen to then grafully catch it
            try {
                $payload = @{name = "$ComputerName" }
                Invoke-NSNitroRestApi -NSSession $myNSSession -OperationMethod POST -ResourceType service -Payload $payload -Action enable -Verbose -ErrorAction Stop
            }
            catch {
                Write-LogInfo -LogPath $fLogFile -Message "Sorry something went wrong the exact error is:- $($_.exception.message)" -TimeStamp -ToScreen
                Disconnect-NSAppliance -NSSession $myNSSession -ErrorAction SilentlyContinue
                #Removing below variables from powershell memory so they can no longer be used or read
                Remove-Variable $usr -ErrorAction SilentlyContinue
                Remove-Variable $sec -ErrorAction SilentlyContinue
                break
            }
            Write-LogInfo -LogPath $fLogFile -Message "$($ComputerName) has now been enabled. All done now exiting netscaler session" -TimeStamp -ToScreen
            Disconnect-NSAppliance -NSSession $myNSSession -ErrorAction SilentlyContinue
            #Removing below variables from powershell memory so they can no longer be used or read
            if((Get-Variable -Name usr -ErrorAction SilentlyContinue).Count -gt 0){Remove-Variable $usr}
            if((Get-Variable -Name sec -ErrorAction SilentlyContinue).Count -gt 0){Remove-Variable $sec}
            } # End Whatif on enable via nitro api

            if($PerfmonWebTrace.IsPresent){
            if($PSCmdlet.ShouldProcess($ComputerName,"Will now monitor current web connections on all sites on target")){
            #Set a web counter as normally IIS servers for 120 seconds to monitor increase in web traffic on all websites
            #so the below loop will complete a total of 4 times waiting 30 seconds between intervals to make sure number is going down on websites
            $ArrayHashData = @()
            For ($i = 1; $i -lt 4; $i++) {
                Write-LogInfo -LogPath $fLogFile -Message "Checking current web connections to $ComputerName run $i of 4 stats will be refreshed automatically until complete" -TimeStamp -ToScreen
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
            Write-LogInfo -LogPath $fLogFile -Message "A total of $($ArrayHashData.Count) samples were taken" -TimeStamp -ToScreen
            Write-LogInfo -LogPath $fLogFile -Message "The first sample counter had a total of $($ArrayHashData[0].Stats) current connections" -TimeStamp -ToScreen
            Write-LogInfo -LogPath $fLogFile -Message "The last sample counter had a total of $($ArrayHashData[-1].Stats) current connections" -TimeStamp -ToScreen
            Write-LogInfo -LogPath $fLogFile -Message "The statistics of current connections of the total trace will now be shown from first to last trace samples" -TimeStamp -ToScreen
            foreach ($stat in $ArrayHashData) {
                Write-LogInfo -LogPath $fLogFile -Message "Run $($stat.Run) had $($stat.Stats) connections" -TimeStamp -ToScreen
           } #End stats
          } #End Whatif block on Perfmon trace
         } #End Switch block
        } # End of if block if you answered either y or Y to continue
        # If the user entered n or N or anything other than Y or y then the below code is run and nothing is changed
        else {
            Write-LogInfo -LogPath $fLogFile -Message "Script will now exit with no changes made as you did not want to continue with enabling $($ComputerName)" -TimeStamp -ToScreen
            if((Get-Variable -Name myNSSession -ErrorAction SilentlyContinue).Count -gt 0){
            Disconnect-NSAppliance -NSSession $myNSSession -ErrorAction SilentlyContinue
            }
            #Removing below variables for security purposes
            if((Get-Variable -Name usr -ErrorAction SilentlyContinue).Count -gt 0){Remove-Variable $usr}
            if((Get-Variable -Name sec -ErrorAction SilentlyContinue).Count -gt 0){Remove-Variable $sec}
        } # End of else block if you didn't answer y or Y to the continue question with no action taken
    } #End of PROCESS block
    END {
        $end = Get-Date
        $timespan = New-TimeSpan -start $start -end $end
        Write-LogInfo -LogPath $fLogFile -Message "Finished in $(($timespan.TotalSeconds).ToString("#.##")) seconds" -TimeStamp -ToScreen
        $msg = "[$end] Ending $($myinvocation.MyCommand)"
        Write-Information $msg -Tags meta, end
        Write-Verbose $msg
        Write-Host -ForegroundColor Green "The script has now finished thank you for using it."
    } #End of END block
} #End of FUNCTION
