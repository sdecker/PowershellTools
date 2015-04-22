######################################################################################
# Written by Ashley Poole  -  http://www.ashleypoole.co.uk                           #
#                                                                                    #
# Checks servers SSL implementation for the given host(s).                           #
# This is achived by consuming SSL Labs Assessment Api Via SSLLWrapper (Api Wrapper) #
######################################################################################

#region Construction
[CmdletBinding(DefaultParameterSetName='passedHost')]
Param
(
 	[Parameter(Mandatory=$true,position=0,ParameterSetName='passedHost')]
	[ValidateNotNullOrEmpty()]
	[String[]]
	[alias("host")]
	[alias("hostInput")]
	$Hostname,

	[Parameter(Mandatory=$true,ParameterSetName='HostFromFile')]
	[ValidateNotNullOrEmpty()]
	[String]
	[alias("hosts")]
	[alias("hostsInput")]
    [ValidateScript({Test-Path $_})]
	$Path,

 	[Parameter(Mandatory=$false,ParameterSetName='passedHost')]
	[Parameter(Mandatory=$false,ParameterSetName='HostFromFile')]
	[switch]
	[alias("endpointdetails")]
	$WriteEndpointDetails,

 	[Parameter(Mandatory=$false,ParameterSetName='passedHost')]
	[Parameter(Mandatory=$false,ParameterSetName='HostFromFile')]
	[switch]
	$Raw

)

$ErrorActionPreference = "stop"

# Variables
$SSLLabsApiUrl = "https://api.ssllabs.com/api/v2/"

switch ($PsCmdlet.ParameterSetName) {

    'HostFromFile'
    {
        $Hosts = Get-Content -Path $Path
        break;
    }

    'passedHost'
    {
        $Hosts = @($hostname) 
        break;
    }

    default
    {
        # Should never get here
        Throw "Invalid parameter"
    }
}

$SSLLWrapperFilePath = $PSScriptRoot.ToString() + "\SSLLWrapper\SSLLWrapper.dll"
$NewtonsoftJsonFilePath = $PSScriptRoot.ToString() + "\SSLLWrapper\NewtonSoft.Json.dll"

# Loading DLLs
Add-Type -Path $NewtonsoftJsonFilePath
Add-Type -Path $SSLLWrapperFilePath

# Creating SSLLService
$SSLService = New-Object SSLLWrapper.SSLLService($SSLLabsApiUrl)

#endregion

clear
Write-Host "`n"
Write-Host "Starting analysis... This process may take several minutes per endpoint, per host..."
Write-Host "`n"

# Testing if Api is online
$ApiInfo = $SSLService.Info()

If ($ApiInfo.Online -ne $true)
{
    # Api is not online. Exiting.
    Write-Error "Api " $SSLLabsApiUrl " is not online, contactable or is incorrect.`r`nExiting."
}

if ($Raw) 
{
    $RawOutput = @()
}


Foreach ($myHost In $Hosts)
{

    # Analysising host with a maximum of a 5 minute wait time
    #$HostAnalysis = $SSLService.AutomaticAnalyze($myHost, 500, 10)
    
    if ($myHost -notlike 'https://.*')
    {
      Write-host "Adding HTTPS:// because the .Net library expects it"
      
      $myHost = "https://" + $myHost
    }
    
    Write-Host "**********************************************************************************"
    Write-Host $myHost " - " (Get-Date -format "dd-MM-yyyy HH:mm:ss")
    Write-Host "**********************************************************************************"

    $HostAnalysis = $SSLService.AutomaticAnalyze($myHost, [SSLLWrapper.SSLLService+Publish]::Off, [SSLLWrapper.SSLLService+ClearCache]::Ignore, [SSLLWrapper.SSLLService+FromCache]::On,[SSLLWrapper.SSLLService+All]::On,500,10)

    if ($Raw) 
    {
        $RawOutput += $HostAnalysis
    }
    else
    {

        Write-Host "Endpoints #           :" ($HostAnalysis.endpoints).Count

        if ($HostAnalysis.HasErrorOccurred) 
        {
            Write-Host "Analysis Error        :" $hostAnalysis.Errors.message
        }

        Write-Host "`n"

        Foreach ($Endpoint In $HostAnalysis.endpoints)
        {
            Write-Host "Endpoint              :" $Endpoint.ipAddress

            Write-Host "Grade                 :" $Endpoint.grade
            Write-Host "Has Warnings          :" $Endpoint.hasWarnings

            # Output extra details if EndpointDetails is true and analysis data is good (i.e check grade exists)
            If (($WriteEndpointDetails) -and ($Endpoint.grade))
            {
                $EndpointAnalysis = $SSLService.GetEndpointData($HostAnalysis.host, $Endpoint.ipAddress)

                Write-Host "Server Signature      :" $EndpointAnalysis.Details.serverSignature
                Write-Host "Cert Chain Issue      :" $EndpointAnalysis.Details.chain.issues
                Write-Host "Forward Secrecy       :" $EndpointAnalysis.Details.forwardSecrecy
                Write-Host "Supports RC4          :" $EndpointAnalysis.Details.supportsRc4
                Write-Host "Beast Vulnerable      :" $EndpointAnalysis.Details.vulnBeast
                Write-Host "Heartbleed Vulnerable :" $EndpointAnalysis.Details.heartbleed

				switch ($EndpointAnalysis.Details.renegSupport)
				{
					# bit 0 (1) - set if insecure client-initiated renegotiation is supported
					0 { $Renegotiation = "Insecure client-initiated supported"}
					# bit 1 (2) - set if secure renegotiation is supported
					1 { $Renegotiation = "secure renegotiation supported"}
					# bit 2 (4) - set if secure client-initiated renegotiation is supported
					2 { $Renegotiation = "client-initiated renegotiation supported"}
					# bit 3 (8) - set if the server requires secure renegotiation support
					3 { $Renegotiation = "requires secure renegotiation"}
				}
				Write-Host "Renegotiation Support : " $Renegotiation

				switch ($EndpointAnalysis.Details.sessionResumption)
				{
					# 0 - session resumption is not enabled and we're seeing empty session IDs
					0 { $sessionResumption = "session resumption not enabled"}
					# 1 - endpoint returns session IDs, but sessions are not resumed
					1 { $sessionResumption = "endpoint returns session IDs, but sessions not resumed"}
					# 2 - session resumption is enabled
					2 { $sessionResumption = "session resumption enabled"}
				}
				Write-Host "Renegotiation Support : " $sessionResumption


<#

key #Expand
cert #Expand
chain #Expand
protocols 
suites #Expand
sessionResumption
# 0 - session resumption is not enabled and we're seeing empty session IDs
# 1 - endpoint returns session IDs, but sessions are not resumed
# 2 - session resumption is enabled
compressionMethods
# bit 0 is set for DEFLATE
supportsNpn
sessionTickets
# bit 0 (1) - set if session tickets are supported
# bit 1 (2) - set if the implementation is faulty [not implemented]
# bit 2 (4) - set if the server is intolerant to the extension
ocspStapling
sniRequired
heartbeat
openSslCcs
# -1 - test failed
# 0 - unknown
# 1 - not vulnerable
# 2 - possibly vulnerable, but not exploitable
# 3 - vulnerable and exploitable
poodleTls
# -1 - test failed
# 0 - unknown
# 1 - not vulnerable
# 2 - vulnerable

forwardSecrecy - indicates support for Forward Secrecy
# bit 0 (1) - set if at least one browser from our simulations negotiated a Forward Secrecy suite.
# bit 1 (2) - set based on Simulator results if FS is achieved with modern clients. For example, the server supports ECDHE suites, but not DHE.
# bit 2 (4) - set if all simulated clients achieve FS. In other words, this requires an ECDHE + DHE combination to be supported.

#>            
				$EndpointAnalysis.Details | Out-String | Write-Verbose
            }
            Write-Host "`n"
        }
        Write-Host "`r`n"
    }

}

if ($Raw) 
{
    $RawOutput
}
