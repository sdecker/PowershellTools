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
                Write-Host "Poodle Vulnerable     :" $EndpointAnalysis.Details.poodleTls
            
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
