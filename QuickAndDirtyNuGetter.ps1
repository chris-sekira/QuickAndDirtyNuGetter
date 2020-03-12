# Author: Chris Sekira
# Version: 0.0.1-alpha
[CmdletBinding(DefaultParameterSetName = "UseVSSEndpointsVariableForUrlAndAuth")]
param (

    [Parameter(Mandatory = $true)]
    [string]
    [ValidateNotNullOrEmpty()]
    $PackageName,

    [Parameter(Mandatory = $true)]
    [string]
    [ValidateNotNullOrEmpty()]
    $PackageVersion,

    [Parameter(Mandatory = $false)]
    [string]
    [ValidateNotNullOrEmpty()]
    $FeedUsername = "user",

    [Parameter(Mandatory = $true, ParameterSetName = "SpecifyFeedUrl")]
    [Parameter(Mandatory = $true, ParameterSetName = "UseVSSEndpointsVariableForUrlAndAuth")]
    [Parameter(Mandatory = $true, ParameterSetName = "SpecifynugetCredential")]
    [ValidateNotNullOrEmpty()]
    [string]
    $FeedUrl,

    [Parameter(Mandatory = $false, ParameterSetName = "SpecifyFeedUrl")]
    [string]
    [ValidateNotNullOrEmpty()]
    $FeedPasswordEnvironmentVariableName = 'VSS_NUGET_ACCESSTOKEN',

    [Parameter(Mandatory = $true, ParameterSetName = "SpecifynugetCredential")]
    [ValidateNotNullOrEmpty()]
    [pscredential]
    $FeedCredential,

    [Parameter(Mandatory = $false)]
    [string]
    [ValidateNotNullOrEmpty()]
    [ValidateScript( { Test-Path -Path $_ -PathType Container -IsValid }, ErrorMessage = "The path '{0}' is not valid or does not exist.")]
    $RootDownloadDirectory = (Join-Path -Path $PWD -ChildPath 'NuGetPackages'),

    [Parameter()]
    [switch]
    $IncludePackageVersion = $false,

    [Parameter()]
    [switch]
    $KeepPackageArchiveAfterExtraction = $false
)

class NuGetEndpointInfo
{
    [string] $Endpoint;

    [string] $Username;

    [string] $Password;

}

class NuGetEndpointsCollection
{
    [NuGetEndpointInfo[]] $EndpointCredentials;
}

function DownloadNuGetPackageToLocation
{
    Param (
        [string] $FeedUrl,
        [pscredential] $FeedCredentials,
        [string] $PackageName,
        [string] $PackageVersion,
        [string] $DownloadDirectory,
        [switch] $IncludePackageVersion = $false,
        [switch] $KeepPackageAfterExtraction = $false
    )

    if (!(Test-Path -Path $DownloadDirectory -PathType Container))
    {
        New-Item -ItemType Directory -Path $DownloadDirectory -Force | Out-Null;
    }

    # Generate random string to represent new PackageSource name
    $tempRepositoryName = [guid]::NewGuid().ToString().Replace('-', '');
    Write-Debug "Temporarily Creating PackageSource '$tempRepositoryName' for '$FeedUrl'"

    # Ignore any progress bars/etc
    $private:ProgressPreference = 'SilentlyContinue'

    try
    {
        # Temporarily register the PackageSource without credentials
        Register-PackageSource -Name $tempRepositoryName -ProviderName 'NuGet' -Location $FeedUrl  -Trusted -ForceBootstrap -Force -SkipValidate | Out-Null;

        # Download the package and parse it's installation folder
        $downloadedPackage = Install-Package -ProviderName 'NuGet' -Source $tempRepositoryName -Credential $FeedCredentials -Name $PackageName -RequiredVersion $PackageVersion -Destination $DownloadDirectory -ExcludeVersion:(!$IncludePackageVersion) -SkipDependencies -Force;
        $payloadDirectories = $downloadedPackage.Payload.Directories
        $packageDirectory = Join-Path -Path $payloadDirectories.Location -ChildPath $payloadDirectories.Name

        Write-Host "Downloaded Package: '$($downloadedPackage.Name)' Version: '$($downloadedPackage.Version)' Location: '$packageDirectory'"

        # Cleanup the .nupkg that was downloaded unless specified
        if (!$KeepPackageAfterExtraction)
        {
            Remove-Item -Path $packageDirectory -Include "$PackageName*.nupkg" -Recurse | Out-Null;
        }
    }
    finally
    {
        # Always delete the temporary package source
        Unregister-PackageSource -Source $tempRepositoryName -Force -ErrorAction SilentlyContinue
    }
}


function Get-NuGetEndpointsCollection
{
    [OutputType([NuGetEndpointsCollection])]
    [CmdletBinding(DefaultParameterSetName = "UseEnvironmentVariable")]
    Param(
        [Parameter(Mandatory = $false, ParameterSetName = "UseEnvironmentVariable")]
        [ValidateNotNullOrEmpty()]
        [string]
        $EnvironmentVariableName = 'VSS_NUGET_EXTERNAL_FEED_ENDPOINTS',

        [Parameter(Mandatory = $true, ParameterSetName = "SpecifyJson")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Json
    )
    Begin
    {
        $endpointJsonSchema = '{"$schema":"http://json-schema.org/draft-07/schema","$id":"http://example.com/nuget-endpoint-schema.json","type":"object","properties":{"endpointCredentials":{"type":"array","uniqueItems":true,"items":{"type":"object","properties":{"endpoint":{"type":"string","minLength":1,"not":{"type":"null"}},"username":{"type":"string","minLength":1,"not":{"type":"null"}},"password":{"type":"string","minLength":1,"not":{"type":"null"}}},"required":["endpoint","username","password"],"additionalProperties":false},"minItems":1,"additionalItems":false}},"required":["endpointCredentials"],"additionalProperties":false}'
    }
    Process
    {
        if ($PSCmdlet.ParameterSetName -eq "SpecifyJson")
        {
            $jsonString = $Json;
        }
        else
        {
            try
            {
                $jsonString = Get-Item -Path "env:$EnvironmentVariableName"
            }
            catch
            {
                Write-Error "The environment variable $EnvironmentVariableName was not found";
                exit 1;
            }
        }

        if (!(Test-Json -Json $jsonString -ErrorAction SilentlyContinue))
        {
            Write-Error "The value $jsonString is not valid JSON and cannot be parsed"
        }

        if (Test-Json -Json $jsonString -Schema $endpointJsonSchema -ErrorAction SilentlyContinue)
        {
            return [NuGetEndpointsCollection] (ConvertFrom-Json -InputObject $jsonString -Depth 100)
        }
        else
        {
            Write-Error "The value $jsonString did not match the schema for NuGet Endpoint Environment Variables";
            exit 1;
        }
    }

}

switch -Exact ($PSCmdlet.ParameterSetName)
{
    'UseVSSEndpointsVariableForUrlAndAuth'
    {
        $endpointCollection = Get-NuGetEndpointsCollection -Json $env:VSS_NUGET_EXTERNAL_FEED_ENDPOINTS

        $matchedEndpointCredentials = $endpointCollection.EndpointCredentials | Where-Object -FilterScript { $_.Endpoint -ieq $FeedUrl } | Select-Object -First 1

        if (!$matchedEndpointCredentials)
        {
            Write-Error "No value in the VSS_NUGET_EXTERNAL_FEED_ENDPOINTS variable matched the FeedUrl value $FeedUrl";
            exit 1;
        }

        $nugetEndpoint = $matchedEndpointCredentials.Endpoint
        $nugetCredential = [pscredential]::new($FeedUsername, (ConvertTo-SecureString $matchedEndpointCredentials.Password -AsPlainText -Force));
    }
    'SpecifynugetCredential'
    {
        $nugetEndpoint = $FeedUrl;
        $nugetCredential = $FeedCredential
    }
    'SpecifyFeedUrl'
    {
        try
        {
            $feedPasswordEnvVarValue = Get-Item -Path "env:$FeedPasswordEnvironmentVariableName";
        }
        catch
        {
            Write-Error "The environment variable $FeedPasswordEnvironmentVariableName was not found";
            exit 1;
        }
        $nugetCredential = [pscredential]::new($FeedUsername, (ConvertTo-SecureString $feedPasswordEnvVarValue -AsPlainText -Force));
        $nugetEndpoint = $FeedUrl
    }
    Default
    {
        Write-Error "Unexpected error, a ParameterSet was not matched. Yeet?"
        exit 1;
    }

}

DownloadNuGetPackageToLocation -FeedUrl $nugetEndpoint -FeedCredentials $nugetCredential -PackageName $PackageName -PackageVersion $PackageVersion -DownloadDirectory $RootDownloadDirectory -IncludePackageVersion:$IncludePackageVersion -KeepPackageAfterExtraction:$KeepPackageArchiveAfterExtraction
