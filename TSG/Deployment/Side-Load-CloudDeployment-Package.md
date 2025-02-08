# Side load Cloud deployment package onto seed node before starting Azure Local Cluster deployment

### Description
Validation (from version 2502) may fail to download the cloud deployment package during cluster deployment. This article covers how to side load the cloud deployment package onto the seed node.

### Issue Validation
If validation fails with one of the errors below, follow [Firewall requirements](https://learn.microsoft.com/en-us/azure/azure-local/concepts/firewall-requirements) to properly configure Firewall settings:
1. HTTP status 403: The client does not have sufficient access rights to the requested server object. at DownloadCloudManifestHelper
2. The server name or address could not be resolved at DownloadDeploymentPackageAndVerifyHelper

If validation fails with one of the errors below, it is mostly due to low bandwidth and network issues. Follow this article to side load the cloud deployment package:
1. The connection was closed prematurely. at DownloadDeploymentPackageAndVerifyHelper
2. The operation timed out at DownloadCloudManifestHelper

### Steps to side load Cloud deployment package
1. Download the cloud deployment manifest file from: [CloudDeploymentManifest](https://aka.ms/AzureStackHCI/CloudDeploymentManifest)

2. Run the PowerShell script below to fetch the CloudDeploymentZip, CloudDeploymentZipVerifier, and BootstrapTool URLs from the manifest file:
```
$manifest = New-Object xml
## Update manifest path in the below line.
$manifestPath = <path to manifest xml file>
$manifest.Load($manifestPath)

Write-Host $manifest.AzureStackHciCloudDeployment.VersionSet.CloudDeploymentZip.Url
Write-Host $manifest.AzureStackHciCloudDeployment.VersionSet.CloudDeploymentZipVerifier.Url
Write-Host $manifest.AzureStackHciCloudDeployment.VersionSet.BootstrapTool.Url
```

3. Download the files from the above links and copy all three files to `C:\DeploymentPackage`.

4. Run the script below to validate the downloaded deployment package:
```
$ExpectedInIssuer ="Microsoft"
try
{
    Trace-Execution "Verify signature for the verify script which has checksum for the package"
    $verifyScript = gci -Path "C:\DeploymentPackage"   -filter Verify-CloudDeployment_*.ps1 | % { $_.FullName }

    # Signature validation below is not 100% secure as already pointed out by security team.
    # The validation is for current implementation which was approved for now.
    # The download URLs will eventually land via authenticated channel from RP at that moment this code can be removed.
    $signInfo = Get-AuthenticodeSignature -filepath $verifyScript
    if (($signInfo.Status -eq "Valid") -and ($SignInfo.SignerCertificate.Issuer.Contains($ExpectedInIssuer))) 
    {     
        Trace-Execution "Confirmed that package is signed using Microsoft certificate"
    } 
    else
    { 
        Trace-Execution "Package signature validation failed. Either package is not signed or signed using incorrect certificate"
        throw "Package signature missing or not signed with correct Microsoft certificate"
    }
    &$verifyScript -FilePath  "C:\DeploymentPackage\CloudDeployment*.zip"
}
catch
{
   throw "Cloud deployment zip not found or is corrupt please pre-stage or rerun download. Exception: $_"
}
```
5. If the above script prints **SUCCESS: CloudDeployment_<version>.zip file hash matches**, then the cloud deployment package is successfully side loaded. Continue with the cluster deployment.
