# How to Resume Add Node operation on BrownField Environment failed at SetTrustedHostsOnNewNode Step
# Description 

This article describes how to resume Add node operation on a brownfield upgraded cluster when failed at SetTrustedHostsOnNewNode.
# Symptoms
ScaleOutOperation action plan for Add node operation will fail with below message at SetTrustedHostsOnNewNode step.
```
Connecting to remote server <host-name> failed with the following error message : Access is denied.
```
# Mitigation 
Follow below steps to manually set trusted hosts and resume Add node operation by skipping the SetTrustedHostsOnNewNode step.<br/>
**1.) Run below PowerShell commands in a host to set Trusted hosts on all hosts in the cluster.**
```
# Update below line with all host names in the cluster.
$hostNames = "<host-name1>", "<host-name2>"

# Update below lines with new host's name and IP.
$newHostName = "<new-host-name>"
$newHostIp = "<new-host-ip>"

# Set existing host’s domain admin credential
$DomainAdminCredential = Get-Credential
foreach ($hostName in $hostNames) {
    $hosts += ","
    $hosts += Invoke-Command -ComputerName $hostName -ScriptBlock {
        (Get-Item -Path WSMan:\localhost\Client\TrustedHosts).Value                     
    } -Credential $DomainAdminCredential
}

# Sets trusted in all hosts in the cluster
$hosts = "$newHostName,$newHostIp"
foreach ($hostName in $hostNames)
{
    Invoke-Command -ComputerName $hostName -ScriptBlock {
        $trustedHosts = $using:hosts
        $existingTrustedHosts = (Get-Item -Path WSMan:\localhost\Client\TrustedHosts).Value
        Trace-Execution "Existing Trusted Hosts: $existingTrustedHosts"
        if (![string]::IsNullOrEmpty($existingTrustedHosts) -and $existingTrustedHosts -ne "*")
        {
            $trustedHosts = (($existingTrustedHosts.Split(",") + $trustedHosts.Split(",")) | select -uniq) -join ','
        }
        Trace-Execution "Adding Trusted Hosts: $trustedHosts"
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $trustedHosts -Force
    } -Credential $DomainAdminCredential
}
```
**Copy and save Existing Trusted Hosts value from above command's verbose**<br/>
**2.) Run below PowerShell commands in new node to set Trusted hosts on all hosts in the cluster.**
```
# Login to new node using local admin credential

# Set Brownfieldreg key in new node.
$key = try {
        Get-Item -Path "HKLM:\Software\Microsoft\LCMAzureStackStampInformation" -ErrorAction Stop
    }
    catch {
        New-Item -Path "HKLM:\Software\Microsoft\LCMAzureStackStampInformation" -Force
    }
    New-ItemProperty -Path $key.PSPath -Name "EnvironmentType" -Value "Brownfield" -Force
    
# Copy trusted from above verbose and paste below
$trustedHosts = "<copied trusted hosts from above verbose>"
$existingTrustedHosts = (Get-Item -Path WSMan:\localhost\Client\TrustedHosts).Value
Trace-Execution "Existing Trusted Hosts: $existingTrustedHosts."
if (![string]::IsNullOrEmpty($existingTrustedHosts) -and $existingTrustedHosts -ne "*")
{
    $trustedHosts = (($existingTrustedHosts.Split(",") + $trustedHosts.Split(",")) | select -uniq) -join ','
}
Trace-Execution "Adding Trusted Hosts: $trustedHosts."
Set-Item WSMan:\localhost\Client\TrustedHosts -Value $trustedHosts -Force
```
**3.) Copy below functions to PowerShell in any host(not the new node) in the cluster.**
```
function Invoke-ActionPlanInstanceWithNewXml
{
param(
[Parameter(Mandatory = $true)]
[string]
$ActionPlanPath,

        [Parameter(Mandatory = $true)]
        [Guid]
        $ReferenceActionPlanInstanceID
    )
    $ErrorActionPreference = 'Stop'
    $eceServiceClient = Create-ECEClusterServiceClient
    $inst = Get-ActionPlanInstance -eceClient $eceServiceClient -actionPlanInstanceId $ReferenceActionPlanInstanceID
    if ($inst -eq $null)
    {
        throw "Reference action plan instance not found: $ReferenceActionPlanInstanceID"
    }
    $lock = $inst.LockType -eq [Microsoft.AzureStack.Solution.Deploy.EnterpriseCloudEngine.Controllers.Models.ActionPlanInstanceExecutionLock]::ExclusiveLock
    Invoke-ActionPlanInstance -eceClient $eceServiceClient -ActionPlanPath $ActionPlanPath -Retries $inst.Retries -RuntimeParameters $inst.RuntimeParameters -ExclusiveLock:$lock | Out-Null
}

# This function MUST be invoked manually and should NOT be used in any automated scripts.
function Skip-FailedStepsInActionPlan
{
[CmdletBinding(SupportsShouldProcess,
ConfirmImpact = 'High')]
param(
[Parameter(Mandatory = $true)]
[Guid]
$ActionPlanInstanceID
)
    $ErrorActionPreference = 'Stop'
    $eceServiceClient = Create-ECEClusterServiceClient
    $inst = Get-ActionPlanInstance -eceClient $eceServiceClient -actionPlanInstanceId $ActionPlanInstanceID
    if ($inst.Status -ne "Failed")
    {
        Write-Warning "Instance is not in Failed state. Cannot skip failed steps."
        return
    }
    [xml]$progressXml = $inst.ProgressAsXml
    $failedInterfaceTasks = $progressXml.SelectNodes("//Task[@InterfaceType and @Status='Error']")
    if ($failedInterfaceTasks.Count -eq 0)
    {
        Write-Warning "Did not find InterfaceTask in 'Error' state in action XML."
        return
    }
    Write-Host "Failed Interface(s):" -ForegroundColor Yellow
    $failedInterfaceTasks | Select RolePath, InterfaceType | Format-Table
    if ($PSCmdlet.ShouldProcess($ActionPlanInstanceID))
    {
        $failedRemoteActions = $progressXml.SelectNodes("//*[RemoteConfig and @Status='Error']")
        Write-Verbose "Marking failed interface Tasks as Skipped." -Verbose
        $failedInterfaceTasks | foreach { $_.Status = 'Skipped' }
        # Delete relevant remote Action plan instance because ECE service will use remote XML.
        foreach ($remoteAction in $failedRemoteActions)
        {
            $remoteNode = $remoteAction.RemoteNodeName
            $remoteActionId = $remoteAction.RemoteTaskId
            $eceAgentClient = Create-ECEAgentClient -NodeName $remoteNode
            if ($eceAgentClient.GetActionPlanInstance($remoteActionId).GetAwaiter().GetResult())
            {
                Write-Verbose "Deleting associated failed remote action plan instance $remoteActionId from $remoteNode." -Verbose
                $deleteActionPlanInstanceDescription = New-Object -TypeName 'Microsoft.AzureStack.Solution.Deploy.EnterpriseCloudEngine.Controllers.Models.DeleteActionPlanInstanceDescription'
                $deleteActionPlanInstanceDescription.ActionPlanInstanceID = $remoteActionId
                $eceAgentClient.DeleteActionPlanInstance($deleteActionPlanInstanceDescription).Wait()
            }
        }
        # Save to file and invoke new action plan
  	 if(!(Test-Path -Path "C:\Temp" -PathType Container)){
            $null = New-Item -Path "C:\Temp" -ItemType Directory -Force
        } 

        $tempFile = Join-Path "C:\Temp" ([IO.Path]::GetRandomFileName())
        Write-Verbose "Saving modified XML to temp file $tempFile." -Verbose
        $progressXml.Save($tempFile)
        Invoke-ActionPlanInstanceWithNewXml -ActionPlanPath $tempFile -ReferenceActionPlanInstanceID $ActionPlanInstanceID | Out-Null
    }
}
```

**4.) Run below PowerShell commands in the same host as Step 3 to skip failed Step and resumes add node.**
```
#Update failed ScaleOutOperation action plan’s ActionPlanInstanceID to variable $instanceid
$instanceId = "<ScaleOutOperation action plan’s instanceid>"
Skip-FailedStepsInActionPlan -ActionPlanInstanceID $instanceId
```
This will print out the failed tasks and then prompt for confirmation. Please check that the tasks called out are all "SetTrustedHostsOnNewNode", and then confirm. The Add node should be resumed with failed steps skipped.

**5.) Track Add node status using new Action plan ID printed from step 4.**

