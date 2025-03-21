# Symptoms
Solution Update (PNU) fails at step 'InstallRemoteSupportArcExtension' with error:
```Powershell
Type 'InstallRemoteSupportArcExtension' of Role 'ObservabilityConfig' raised an exception: H1750207052254 Extension installation found failed. AzureEdgeEdgeRemoteSupport ProvisioningState: Failed Publisher: Microsoft.AzureStack.Observability at , : line 64 at CloudEngine.Actions.PowerShellHost.WaitAndReceiveJob(Job job, CancellationToken token, UInt32 timeoutSeconds, Stopwatch watch) in C:\__w\1\s\src\EceEngine\ece\CloudEngine\Actions\Source\PowerShellHost.cs:line 231 at CloudEngine.Actions.PowerShellHost.Invoke(InterfaceParameters parameters, CancellationToken token, UInt32 timeoutSeconds, ThrottlingDescription throttlingDesc) in C:\__w\1\s\src\EceEngine\ece\CloudEngine\Actions\Source\PowerShellHost.cs:line 156 at CloudEngine.Actions.InterfaceTask.Invoke(Configuration roleConfiguration, String startStep, String endStep, String[] skip, Nullable`1 retries, Nullable`1 interfaceTimeout, CancellationToken token, Dictionary`2 runtimeParameter, Boolean runInProcess) in C:\__w\1\s\src\EceEngine\ece\CloudEngine\Actions\Source\InterfaceTask.cs:line 236
```

# Mitigation Details

Since the InstallRemoteSupportArcExtension step is not necessary anymore, we've removed it in builds 2405.3 and 2408 onwards. For any builds below this, if update fails due to this issue we can uninstall the extension and wait for extension to be automatically reinstalled (as a mandatory extension), then resume update. The steps are below:

1/ Uninstall the Remote Support extension from all nodes through Azure Portal. If the uninstallation gets stuck in portal then we'll need to manually uninstall through Powershell. The steps are below:
*	Restart the node (This will kill any open handles to the extension folder which can block deletion)
*	Run ```logman stop remoteSupportLogmanTraces```
*	Check the extension folder C:\Packages\Plugins\Microsoft.AzureStack.Observability.EdgeRemoteSupport\<version>\scripts if it still exists
		If it does, cd to that folder and run ./Disable-Extension.ps1
		Then run ./Uninstall-Extension.ps1
*	Once the scripts are completed. Check back in portal to make sure extension has been uninstalled

2/ Wait a few minutes and check portal to see if extension is automatically reinstalled. If it doesn't show up, extension can be manually installed by:
* Run Connect-AzAccount (log in with registration account)
* Run New-AzConnectedMachineExtension -Name AzureEdgeRemoteSupport -ResourceGroupName $ResourceGroupName `
                                        -MachineName $(hostname)`
                                        -Location $Region `
                                        -Publisher Microsoft.AzureStack.Observability `
                                        -ExtensionType EdgeRemoteSupport `
                                        -EnableAutomaticUpgrade


3/Resume update