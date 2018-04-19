Param
(
    [System.IO.DirectoryInfo]$Path=("$($env:systemdrive)\SCOM2016Reqs")
)
function Get-MSIFileInfo
{
    Param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$Path,
     
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ProductCode', 'ProductVersion', 'ProductName', 'Manufacturer', 'ProductLanguage', 'FullVersion')]
        [string]$Property
    )
    Begin
    {
        $Value = '';
        $WindowsInstaller = New-Object -ComObject WindowsInstaller.Installer;
    }
    Process
    {
        $MSIDatabase = $WindowsInstaller.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $WindowsInstaller, @($Path.FullName, 0));
        if($MSIDatabase)
        {
            $Query = "SELECT Value FROM Property WHERE Property = '$($Property)'";
            $View = $MSIDatabase.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $MSIDatabase, ($Query));
            if($View)
            {
                # Read property from MSI database
                $null = $View.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $View, $null);
                $Record = $View.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $View, $null);
                if($Record)
                {
                    $Value = $Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, 1);
                };
                # Commit database and close view
                $MSIDatabase.GetType().InvokeMember('Commit', 'InvokeMethod', $null, $MSIDatabase, $null);
                $View.GetType().InvokeMember('Close', 'InvokeMethod', $null, $View, $null);
                $MSIDatabase = $null;
                $View = $null;
            };
        };
        # Return the value
        return $Value;
    }
    End
    {
        # Run garbage collection and release ComObject
        $null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WindowsInstaller);
        [System.GC]::Collect();
    };
};
function Get-UninstallRegKey
{
    Param
    (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName
    )
    # paths: x86 and x64 registry keys are different
    [string[]]$path = if([IntPtr]::Size -eq 4)
    {
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*';
    } else {
        @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        );
    };
    # get all data
    Get-ItemProperty $path | Where-Object {$_.DisplayName -match $DisplayName}
};

if(-not(Test-Path -Path $($Path.FullName) -PathType Container)){$null=$Path.Create();};
if(Test-Path -Path $($Path.FullName) -PathType Container)
{
    # Report Viewer has a dependency on Microsoft System CLR Types for SQL Server
    $sqlSysClrTypesFile = $($($Path.FullName)+'\SQLSysClrTypes.msi');
    $sqlSysClrTypesUri = 'http://download.microsoft.com/download/F/E/E/FEE62C90-E5A9-4746-8478-11980609E5C2/ENU/x64/SQLSysClrTypes.msi';
    $sqlSysClrTypesInstalled = $null;
    # Get Product Version of previously downloaded Microsoft System CLR Types for SQL Server
    $sqlSysClrTypesVersion = if(Test-Path -Path $sqlSysClrTypesFile -PathType Leaf){Get-MSIFileInfo -Path $sqlSysClrTypesFile -Property ProductVersion;} else {'0.0.0.0'};
    $sqlSysClrTypesVersion = if($sqlSysClrTypesVersion -and [string]$sqlSysClrTypesVersion -match '\.'){([string]$sqlSysClrTypesVersion).Trim()} else {'0.0.0.0'};
    $sqlSysClrTypesVersion = $sqlSysClrTypesVersion.Split('.');
    # If Microsoft System CLR Types for SQL Server has not been downloaded or older version exist
    if(-not(Test-Path -Path $sqlSysClrTypesFile -PathType Leaf) -or $sqlSysClrTypesVersion[0] -lt 12 -or ($sqlSysClrTypesVersion[0] -eq 12 -and $sqlSysClrTypesVersion[1] -lt 1) -or ($sqlSysClrTypesVersion[0] -eq 12 -and $sqlSysClrTypesVersion[1] -eq 1 -and $sqlSysClrTypesVersion[2] -lt 4100))
    {
        # DownloadMicrosoft System CLR Types for SQL Server
        $null = Invoke-WebRequest -Uri $sqlSysClrTypesUri -OutFile $sqlSysClrTypesFile -UseBasicParsing;
    };
    # If Microsoft System CLR Types for SQL Server exist (has been downloaded)
    if(Test-Path -Path $sqlSysClrTypesFile -PathType Leaf)
    {
        # Get Product Name of downloaded Microsoft System CLR Types for SQL Server
        $sqlSysClrTypesProductName = Get-MSIFileInfo -Path $sqlSysClrTypesFile -Property ProductName;
        $sqlSysClrTypesProductName = if($sqlSysClrTypesProductName){([string]$sqlSysClrTypesProductName).Trim()} else {''};
        # Get Product Year of downloaded Microsoft System CLR Types for SQL Server
        $sqlSysClrTypesProductYear = if($sqlSysClrTypesProductName){$sqlSysClrTypesProductName.Substring($sqlSysClrTypesProductName.Length-4);} else {'2012'};
        # Remove Year from Product Name of downloaded Microsoft System CLR Types for SQL Server
        $sqlSysClrTypesProductName = if($sqlSysClrTypesProductName){$sqlSysClrTypesProductName.Substring(0,$sqlSysClrTypesProductName.Length-5)} else {''};
        if(-not($sqlSysClrTypesProductName)){$sqlSysClrTypesProductName = 'Microsoft System CLR Types for SQL Server'};
        # Check registry for newest installed version of Microsoft System CLR Types for SQL Server
        $sqlSysClrTypesInstalled = Get-UninstallRegKey -DisplayName $sqlSysClrTypesProductName;
        $sqlSysClrTypesInstalled = $sqlSysClrTypesInstalled | Sort-Object DisplayVersion -Descending | Select-Object -First 1;
        # Get Product Name of installed Microsoft System CLR Types for SQL Server
        $sqlSysClrTypesInstalledProductName = if($sqlSysClrTypesInstalled){$sqlSysClrTypesInstalled.DisplayName} else {''};
        # Get Product Year of installed Microsoft System CLR Types for SQL Server
        $sqlSysClrTypesInstalledProductYear = if($sqlSysClrTypesInstalledProductName){$sqlSysClrTypesInstalledProductName.Substring($sqlSysClrTypesInstalledProductName.Length-4);} else {0};
        # If installed version is older than downloaded or CRL Types is not installed
        if($sqlSysClrTypesProductYear -gt $sqlSysClrTypesInstalledProductYear)
        {
            # Install Microsoft System CLR Types for SQL Server
            Start-Process -FilePath $sqlSysClrTypesFile -ArgumentList '/qn' -Wait;
            # Check registry for newest installed version of Microsoft System CLR Types for SQL Server
            $sqlSysClrTypesInstalled = Get-UninstallRegKey -DisplayName $sqlSysClrTypesProductName;
            $sqlSysClrTypesInstalled = $sqlSysClrTypesInstalled | Sort-Object DisplayVersion -Descending | Select-Object -First 1;
        };
    };
    if(-not($sqlSysClrTypesInstalled)){throw 'Unable to install Microsoft System CLR Types for SQL Server'};
    # Microsoft Report Viewer 2015 Runtime required for Operations Manager console
    $reportviewerFile = $($($Path.FullName)+'\ReportViewer.msi');
    $reportviewerUri = 'http://download.microsoft.com/download/A/1/2/A129F694-233C-4C7C-860F-F73139CF2E01/ENU/x86/ReportViewer.msi';
    $reportviewerInstalled = $null;
    $status = 'was not installed';
    # Get Product Version of previously downloaded Microsoft Report Viewer 2015 Runtime
    $reportviewerVersion = if(Test-Path -Path $reportviewerFile -PathType Leaf){Get-MSIFileInfo -Path $reportviewerFile -Property ProductVersion;} else {'0.0.0.0'};
    $reportviewerVersion = if($reportviewerVersion -and [string]$reportviewerVersion -match '\.'){([string]$reportviewerVersion).Trim()} else {'0.0.0.0'};
    $reportviewerVersion = $reportviewerVersion.Split('.');
    # If Microsoft Report Viewer 2015 Runtime has not been downloaded or older version exist
    if(-not(Test-Path -Path $reportviewerFile -PathType Leaf) -or $reportviewerVersion[0] -lt 12 -or ($reportviewerVersion[0] -eq 12 -and $reportviewerVersion[1] -eq 0 -and $reportviewerVersion[2] -lt 2402))
    {
        $null = Invoke-WebRequest -Uri $reportviewerUri -OutFile $reportviewerfile -UseBasicParsing;
    };
    # If Microsoft Report Viewer 2015 Runtime exist (has been downloaded)
    if(Test-Path -Path $reportviewerFile -PathType Leaf)
    {
        # Get Product Name of downloaded Microsoft Report Viewer 2015 Runtime
        $reportviewerProductName = Get-MSIFileInfo -Path $reportviewerFile -Property ProductName;
        $reportviewerProductName = if($reportviewerProductName){([string]$reportviewerProductName).Replace('Runtime','').Trim()} else {''};
        # Get Product Year of downloaded Microsoft Report Viewer 2015 Runtime
        $reportviewerProductYear = if($reportviewerProductName){$reportviewerProductName.Substring($reportviewerProductName.Length-4);} else {'2015'};
        # Remove Year from Product Name of downloaded Microsoft Report Viewer 2015 Runtime
        $reportviewerProductName = if($reportviewerProductName){$reportviewerProductName.Substring(0,$reportviewerProductName.Length-5)} else {''};
        if(-not($reportviewerProductName)){$reportviewerProductName = 'Microsoft Report Viewer'};
        # Check registry for newest installed version of Microsoft Report Viewer 2015 Runtime
        $reportviewerInstalled = Get-UninstallRegKey -DisplayName $reportviewerProductName;
        if($reportviewerInstalled)
        {
            $reportviewerInstalled = $reportviewerInstalled | Sort-Object DisplayVersion -Descending | Select-Object -First 1;
            $status = 'version ' + $reportviewerInstalled.DisplayVersion + ' has already been installed';
        };
        # Get Product Name of installed Microsoft Report Viewer 2015 Runtime
        $reportviewerInstalledProductName = if($reportviewerInstalled){$reportviewerInstalled.DisplayName} else {''};
        # Get Product Year of installed Microsoft Report Viewer 2015 Runtime
        $reportviewerInstalledProductYear = if($reportviewerInstalledProductName){$reportviewerInstalledProductName.Substring($reportviewerInstalledProductName.Length-4);} else {0};
        # If installed version is older than downloaded or CRL Types is not installed
        if($reportviewerProductYear -gt $reportviewerInstalledProductYear)
        {
            # Install Microsoft Report Viewer 2015 Runtime
            Start-Process -FilePath $reportviewerFile -ArgumentList '/qn' -Wait;
            # Check registry for newest installed version of Microsoft Report Viewer 2015 Runtime
            $reportviewerInstalled = Get-UninstallRegKey -DisplayName $reportviewerProductName;
            if($reportviewerInstalled)
            {
                $reportviewerInstalled = $reportviewerInstalled | Sort-Object DisplayVersion -Descending | Select-Object -First 1;
                $status = 'version ' + $reportviewerInstalled.DisplayVersion + ' has been installed';
            };
        };
    };
    if(-not($reportviewerInstalled)){throw 'Unable to install Microsoft Report Viewer 2015 Runtime'};
    Write-Host "Microsoft Report Viewer $status" -ForegroundColor DarkCyan
};
