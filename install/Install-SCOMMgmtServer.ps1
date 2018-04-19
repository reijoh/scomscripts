param
(
    [bool]$FirstManagementServer = $true,

    [string]$Components = 'OMServer', # 'OMServer,OMConsole,OMWebConsole,OMReporting'

    [string]$ManagementGroupName,

    [string]$SqlServerInstance, # e.g. Server\Instancename or just Server or Always On availability group listener

    [int]$SqlInstancePort = 1433,

    [string]$DWSqlServerInstance,

    [int]$DWSqlInstancePort = 1433,

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $ActionAccountUser = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $DASAccountUser = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $DataReaderUser = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $DataWriterUser = [System.Management.Automation.PSCredential]::Empty,

    [string]$InstallPath = 'D:\Program Files\Microsoft System Center 2016\Operations Manager',

    [Parameter(Mandatory=$false)]
    [ValidateSet('Never','Queued','Always')]
    [string]$EnableErrorReporting = 'Never',

    [int]$SendCEIPReports = 0,

    [int]$UseMicrosoftUpdate = 0,

    [string]$WebSiteName = 'Default Web Site',

    [bool]$WebConsoleUseSSL = $false,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Mixed','Network')]
    $WebConsoleAuthorizationMode = 'Mixed',

    [string]$ManagementServer = '',

    [string]$SRSInstance,

    [int]$SendODRReports = 0
)
function Get-SecureStringPlainText
{
  [CmdletBinding()]
  [OutputType([string])]
  param
  (
    [parameter(Mandatory=$true)]
    [System.Security.SecureString]$SecureString
  )
  begin
  {
    Set-StrictMode -Version Latest;
  }
  process
  {
    # Allocate an unmanaged binary string (BSTR) and copy the contents of managed SecureString object into it
    $bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString);
    try
    {
      # Allocate a managed String and copy a binary string (BSTR) stored in unmanaged memory into it
      [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr);
    }
    finally
    {
      # Free BSTR using the COM SysFreeString function
      [Runtime.InteropServices.Marshal]::FreeBSTR($bstr);
    };
  };
};
$actionAccountPassword = Get-SecureStringPlainText -SecureString $ActionAccountUser.Password;
$dasAccountPassword = Get-SecureStringPlainText -SecureString $DASAccountUser.Password;
$dataReaderPassword = Get-SecureStringPlainText -SecureString $DataReaderUser.Password;
$dataWriterPassword = Get-SecureStringPlainText -SecureString $DataWriterUser.Password;
$arglist = @(
    "/install /components:$Components";
);
if($Components -match 'OMServer')
{
    if($FirstManagementServer)
    {
        $arglist += @(
            "/ManagementGroupName:$ManagementGroupName",
            "/DWSqlServerInstance:$DWSqlServerInstance /DWSqlInstancePort:$DWSqlInstancePort /DWDatabaseName:OperationsManagerDW"
        );
    };
    $arglist += @(
        "/SqlServerInstance:$SqlServerInstance /SqlInstancePort:$SqlInstancePort /DatabaseName:OperationsManager",
        "/ActionAccountUser:$($ActionAccountUser.UserName) /ActionAccountPassword:$actionAccountPassword",
        "/DASAccountUser:$($DASAccountUser.UserName) /DASAccountPassword:$dasAccountPassword",
        "/DataWriterUser:$($DataWriterUser.UserName) /DataWriterPassword:$dataWriterPassword"
    );
};

if($Components -match 'OMServer' -or $Components -match 'OMReporting')
{
    $arglist += @(
        "/DataReaderUser:$($DataReaderUser.UserName) /DataReaderPassword:$dataReaderPassword"
    );
};

if($Components -match 'OMWebConsole')
{
    if(-not($WebSiteName)){$WebSiteName = 'Default Web Site'};
    $arglist += @(
        "/WebSiteName:""$WebSiteName"" /WebConsoleAuthorizationMode:$WebConsoleAuthorizationMode"
    );
    if($WebConsoleUseSSL)
    {
        $arglist += @(
            "/WebConsoleUseSSL"
        );
    };
};
if($Components -match 'OMReporting' -and $SRSInstance)
{
    $arglist += @(
        "/SRSInstance:$SRSInstance /SendODRReports:$SendODRReports"
    );
};
if(-not($Components -match 'OMServer') -and $ManagementServer -and ($Components -match 'OMWebConsole' -or $Components -match 'OMReporting'))
{
    $arglist += @(
        "/ManagementServer:$ManagementServer"
    );
};

$arglist += @(
    "/InstallPath:""$InstallPath"" /EnableErrorReporting:$EnableErrorReporting",
    "/SendCEIPReports:$SendCEIPReports /UseMicrosoftUpdate:$UseMicrosoftUpdate",
    "/AcceptEndUserLicenseAgreement:1 /silent"
);

Start-Process -FilePath $env:systemdrive\SCOM2016\setup.exe -ArgumentList $arglist -Wait;
Write-Host "Verify installation log $($env:LOCALAPPDATA)\SCOM\LOGS\OpsMgrSetupWizard.txt"
Write-Host "Don't forget to set a valid product key by using the Set-SCOMLicense –ProductId <key>";
