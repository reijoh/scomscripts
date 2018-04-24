# TODO: Ensure local Administrators group membership
param
(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
    [string]$SetupPath,

    [switch]$FirstManagementServer,

    [switch]$NoInstallation,

    [string]$Components = 'OMServer', # 'OMServer,OMConsole,OMWebConsole,OMReporting'

    [string]$ManagementGroupName,

    [string]$SqlServerInstance, # e.g. Server\Instancename or just Server or Always On availability group listener

    [int]$SqlInstancePort = 1433,

    [string]$DWSqlServerInstance,

    [int]$DWSqlInstancePort = 1433,

    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $ActionAccountUser = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $DASAccountUser = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $DataReaderUser = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $DataWriterUser = [System.Management.Automation.PSCredential]::Empty,

    [ValidateNotNullOrEmpty()]
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

    [int]$SendODRReports = 0,

    [ValidateNotNullOrEmpty()]
    [System.IO.DirectoryInfo]$DownloadPath = ("$($env:systemdrive)\SCOM2016Reqs")
)
function Get-SecureStringPlainText
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
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
function Get-ErrorMessageString
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $e
    )
    $errtype='';
    $msg=if([bool]($e|Get-Member -Name Exception) -and [bool]($e.Exception|Get-Member -Name InnerException) -and $e.Exception.InnerException)
    {
        $errtype=$e.Exception.InnerException.GetType().FullName;
        $e.Exception.InnerException.Message;
    } elseif([bool]($e|Get-Member -Name Exception) -and $e.Exception) {
        $errtype=$e.Exception.GetType().FullName;
        $e.Exception.Message;
    } elseif([bool]($e|Get-Member -Name ErrorRecord) -and [bool]($e.ErrorRecord|Get-Member -Name Exception) -and [bool]($e.ErrorRecord.Exception|Get-Member -Name InnerException) -and $e.ErrorRecord.Exception.InnerException) {
        $errtype=$e.ErrorRecord.Exception.InnerException.GetType().FullName;
        $e.ErrorRecord.Exception.InnerException.Message;
    } elseif([bool]($e|Get-Member -Name ErrorRecord) -and [bool]($e.ErrorRecord|Get-Member -Name Exception) -and $e.ErrorRecord.Exception) {
        $errtype=$e.ErrorRecord.Exception.GetType().FullName;
        $e.ErrorRecord.Exception.Message;
    } elseif([bool]($e|Get-Member -Name Message)) {
        $errtype=$e.GetType().FullName;
        $e.Message;
    } else {'';};
    if($msg -match '\n')
    {
        $a=@($msg -split '\r\n' -split '\n');
        $b=$a -notmatch '^\+' -notmatch '^$';
        $msg=$b -join ' : ';
    };
    if($msg -match ('^Exception calling '+[char]34+'.+'+[char]34+' with '+[char]34+'\d+'+[char]34+' argument\(s\): '+[char]34)){$msg=$msg -replace ('^Exception calling '+[char]34+'.+'+[char]34+' with '+[char]34+'\d+'+[char]34+' argument\(s\): '+[char]34) -replace ([char]34+'$'),'';};
    if($msg -eq ''){($errtype+' has occured without any error message.').Trim();}else{$msg+'.' -replace '\t|\r\n|\n|\r|\s+',' ' -replace '\.+','.';};
};
function Get-ErrorCodeNumber
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $e
    )
    if([bool]($e|Get-Member -Name Exception) -and [bool]($e.Exception|Get-Member -Name InnerException) -and $e.Exception.InnerException -and [bool]($e.Exception.InnerException|Get-Member -Name Number))
    {
        $e.Exception.InnerException.Number;
    } elseif([bool]($e|Get-Member -Name Exception) -and [bool]($e.Exception|Get-Member -Name InnerException) -and $e.Exception.InnerException -and [bool]($e.Exception.InnerException|Get-Member -Name ErrorCode)) {
        $e.Exception.InnerException.ErrorCode;
    } elseif([bool]($e|Get-Member -Name Exception) -and [bool]($e.Exception|Get-Member -Name InnerException) -and $e.Exception.InnerException -and [bool]($e.Exception.InnerException|Get-Member -Name HResult)) {
        $e.Exception.InnerException.HResult;
    } elseif([bool]($e|Get-Member -Name Exception) -and $e.Exception -and [bool]($e.Exception|Get-Member -Name Number)) {
        $e.Exception.Number;
    } elseif([bool]($e|Get-Member -Name Exception) -and $e.Exception -and [bool]($e.Exception|Get-Member -Name ErrorCode)) {
        $e.Exception.ErrorCode;
    } elseif([bool]($e|Get-Member -Name Exception) -and $e.Exception -and [bool]($e.Exception|Get-Member -Name HResult)) {
        $e.Exception.HResult;
    } elseif([bool]($e|Get-Member -Name ErrorRecord) -and [bool]($e.ErrorRecord|Get-Member -Name Exception) -and [bool]($e.ErrorRecord.Exception|Get-Member -Name InnerException) -and $e.ErrorRecord.Exception.InnerException -and [bool]($e.ErrorRecord.Exception.InnerException|Get-Member -Name Number)) {
        $e.ErrorRecord.Exception.InnerException.Number;
    } elseif([bool]($e|Get-Member -Name ErrorRecord) -and [bool]($e.ErrorRecord|Get-Member -Name Exception) -and [bool]($e.ErrorRecord.Exception|Get-Member -Name InnerException) -and $e.ErrorRecord.Exception.InnerException -and [bool]($e.ErrorRecord.Exception.InnerException|Get-Member -Name ErrorCode)) {
        $e.ErrorRecord.Exception.InnerException.ErrorCode;
    } elseif([bool]($e|Get-Member -Name ErrorRecord) -and [bool]($e.ErrorRecord|Get-Member -Name Exception) -and [bool]($e.ErrorRecord.Exception|Get-Member -Name InnerException) -and $e.ErrorRecord.Exception.InnerException -and [bool]($e.ErrorRecord.Exception.InnerException|Get-Member -Name HResult)) {
        $e.ErrorRecord.Exception.InnerException.HResult;
    } elseif([bool]($e|Get-Member -Name ErrorRecord) -and [bool]($e.ErrorRecord|Get-Member -Name Exception) -and $e.ErrorRecord.Exception -and [bool]($e.ErrorRecord.Exception|Get-Member -Name Number)) {
        $e.ErrorRecord.Exception.Number;
    } elseif([bool]($e|Get-Member -Name ErrorRecord) -and [bool]($e.ErrorRecord|Get-Member -Name Exception) -and $e.ErrorRecord.Exception -and [bool]($e.ErrorRecord.Exception|Get-Member -Name ErrorCode)) {
        $e.ErrorRecord.Exception.ErrorCode;
    } elseif([bool]($e|Get-Member -Name ErrorRecord) -and [bool]($e.ErrorRecord|Get-Member -Name Exception) -and $e.ErrorRecord.Exception -and [bool]($e.ErrorRecord.Exception|Get-Member -Name HResult)) {
        $e.ErrorRecord.Exception.HResult;
    } else {-1;};
};
function Test-NetPort
{
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Server,
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,Position=1)]
        [ValidateNotNullOrEmpty()]
        [int[]]$Port,
        [string]$PortType='TCP',
        [int]$Timeout=500
    )
    begin
    {
        Set-StrictMode -Version Latest;
        $outmsg=@();
    }
    process
    {
        foreach($srv in $Server)
        {
            foreach($prt in $Port)
            {
                $testok=$true;
                $msg='';
                $code=0;
                try
                {
                    if($PortType -eq 'UDP')
                    {
                        $client=New-Object System.Net.Sockets.UdpClient;
                        $null=$client.Connect($srv,$prt);
                        $textASCII=New-Object System.Text.ASCIIEncoding;
                        $byte=$textASCII.GetBytes([string]$(Get-Date));
                        $null=$client.Send($byte,$byte.Length);
                        $ipEndPoint=New-Object System.Net.IPEndPoint([system.net.ipaddress]::Any,0);
                        $client.Client.ReceiveTimeout=$Timeout;
                        $null=$client.Receive([ref]$ipEndPoint);
                    }
                    else
                    {
                        $client=New-Object System.Net.Sockets.TcpClient;
                        $bc=$client.BeginConnect($srv,$prt,$null,$null);
                        $null=$bc.AsyncWaitHandle.WaitOne($Timeout,$false);
                        $testok=$client.Connected;
                        if($testok){$null=$client.EndConnect($bc);}else{$msg='Timeout';$code=1;};
                    };
                }
                catch
                {
                    $testok=$false;
                    $msg=Get-ErrorMessageString $_;
                    $code=Get-ErrorCodeNumber $_;
                    $Error.Remove($Error[0]);
                }
                finally
                {
                    $null=$client.Close();
                    if(-not($testok) -and $code -eq 0){$code=1;};
                    if(-not($testok) -and -not($msg)){$msg='Unable to connect to '+$PortType+' port';};
                    $outmsg+=New-Object PSObject -Property @{ServerName=$srv;Port=$prt;Connected=$testok;Message=$msg;ErrorCode=$code};
                };
            };
        };
    }
    end
    {
        $outmsg|Select-Object ServerName,Port,Connected,Message,ErrorCode|Sort-Object ServerName,Port,Connected;
    };
};
function Test-WebSite
{
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$URL,
        [string]$Proxy,
        [string]$Method='Get',
        [string]$UserAgent='Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; nb-NO)',
        [string]$ContentType='text/xml;charset=utf-8',
        [string]$Headers='Accept-Language=en-US,en;q=0.8|Accept-Charset=utf-8|Accept-Encoding=gzip,deflate,sdch',
        [string]$Body='',
        [string]$Authentication='Negotiate',
        [string]$Username,
        [string]$Password,
        [string]$ContentMatch='',
        [bool]$ShowContent=$false,
        [int]$StatusCodeLessOrEqual=401,
        [int]$TimeoutSec=10
    )
    begin
    {
        Set-StrictMode -Version Latest;
        $outmsg=@();
    }
    process
    {
        foreach($uri in $URL)
        {
            $testok=$connected=$scError=$cmError=$false;
            $msg=$webContent='';
            $code=0;
            [int]$webStatusCode=-1;
            try
            {
                $headerhash=@{};
                $desc='';
                if((Get-Command -Verb Invoke -Module Microsoft.PowerShell.Utility)|Where-Object{$_.Name -eq 'Invoke-WebRequest'})
                {
                    $p=@{Uri=$uri;TimeoutSec=$TimeoutSec;DisableKeepAlive=$true;UseBasicParsing=$true;UseDefaultCredentials=[bool]($Authentication -eq 'Negotiate');ErrorAction='Stop'};
                    if($Proxy){$p.Add('Proxy',$Proxy);$p.Add('ProxyUseDefaultCredentials',$true);};
                    if($Authentication -match '^(Basic|NTLM|Digest)$' -and $Username -and $Password)
                    {
                        $pwd=ConvertTo-SecureString -String $Password -AsPlainText -Force;
                        $cred=New-Object System.Management.Automation.PSCredential($Username,$pwd);
                        $p.Add('Credential',$cred);
                    };
                    if($ContentType){$p.Add('ContentType',$ContentType);};
                    if($Method){$p.Add('Method',$Method);};
                    if($UserAgent){$p.Add('UserAgent',$UserAgent)};
                    if($Headers)
                    {
                        $headerlines=$Headers.Replace('|',[char]10);
                        $headerhash=ConvertFrom-StringData -StringData $headerlines;
                        $p.Add('Headers',$headerhash);
                    };
                    if($Body -and $Method -eq 'POST'){$p.Add('Body',$Body);};
                    $webResponse=Invoke-WebRequest @p;
                    if($webResponse)
                    {
                        $connected=$true;
                        $webStatusCode=$webResponse.StatusCode;
                        $desc=$webResponse.StatusDescription;
                        $webContent=$webResponse.Content;
                    };
                } else {
                    [System.Net.HttpWebRequest]$webreq=[System.Net.WebRequest]::Create($uri);
                    $webreq.Method=$Method;
                    $webreq.Timeout=($TimeoutSec*1000);
                    $webreq.KeepAlive=$false;
                    if($Proxy)
                    {
                        $proxyUri=New-Object System.Uri($Proxy) -ErrorAction SilentlyContinue;
                        if($proxyUri)
                        {
                            $wp=New-Object System.Net.WebProxy;
                            $wp.UseDefaultCredentials=$true;
                            $wp.Credentials=[System.Net.CredentialCache]::DefaultCredentials;
                            $wp.Address=$proxyUri;
                            $webreq.Proxy=$wp;
                        };
                    };
                    if($ContentType){$webreq.ContentType=$ContentType;};
                    if($UserAgent){$webreq.UserAgent=$UserAgent;};
                    if($Body -and $Method -eq 'POST')
                    {
                        $Body=[byte[]][char[]]$Body;
                        $reqstream=$webreq.GetRequestStream();
                        $reqstream.Write($Body,0,$Body.Length);
                    };
                    $webreq.UseDefaultCredentials=[bool]($Authentication -eq 'Negotiate');
                    if($Authentication -eq 'NTLM' -and $Username -and $Password)
                    {
                        $credential=New-Object -TypeName System.Net.NetworkCredential($Username,$Password);
                        $credc=New-Object -TypeName System.Net.CredentialCache;
                        $credc.Add($uri,$Authentication,$credential);
                        $webreq.PreAuthenticate=$true;
                        $webreq.Credentials=$credc;
                    } elseif($Authentication -eq 'Basic' -and $Username -and $Password) {
                        $pair=($Username+':'+$Password);
                        $encodedCreds=[System.Convert]::ToBase64String([System.Text.Encoding]::Default.GetBytes($pair));
                        $basicAuthValue='Basic '+$encodedCreds;
                        if($Headers){$Headers+='|';};
                        $Headers+='Authorization='+$basicAuthValue;
                        $webreq.PreAuthenticate=$true;
                        $webreq.AuthenticationLevel=[System.Net.Security.AuthenticationLevel]::MutualAuthRequested;
                    };
                    if($Headers)
                    {
                        $headerlines=$Headers.Replace('|',[char]10);
                        $headerhash=ConvertFrom-StringData -StringData $headerlines;
                        $headercol=New-Object -TypeName System.Net.WebHeaderCollection;
                        foreach($key in $headerhash.Keys){$headercol.Add($key,$headerhash.Item($key));};
                        $webreq.Headers=$headercol;
                    };
                    [System.Net.HttpWebResponse]$webResponse=$webreq.GetResponse();
                    if($webResponse)
                    {
                        $connected=$true;
                        $webStatusCode=[int]$webResponse.StatusCode;
                        $desc=$webResponse.StatusDescription;
                        if($webResponse.ContentLength -gt 0)
                        {
                            [System.IO.Stream]$rs=$webResponse.GetResponseStream();
                            if($webResponse.ContentEncoding.ToLower().Contains('gzip'))
                            {
                                [System.IO.Compression.GzipStream]$rs=New-Object System.IO.Compression.GzipStream($rs,[System.IO.Compression.CompressionMode]::Decompress);
                            } elseif($webResponse.ContentEncoding.ToLower().Contains('deflate')) {
                                [System.IO.Compression.DeflateStream]$rs=New-Object System.IO.Compression.DeflateStream($rs,[System.IO.Compression.CompressionMode]::Decompress);
                            };
                            [System.IO.StreamReader]$reader=New-Object System.IO.StreamReader($rs);
                            [string]$webContent=$reader.ReadToEnd();
                            $reader.Close();
                            $rs.Close();
                        };
                        $webResponse.Close();
                    };
                };
                if($connected)
                {
                    $msg=$desc;
                    # If statuscode is below threshold
                    if($webStatusCode -le $StatusCodeLessOrEqual)
                    {
                        $cmError=[bool](-not(($ContentMatch -and $webContent -and $webContent -match $ContentMatch) -or -not($ContentMatch)));
                        if(-not($cmError)){$testok=$true;};
                    } else {$scError=$true;};
                };
            }
            catch
            {
                $msg=Get-ErrorMessageString $_;
                $code=Get-ErrorCodeNumber $_;
                $Error.Remove($Error[0]);
            }
            finally
            {
                if(-not($ShowContent)){$webContent='';};
                $status=if($testok){'Success';}else{'Failure';};
                if(-not($testok) -and $code -eq 0){$code=1;};
                $outmsg+=New-Object PSObject -Property @{Status=$status;Url=$uri;Connected=$connected;StatusCode=$webStatusCode;StatusCodeError=$scError;ContentMatchError=$cmError;Content=$webContent;Message=$msg;ErrorCode=$code};
            };
        };
    }
    end
    {
        $outmsg|Select-Object Status,Url,Connected,StatusCode,StatusCodeError,ContentMatchError,Content,Message,ErrorCode|Sort-Object -Property @{Expression='Status';Descending=$true},@{Expression='Url';Descending=$false};
    };
};
function Get-DataSourceStatus
{
<#
.SYNOPSIS
Connect to a data source, run a query if specified, and return the result
#>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$ConnectionString,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string]$Query,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string]$QueryInsert,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential=[System.Management.Automation.PSCredential]::Empty
    )
    # Create a DataSet object
    [System.Data.DataSet]$ds=New-Object System.Data.DataSet;
    [string]$connectionState='';
    [int]$rowcount=-1;
    [int]$rowcountinsert=-1;
    [long]$millisecConnect=-1;
    [long]$millisecInsert=-1;
    [long]$millisecSelect=-1;
    $returnValue='';
    if($ConnectionString -match '^Provider=SQL' -or $ConnectionString -match '^Driver={SQL')
    {
        [System.Data.SqlClient.SqlConnection]$dc=$null;
        # Strip provider away because we use SqlClient so provider is not supported/used
        $ConnectionString=$ConnectionString.Substring($ConnectionString.IndexOf(';')+1);
        $dcType='SqlClient';
    } elseif($ConnectionString -match '^Provider=') {
        [System.Data.OleDb.OleDbConnection]$dc=$null;
        $dcType='OleDb';
    } elseif($ConnectionString -match '^Driver=') {
        [System.Data.Odbc.OdbcConnection]$dc=$null;
        $dcType='ODBC';
    } else {
        [System.Data.SqlClient.SqlConnection]$dc=$null;
        $dcType='SqlClient';
    };
    try
    {
        # If the ConnectionString do not specify to use Integrated Security or Trusted_Connection or UID or User ID and Credential has been supplied
        if($ConnectionString -notmatch 'Integrated Security' -and $ConnectionString -notmatch 'Trusted_Connection' -and $ConnectionString -notmatch ';UID' -and $ConnectionString -notmatch ';User ID' -and $Credential -and $Credential -ne [System.Management.Automation.PSCredential]::Empty)
        {
            # Get the password out of Credential
            $password=Get-SecureStringPlainText -SecureString $Credential.Password;
            # Build the ConnectionString up to include UID and PWD from Credential
            $ConnectionString=$ConnectionString.Trim(';')+';UID='+$Credential.UserName+';PWD='+$password;
        };
        # Create a Connection object
        $dc=switch($dcType)
        {
            'ODBC' {New-Object System.Data.Odbc.OdbcConnection($ConnectionString);};
            'OleDb'{New-Object System.Data.OleDb.OleDbConnection($ConnectionString);};
            default{New-Object System.Data.SqlClient.SqlConnection($ConnectionString);};
        };
        # Open the db connection
        $start=Get-Date;
        $null=$dc.Open();
        $connectionState=[string]$dc.State;
        if($connectionState -eq 'Open')
        {
            [long]$millisecConnect=((Get-Date)-$start).TotalMilliseconds;
            if($QueryInsert)
            {
                $command=switch($dcType)
                {
                    'ODBC' {New-Object System.Data.Odbc.OdbcCommand($QueryInsert,$dc);};
                    'OleDb'{New-Object System.Data.OleDb.OleDbCommand($QueryInsert,$dc);};
                    default{New-Object System.Data.SqlClient.SqlCommand($QueryInsert,$dc);};
                };
                if($command){try{$start=Get-Date;$rowcountinsert=$command.ExecuteNonQuery();[long]$millisecInsert=((Get-Date)-$start).TotalMilliseconds;}finally{$null=$command.Dispose();};};
            };
            # If we have a DB Query to run
            if($Query)
            {
                # Create a DataAdapter object
                $da=switch($dcType)
                {
                    'ODBC' {New-Object System.Data.Odbc.OdbcDataAdapter($Query,$dc);};
                    'OleDb'{New-Object System.Data.OleDb.OleDbDataAdapter($Query,$dc);};
                    default{New-Object System.Data.SqlClient.SqlDataAdapter($Query,$dc);};
                };
                # If we have the db Data adapter object Fill the DataSet by using the db Data adapter
                if($da){try{$start=Get-Date;$rowcount=$da.Fill($ds);if($rowcount -gt 0){$returnValue=$ds.Tables[0].Rows[0][0];};[long]$millisecSelect=((Get-Date)-$start).TotalMilliseconds;}finally{$null=$da.Dispose();};};
            };
        };
        New-Object PSObject -Property @{Status=$connectionState;MilliSecondsConnect=$millisecConnect;MilliSecondsInsert=$millisecInsert;MilliSecondsSelect=$millisecSelect;ReturnValue=$returnValue;DataSet=$ds;RowCount=$rowcount;RowCountInsert=$rowcountinsert};
    }
    finally
    {
        # Dispose of objects
        if($ds){$null=$ds.Dispose();};
        if($dc)
        {
            $null=$dc.Close();
            $null=$dc.Dispose();
        };
    };
};
function Get-DataSourceQueryResult
{
<#
.SYNOPSIS
Validate a Query Result against given operator and result match string
#>
    param
    (
        [string]$ResultValue,
        [string]$Operator,
        [string]$ResultMatch,
        [string]$Message
    )
    # If the result variable is empty and the operator equals IsNotEmpty, we have a Bad result
    if([string]$ResultValue -eq '' -and $Operator -eq 'IsNotEmpty')
    {
        if(-not ($Message)){$Message='Query result not valid! Expected to receive data but no data received.';};
        New-Object PSObject -Property @{Valid=$false;Message=$Message};
    # If we have a result in the variable
    } elseif([string]$ResultValue -ne '') {
        # We have a bad result if operator equals IsEmpty
        if($Operator -eq 'IsEmpty')
        {
            if(-not ($Message)){$Message='Query result not valid! Expected no data but received '''+$ResultValue+'''.';};
            New-Object PSObject -Property @{Valid=$false;Message=$Message};
        # We have a bad result if operator equals Contains or Match and query result match expected value
        } elseif(($Operator -eq 'Contains' -or $Operator -eq 'Match') -and $ResultValue -match $ResultMatch) {
            if(-not ($Message)){$Message='Query result not valid! Expected that result do not contain '''+$ResultMatch+''' but received '''+$ResultValue+'''.';};
            New-Object PSObject -Property @{Valid=$false;Message=$Message};
        # We have a bad result if operator equals NotContains or NotMatch and query result do not match expected value
        } elseif(($Operator -eq 'NotContains' -or $Operator -eq 'NotMatch') -and $ResultValue -notmatch $ResultMatch) {
            if(-not ($Message)){$Message='Query result not valid! Expected result to contain '''+$ResultMatch+''' but received '''+$ResultValue+'''.';};
            New-Object PSObject -Property @{Valid=$false;Message=$Message};
        # We have a bad result if operator equals Equals and query result equals expected value
        } elseif($Operator -eq 'Equals' -and $ResultValue -eq $ResultMatch) {
            if(-not ($Message)){$Message='Query result not valid! Expected result to not be equal to '''+$ResultMatch+'''.';};
            New-Object PSObject -Property @{Valid=$false;Message=$Message};
        # We have a bad result if operator equals NotEquals and query result do not equals expected value
        } elseif($Operator -eq 'NotEquals' -and $ResultValue -ne $ResultMatch) {
            if(-not ($Message)){$Message='Query result not valid! Expected result to be equal to '''+$ResultMatch+''' but received '''+$ResultValue+'''.';};
            New-Object PSObject -Property @{Valid=$false;Message=$Message};
        # We have a bad result if operator equals BeginsWith and query result begin with expected value
        } elseif($Operator -eq 'BeginsWith' -and $ResultValue -match ('^'+$ResultMatch)) {
            if(-not ($Message)){$Message='Query result not valid! Expected that result do not begin with '''+$ResultMatch+''' but received '''+$ResultValue+'''.';};
            New-Object PSObject -Property @{Valid=$false;Message=$Message};
        # We have a bad result if operator equals EndsWith and query result end with expected value
        } elseif($Operator -eq 'EndsWith' -and $ResultValue -match ($ResultMatch+'$')) {
            if(-not ($Message)){$Message='Query result not valid! Expected that result do not end with '''+$ResultMatch+''' but received '''+$ResultValue+'''.';};
            New-Object PSObject -Property @{Valid=$false;Message=$Message};
        # We have a bad result if operator equals cmatch and query result match expected value (case sensitive)
        } elseif($Operator -eq 'cmatch' -and $ResultValue -cmatch $ResultMatch) {
            if(-not ($Message)){$Message='Query result not valid! Expected that result do not contain '''+$ResultMatch+''' (case sensitive) but received '''+$ResultValue+'''.';};
            New-Object PSObject -Property @{Valid=$false;Message=$Message};
        # We have a bad result if operator equals cnotmatch and query result do not match expected value (case sensitive)
        } elseif($Operator -eq 'cnotmatch' -and $ResultValue -cnotmatch $ResultMatch) {
            if(-not ($Message)){$Message='Query result not valid! Expected result to contain '''+$ResultMatch+''' (case sensitive) but received '''+$ResultValue+'''.';};
            New-Object PSObject -Property @{Valid=$false;Message=$Message};
        } else {
            New-Object PSObject -Property @{Valid=$true;Message='Query result is valid.'};
        };
    } else {
        New-Object PSObject -Property @{Valid=$true;Message='Query result is valid.'};
    };
};
function Test-DataSource
{
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ConnectionString,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string]$Username,
        [string]$Password,
        [string]$Query,
        [string]$QueryInsert,
        [string]$Operator,
        [string]$ResultMatch
    )
    begin
    {
        Set-StrictMode -Version Latest;
        if(@('IsNotEmpty','IsEmpty','Contains','Match','NotContains','NotMatch','Equals','NotEquals','BeginsWith','EndsWith','cmatch','cnotmatch') -notcontains $Operator){$Operator='IsNotEmpty';};
        $outmsg=@();
        $result=@();
    }
    process
    {
        foreach($cs in $ConnectionString)
        {
            $testok=$false;
            $connected=$false;
            $msg='';
            $code=0;
            $rows=$null;
            try
            {
                [System.Management.Automation.PSCredential]$credential=if($Username -and $Password){New-Object System.Management.Automation.PSCredential ($Username,(ConvertTo-SecureString $Password -AsPlainText -Force -ErrorAction SilentlyContinue)) -ErrorAction SilentlyContinue;}else{[System.Management.Automation.PSCredential]::Empty;};
                # Get connection and run query (if specified)
                $result=@(Get-DataSourceStatus -ConnectionString $cs -Query $Query -QueryInsert $QueryInsert -Credential $credential -ErrorAction Stop);
                # If we have an open connection
                if($result -and $result[0].Status -eq 'Open')
                {
                    $connected=$true;
                    # If we have a dataset with rows from DB Query
                    if($Query)
                    {
                        # Check if the value from the first column in the first row of the dataset is valid
                        $queryresult=Get-DataSourceQueryResult -ResultValue $result[0].ReturnValue -Operator $Operator -ResultMatch $ResultMatch -ErrorAction Stop;
                        if($queryresult -and $queryresult.Valid){$testok=$true;}else{$msg=$queryresult.Message;};
                        # If we have more than one row or column
                        if($result[0].DataSet.Tables[0].Rows.Count -gt 1 -or $result[0].DataSet.Tables[0].Columns.Count -gt 1)
                        {
                            $rows=$result[0].DataSet.Tables[0].Rows;
                        };
                    } else {$testok=$true;};
                }
                else{$msg='Unable to connect to Data Source.';};
            }
            catch
            {
                $msg=Get-ErrorMessageString $_;
                if($msg -match 'No connection could be made because the target machine actively refused it'){$msg='No connection could be made because the target machine actively refused it.';};
                if($msg -match 'No such host is known'){$msg='No such host is known.';};
                if($msg -match 'ORA-12514'){$msg='ORA-12514: TNS:listener does not currently know of service requested in connect descriptor.';};
                if($msg -match 'ORA-01017'){$msg='ORA-01017: invalid username/password; logon denied.';};
                if($msg -match 'ORA-28000'){$msg='ORA-28000: the account is locked.';};
                if($msg -match 'ORA-28001'){$msg='ORA-28001: the password has expired.';};
                if($msg -match 'ORA-28003'){$msg='ORA-28003: password verification for the specified password failed.';};
                $code=Get-ErrorCodeNumber $_;
                $Error.Remove($Error[0]);
            }
            finally
            {
                $status=if($testok){'Success';}else{'Failure';};
                if(-not($testok) -and $code -eq 0){$code=1;};
                $outmsg+=if($result)
                {
                    New-Object PSObject -Property @{Status=$status;ConnectionString=$cs;Connected=$connected;MilliSecondsConnect=$result[0].MilliSecondsConnect;MilliSecondsInsert=$result[0].MilliSecondsInsert;MilliSecondsSelect=$result[0].MilliSecondsSelect;ReturnValue=$result[0].ReturnValue;RowCount=$result[0].RowCount;RowCountInsert=$result[0].RowCountInsert;Rows=$rows;Message=$msg;ErrorCode=$code};
                } else {
                    New-Object PSObject -Property @{Status=$status;ConnectionString=$cs;Connected=$connected;MilliSecondsConnect=-1;MilliSecondsInsert=-1;MilliSecondsSelect=-1;ReturnValue='';RowCount=0;RowCountInsert=0;Rows=$null;Message=$msg;ErrorCode=$code};
                };
            };
        };
    }
    end
    {
        $outmsg|Select-Object Status,ConnectionString,Connected,Result,MilliSecondsConnect,MilliSecondsInsert,MilliSecondsSelect,ReturnValue,RowCount,RowCountInsert,Rows,Message,ErrorCode|Sort-Object -Property @{Expression='Status';Descending=$true},@{Expression='ConnectionString';Descending=$false};
    };
};
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
function Install-SCOMConsole2016Prerequisites
{
    Param
    {
        [ValidateNotNullOrEmpty()]
        [System.IO.DirectoryInfo]$DownloadPath = ("$($env:systemdrive)\SCOM2016Reqs")
    }
    # Microsoft Report Viewer 2015 Runtime required for Operations Manager 2016 console
    $reportviewerFile = $($($DownloadPath.FullName)+'\ReportViewer.msi');
    $reportviewerUri = 'http://download.microsoft.com/download/A/1/2/A129F694-233C-4C7C-860F-F73139CF2E01/ENU/x86/ReportViewer.msi';
    $reportviewerInstalled = $null;
    # Report Viewer has a dependency on Microsoft System CLR Types for SQL Server
    $sqlSysClrTypesFile = $($($DownloadPath.FullName)+'\SQLSysClrTypes.msi');
    $sqlSysClrTypesUri = 'http://download.microsoft.com/download/F/E/E/FEE62C90-E5A9-4746-8478-11980609E5C2/ENU/x64/SQLSysClrTypes.msi';
    $sqlSysClrTypesInstalled = $null;
    $installed = @();
    if(-not(Test-Path -Path $($DownloadPath.FullName) -PathType Container)){$null=$DownloadPath.Create();};
    if(Test-Path -Path $($DownloadPath.FullName) -PathType Container)
    {
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
            };
        };
        if(-not($sqlSysClrTypesInstalled)){throw 'Unable to install Microsoft System CLR Types for SQL Server'};
        $installed += @($sqlSysClrTypesInstalled | Sort-Object DisplayVersion -Descending | Select-Object -First 1);
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
            };
        };
        if(-not($reportviewerInstalled)){throw 'Unable to install Microsoft Report Viewer 2015 Runtime'};
        $installed += @($reportviewerInstalled | Sort-Object DisplayVersion -Descending | Select-Object -First 1);
        $installed;
    };
};
function Install-SCOMWebConsolePrerequisites
{
    $requiredfeatures = @(
        'NET-WCF-HTTP-Activation45',
        'Web-Static-Content',
        'Web-Default-Doc',
        'Web-Dir-Browsing',
        'Web-Http-Errors',
        'Web-Http-Logging',
        'Web-Request-Monitor',
        'Web-Filtering',
        'Web-Stat-Compression',
        'Web-Metabase',
        'Web-Asp-Net',
        'Web-Windows-Auth',
        'Web-Mgmt-Console'
    );
    $installfeatures = @();
    foreach($requiredfeature in $requiredfeatures)
    {
        $feature = Get-WindowsFeature -Name $requiredfeature;
        if(-not($feature)){throw "Unable to get required Windows Feature $requiredfeature!"};
        if($feature.InstallState -eq 'Removed'){throw "Windows Feature $requiredfeature has been removed and must be installed from media!"};
        if($feature.InstallState -eq 'Available')
        {
          $installfeatures += $requiredfeature;
        };
    };
    if($installfeatures)
    {
        Install-WindowsFeature -Name $installfeatures;
    };
    if(Get-Module -Name WebAdministration -ListAvailable -Refresh)
    {
        Import-Module -Name WebAdministration;
        $frameworkPath = "$env:windir\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll";
        $isapiConfiguration = Get-WebConfiguration -Filter "/system.webServer/security/isapiCgiRestriction/add[@path='$frameworkPath']/@allowed";
        if(-not($isapiConfiguration.value))
        {
            $null = Add-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/isapiCgiRestriction' -value @{
                description = 'ASP.NET v4.0.30319'
                path        = $frameworkPath
                allowed     = 'True'
            };
            $null = Set-WebConfiguration "/system.webServer/security/isapiCgiRestriction/add[@path='$frameworkPath']/@allowed" -value 'True' -PSPath:IIS:\;
        };
    };
};
$arglist = @("/install /components:$Components";);
# Verify that .NET Framework 4.5 is installed
$feature = Get-WindowsFeature -Name 'NET-Framework-45-Core';
if(-not($feature)){throw "Unable to get required Windows Feature NET-Framework-45-Core!"};
if($feature.InstallState -eq 'Removed'){throw "Windows Feature NET-Framework-45-Core has been removed and must be installed from media!"};
if($feature.InstallState -eq 'Available'){$null = Install-WindowsFeature -Name 'NET-Framework-45-Core';};
if($Components -match 'OMServer' -or $Components -match 'OMReporting')
{
   $dataReaderPassword = Get-SecureStringPlainText -SecureString $DataReaderUser.Password;
};
if($Components -match 'OMServer')
{
    $actionAccountPassword = Get-SecureStringPlainText -SecureString $ActionAccountUser.Password;
    $dasAccountPassword = Get-SecureStringPlainText -SecureString $DASAccountUser.Password;
    $dataWriterPassword = Get-SecureStringPlainText -SecureString $DataWriterUser.Password;
    if(-not($SqlServerInstance)){throw 'A SqlServerInstance must be specified. This can be Server\Instancename or just Server or Always On availability group listener.'};
    if(-not($SqlInstancePort)){$SqlInstancePort=1433};
    $servername=if($SqlServerInstance -match '\\'){$SqlServerInstance.Split('\')[0]} else {$SqlServerInstance};
    # Test WMI Query Connection to SQL Server
    $wmianswer = Get-WmiObject Win32_Bios -ComputerName $servername -ErrorAction SilentlyContinue;
    if(-not($wmianswer)){throw "Unable to run WMI query against Sql Server $servername!"};
    # Test SMB Connection to SQL Server
    $smbportanswer = Test-NetPort -Server $servername -Port 445;
    if(-not($smbportanswer.Connected)){throw "Unable to connect to SMB on Sql Server $servername!"};
    # Test SQL port Connection to SQL Server
    $sqlportanswer = Test-NetPort -Server $servername -Port $SqlInstancePort;
    if(-not($sqlportanswer.Connected)){throw "Unable to connect to Sql port $SqlInstancePort on Sql Server $servername!"};
    # Test connecting to SQL Server Instance
    $connectionstring = 'Data Source='+$SqlServerInstance+','+$SqlInstancePort+';Integrated Security=true';
    if(-not($FirstManagementServer)){$connectionstring += ';Initial Catalog=OperationsManager';};
    $sqlconnection = Test-DataSource -ConnectionString $connectionstring;
    if(-not($sqlconnection.Connected))
    {
        if(-not($FirstManagementServer)){throw "Unable to connect to OperationsManager database on Sql Server Instance $SqlServerInstance,$SqlInstancePort!"};
        throw "Unable to connect to Sql Server Instance $SqlServerInstance,$SqlInstancePort!";
    };
    if(-not($FirstManagementServer))
    {
        $connectionstringBase = 'Data Source='+$SqlServerInstance+','+$SqlInstancePort+';Persist Security Info=True;Initial Catalog=OperationsManager;UID='
        # Test connecting to SQL Server Instance with action Account and Password
        $connectionstring = $connectionstringBase+$($ActionAccountUser.UserName)+';PWD='+$actionAccountPassword;
        $sqlconnection = Test-DataSource -ConnectionString $connectionstring;
        if(-not($sqlconnection.Connected))
        {
            throw "Unable to connect to OperationsManager database on Sql Server Instance $SqlServerInstance,$SqlInstancePort with ActionAccountUser $($ActionAccountUser.UserName)!";
        };
        # Test connecting to SQL Server Instance with DAS Account and Password
        $connectionstring = $connectionstringBase+$($DASAccountUser.UserName)+';PWD='+$dasAccountPassword;
        $sqlconnection = Test-DataSource -ConnectionString $connectionstring;
        if(-not($sqlconnection.Connected))
        {
            throw "Unable to connect to OperationsManager database on Sql Server Instance $SqlServerInstance,$SqlInstancePort with DASAccountUser $($dasAccountUser.UserName)!";
        };
        # Test connecting to SQL Server Instance with DataWriter Account and Password
        $connectionstring = $connectionstringBase+$($DataWriterUser.UserName)+';PWD='+$dataWriterPassword;
        $sqlconnection = Test-DataSource -ConnectionString $connectionstring;
        if(-not($sqlconnection.Connected))
        {
            throw "Unable to connect to OperationsManager database on Sql Server Instance $SqlServerInstance,$SqlInstancePort with DataWriterUser $($DataWriterUser.UserName)!";
        };
    };
    if($FirstManagementServer)
    {
        if(-not($DWSqlServerInstance)){$DWSqlServerInstance = $SqlServerInstance};
        if(-not($DWSqlInstancePort)){$DWSqlInstancePort = $SqlInstancePort};
        if($DWSqlServerInstance -and ($SqlServerInstance -ne $DWSqlServerInstance))
        {
            $servername=if($DWSqlServerInstance -match '\\'){$DWSqlServerInstance.Split('\')[0]} else {$DWSqlServerInstance};
            # Test WMI Query Connection to DW SQL Server
            $wmianswer = Get-WmiObject Win32_Bios -ComputerName $servername -ErrorAction SilentlyContinue;
            if(-not($wmianswer)){throw "Unable to run WMI query against DW Sql Server $servername!"};
            # Test SMB Connection to DW SQL Server
            $smbportanswer = Test-NetPort -Server $servername -Port 445;
            if(-not($smbportanswer.Connected)){throw "Unable to connect to SMB on DW Sql Server $servername!"};
            # Test SQL port Connection to DW SQL Server
            $sqlportanswer = Test-NetPort -Server $servername -Port $DWSqlInstancePort;
            if(-not($sqlportanswer.Connected)){throw "Unable to connect to Sql port $DWSqlInstancePort on DW Sql Server $servername!"};
            # Test connecting to DW SQL Server Instance
            $connectionstring = 'Data Source='+$DWSqlServerInstance+','+$DWSqlInstancePort+';Integrated Security=true';
            if(-not($FirstManagementServer)){$connectionstring += ';Initial Catalog=OperationsManagerDW';};
            $sqlconnection = Test-DataSource -ConnectionString $connectionstring;
            if(-not($sqlconnection.Connected))
            {
                if(-not($FirstManagementServer)){throw "Unable to connect to OperationsManagerDW database on DW Sql Server Instance $DWSqlServerInstance,$DWSqlInstancePort!"};
                throw "Unable to connect to DW Sql Server Instance $DWSqlServerInstance,$DWSqlInstancePort!";
            };
        };
        $arglist += @(
            "/ManagementGroupName:""$ManagementGroupName""",
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
    $arglist += @("/DataReaderUser:$($DataReaderUser.UserName) /DataReaderPassword:$dataReaderPassword");
};

if($Components -match 'OMWebConsole')
{
    $installedfeatures = Install-SCOMWebConsolePrerequisites -ErrorAction Stop;
    if($installedfeatures)
    {
        $installedfeatures;
        throw 'Required features was installed. Restart before you continue installation!';
    };
    $url = if($WebConsoleUseSSL){'https://localhost/'} else {'http://localhost/'};
    $webanswer = Test-WebSite -URL $url -StatusCodeLessOrEqual 400;
    if(-not($webanswer.Connected)){throw "Unable to connect to $url!"};
    if(-not($WebSiteName)){$WebSiteName = 'Default Web Site'};
    $arglist += @("/WebSiteName:""$WebSiteName"" /WebConsoleAuthorizationMode:$WebConsoleAuthorizationMode");
    if($WebConsoleUseSSL){$arglist += @("/WebConsoleUseSSL");};
};
if($Components -match 'OMReporting' -and $SRSInstance)
{
#    $url = 'http://localhost/';
#    $webanswer = Test-WebSite -URL $url -StatusCodeLessOrEqual 400;
#    if(-not($webanswer.Connected)){throw "Unable to connect to $url!"};
    # Test connecting to SRS SQL Server Instance
    $connectionstring = 'Data Source='+$SRSInstance+';Integrated Security=true';
    $sqlconnection = Test-DataSource -ConnectionString $connectionstring;
    if(-not($sqlconnection.Connected))
    {
        throw "Unable to connect to Sql Server Reporting Services Instance $SRSInstance!";
    };
    $arglist += @("/SRSInstance:$SRSInstance /SendODRReports:$SendODRReports");
};
if(-not($Components -match 'OMServer') -and $ManagementServer -and ($Components -match 'OMWebConsole' -or $Components -match 'OMReporting'))
{
    $arglist += @("/ManagementServer:$ManagementServer");
};
if($Components -match 'OMConsole')
{
    $null = Install-SCOMConsole2016Prerequisites -ErrorAction Stop;
};
$arglist += @(
    "/InstallPath:""$InstallPath"" /EnableErrorReporting:$EnableErrorReporting",
    "/SendCEIPReports:$SendCEIPReports /UseMicrosoftUpdate:$UseMicrosoftUpdate",
    "/AcceptEndUserLicenseAgreement:1 /silent"
);
if($NoInstallation){return};
Start-Process -FilePath $SetupPath -ArgumentList $arglist -Wait;
Write-Host "Verify installation log $($env:LOCALAPPDATA)\SCOM\LOGS\OpsMgrSetupWizard.log";
