Param
(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName,
    [string]$SqlInstance = 'MSSQLSERVER',
    [ValidateNotNullOrEmpty()]
    [int]$SqlPort = 1433
)
function Get-ErrorMessageString
{
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory=$true)]
    $e
  )
  $errtype='';
  $msg=if([bool]($e|gm -Name Exception) -and [bool]($e.Exception|gm -Name InnerException) -and $e.Exception.InnerException)
  {
    $errtype=$e.Exception.InnerException.GetType().FullName;
    $e.Exception.InnerException.Message;
  }elseif([bool]($e|gm -Name Exception) -and $e.Exception)
  {
    $errtype=$e.Exception.GetType().FullName;
    $e.Exception.Message;
  }elseif([bool]($e|gm -Name ErrorRecord) -and [bool]($e.ErrorRecord|gm -Name Exception) -and [bool]($e.ErrorRecord.Exception|gm -Name InnerException) -and $e.ErrorRecord.Exception.InnerException)
  {
    $errtype=$e.ErrorRecord.Exception.InnerException.GetType().FullName;
    $e.ErrorRecord.Exception.InnerException.Message;
  }elseif([bool]($e|gm -Name ErrorRecord) -and [bool]($e.ErrorRecord|gm -Name Exception) -and $e.ErrorRecord.Exception)
  {
    $errtype=$e.ErrorRecord.Exception.GetType().FullName;
    $e.ErrorRecord.Exception.Message;
  }elseif([bool]($e|gm -Name Message))
  {
    $errtype=$e.GetType().FullName;
    $e.Message;
  }else{'';};
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
  if([bool]($e|gm -Name Exception) -and [bool]($e.Exception|gm -Name InnerException) -and $e.Exception.InnerException -and [bool]($e.Exception.InnerException|gm -Name Number))
  {
    $e.Exception.InnerException.Number;
  }elseif([bool]($e|gm -Name Exception) -and [bool]($e.Exception|gm -Name InnerException) -and $e.Exception.InnerException -and [bool]($e.Exception.InnerException|gm -Name ErrorCode))
  {
    $e.Exception.InnerException.ErrorCode;
  }elseif([bool]($e|gm -Name Exception) -and [bool]($e.Exception|gm -Name InnerException) -and $e.Exception.InnerException -and [bool]($e.Exception.InnerException|gm -Name HResult))
  {
    $e.Exception.InnerException.HResult;
  }elseif([bool]($e|gm -Name Exception) -and $e.Exception -and [bool]($e.Exception|gm -Name Number))
  {
    $e.Exception.Number;
  }elseif([bool]($e|gm -Name Exception) -and $e.Exception -and [bool]($e.Exception|gm -Name ErrorCode))
  {
    $e.Exception.ErrorCode;
  }elseif([bool]($e|gm -Name Exception) -and $e.Exception -and [bool]($e.Exception|gm -Name HResult))
  {
    $e.Exception.HResult;
  }elseif([bool]($e|gm -Name ErrorRecord) -and [bool]($e.ErrorRecord|gm -Name Exception) -and [bool]($e.ErrorRecord.Exception|gm -Name InnerException) -and $e.ErrorRecord.Exception.InnerException -and [bool]($e.ErrorRecord.Exception.InnerException|gm -Name Number))
  {
    $e.ErrorRecord.Exception.InnerException.Number;
  }elseif([bool]($e|gm -Name ErrorRecord) -and [bool]($e.ErrorRecord|gm -Name Exception) -and [bool]($e.ErrorRecord.Exception|gm -Name InnerException) -and $e.ErrorRecord.Exception.InnerException -and [bool]($e.ErrorRecord.Exception.InnerException|gm -Name ErrorCode))
  {
    $e.ErrorRecord.Exception.InnerException.ErrorCode;
  }elseif([bool]($e|gm -Name ErrorRecord) -and [bool]($e.ErrorRecord|gm -Name Exception) -and [bool]($e.ErrorRecord.Exception|gm -Name InnerException) -and $e.ErrorRecord.Exception.InnerException -and [bool]($e.ErrorRecord.Exception.InnerException|gm -Name HResult))
  {
    $e.ErrorRecord.Exception.InnerException.HResult;
  }elseif([bool]($e|gm -Name ErrorRecord) -and [bool]($e.ErrorRecord|gm -Name Exception) -and $e.ErrorRecord.Exception -and [bool]($e.ErrorRecord.Exception|gm -Name Number))
  {
    $e.ErrorRecord.Exception.Number;
  }elseif([bool]($e|gm -Name ErrorRecord) -and [bool]($e.ErrorRecord|gm -Name Exception) -and $e.ErrorRecord.Exception -and [bool]($e.ErrorRecord.Exception|gm -Name ErrorCode))
  {
    $e.ErrorRecord.Exception.ErrorCode;
  }elseif([bool]($e|gm -Name ErrorRecord) -and [bool]($e.ErrorRecord|gm -Name Exception) -and $e.ErrorRecord.Exception -and [bool]($e.ErrorRecord.Exception|gm -Name HResult))
  {
    $e.ErrorRecord.Exception.HResult;
  }else{-1;};
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
          }
          else{$testok=$true;};
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
        }
        else
        {
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
$wmianswer = Get-WmiObject Win32_Bios -ComputerName $ComputerName -ErrorAction SilentlyContinue;
if(-not($wmianswer)){Write-Host "WMI query failed against $ComputerName" -ForegroundColor Red} else {Write-Host "WMI query succeeded against $ComputerName" -ForegroundColor Green};
$smbportanswer = Test-NetPort -Server $ComputerName -Port 445;
if(-not($smbportanswer.Connected)){Write-Host "SMB TCP Port 445 on $ComputerName is not open!" -ForegroundColor Red} else {Write-Host "SMB TCP Port 445 on $ComputerName is open!" -ForegroundColor Green};
$sqlportanswer = Test-NetPort -Server $ComputerName -Port $SqlPort;
if(-not($sqlportanswer.Connected)){Write-Host "SQL TCP Port $SqlPort on $ComputerName is not open!" -ForegroundColor Red} else {Write-Host "SQL TCP Port $SqlPort on $ComputerName is open!" -ForegroundColor Green};
if(-not($SqlInstance)){$SqlInstance = 'MSSQLSERVER'};
$connectionstring = if($SqlInstance -eq 'MSSQLSERVER'){'Data Source='+$ComputerName+','+$SqlPort+';Integrated Security=true'} else {'Data Source='+$ComputerName+'\'+$SqlInstance+','+$SqlPort+';Integrated Security=true'};
$sqlconnection = Test-DataSource -ConnectionString $connectionstring;
if(-not($sqlconnection.Connected)){Write-Host "Connection to $SqlInstance on $ComputerName port $SqlPort failed!" -ForegroundColor Red} else {Write-Host "Connection to $SqlInstance on $ComputerName port $SqlPort succeeded!" -ForegroundColor Green};
