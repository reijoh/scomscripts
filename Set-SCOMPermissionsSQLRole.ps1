# Prerequisites:
# Setting SQL Permission requires Shared Management Objects.msi available in the SQL Server feature pack
# SMO requires SQLSysClrTypes.msi
# URL to SQL Server 2014 64-bit editions:
# http://download.microsoft.com/download/1/3/0/13089488-91FC-4E22-AD68-5BE58BD5C014/ENU/x64/SQLSysClrTypes.msi
# http://download.microsoft.com/download/1/3/0/13089488-91FC-4E22-AD68-5BE58BD5C014/ENU/x64/SharedManagementObjects.msi
# The user that execute this script need to be member of local Administrators group on each server and be member of the sysadmin role on each SQL Server instance
# This script assumes that the servers are joined to a domain
# Assembled by: Reidar Johansen, reidar@outlook.com
Param ([string[]]$Computers = '.',
       [string]$UserName = 'SQL_SCSOM_MPLowPriv',
       [string]$DomainName = '.')

$ErrorActionPreference = 'Stop'

Function Set-UserLocalGroup {
    [cmdletBinding()]
    Param( 
        [Parameter(Mandatory=$True)][string]$Computer,
        [Parameter(Mandatory=$True)][string]$Group,
        [Parameter(Mandatory=$True)][string]$Domain,
        [Parameter(Mandatory=$True)][string]$User,
        [switch]$add,
        [switch]$remove
    )
    $ADSI = $null
    $exist = $null
    $msg = $null
    $ADSI = [ADSI]"WinNT://$Computer/$Group,group"
    $Members = $null
    $ErrorStat = $null
    try{$Members = @($ADSI.Invoke('Members'))}catch{$ErrorStat = 1}
    if($ErrorStat -eq $null){
        if($Members -ne $null){
            $Members | foreach{If ($User, 'Domain Users' -eq $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)){$exist = 1}}
        }
        if($add){
            If ($exist -eq $null){
                $ADSI.psbase.Invoke('Add',([ADSI]"WinNT://$Domain/$User").path)
                $msg = "$Computer : Added $Domain\$User to Group $Group"
            }
        } elseif ($remove){
            If ($exist -eq 1){
                $ADSI.psbase.Invoke('Remove',([ADSI]"WinNT://$Domain/$User").path)
                $msg = "$Computer : Removed $Domain\$User from Group $Group"
            }
        }
        if ($msg){Write-Output $msg}
    }
}

Function Set-WmiNamespaceSecurity {
    [cmdletBinding()]
    Param (
        [parameter(Mandatory=$true,Position=0)][string] $Namespace,
        [parameter(Mandatory=$true,Position=1)][string] $Operation,
        [parameter(Mandatory=$true,Position=2)][string] $Account,
        [parameter(Position=3)][string[]] $Permissions = $null,
        [bool] $AllowInherit = $false,
        [bool] $Deny = $false,
        [string] $Computer = '.',
        [System.Management.Automation.PSCredential] $Credential = $null
    )

    Process {
        $ErrorActionPreference = 'Stop'

        Function Get-AccessMaskFromPermission($Permissions) {
            $WBEM_ENABLE = 1
            $WBEM_METHOD_EXECUTE = 2
            $WBEM_FULL_WRITE_REP = 4
            $WBEM_PARTIAL_WRITE_REP = 8
            $WBEM_WRITE_PROVIDER = 0x10
            $WBEM_REMOTE_ACCESS = 0x20
            $WBEM_RIGHT_SUBSCRIBE = 0x40
            $WBEM_RIGHT_PUBLISH = 0x80
            $READ_CONTROL = 0x20000
            $WRITE_DAC = 0x40000
       
            $WBEM_RIGHTS_FLAGS = $WBEM_ENABLE,$WBEM_METHOD_EXECUTE,$WBEM_FULL_WRITE_REP,$WBEM_PARTIAL_WRITE_REP,$WBEM_WRITE_PROVIDER,$WBEM_REMOTE_ACCESS,$READ_CONTROL,$WRITE_DAC
            $WBEM_RIGHTS_STRINGS = 'Enable','MethodExecute','FullWrite','PartialWrite','ProviderWrite','RemoteAccess','ReadSecurity','WriteSecurity'
            $msg = $null
            $permissionTable = @{}

            for ($i = 0; $i -lt $WBEM_RIGHTS_FLAGS.Length; $i++) {
                $permissionTable.Add($WBEM_RIGHTS_STRINGS[$i].ToLower(), $WBEM_RIGHTS_FLAGS[$i])
            }

            $accessMask = 0

            foreach ($permission in $Permissions) {
                if (-not $permissionTable.ContainsKey($permission.ToLower())) {
                    throw "$Computer : Unknown permission: $permission Valid permissions: $($permissionTable.Keys)"
                }
                $accessMask += $permissionTable[$permission.ToLower()]
            }
            $accessMask
        }

        If ($Computer -eq '.') {$Computer = (gwmi Win32_ComputerSystem).Name}

        If ($PSBoundParameters.ContainsKey('Credential')) {
            $remoteparams = @{ComputerName=$Computer;Credential=$Credential}
        } Else {
            $remoteparams = @{ComputerName=$Computer}
        }

        $invokeparams = @{Namespace=$namespace;Path="__systemsecurity=@"} + $remoteParams
        $output = $null
        try{
            $output = Invoke-WmiMethod @invokeparams -Name GetSecurityDescriptor
        } catch {
            If (!$output) {
                throw "$Computer : Unable to invoke WMI method GetSecurityDescriptor on namespace $namespace"
            }
            If ($output.ReturnValue -ne 0) {
                throw "$Computer : GetSecurityDescriptor failed: $($output.ReturnValue)"
            }
        }

        $acl = $output.Descriptor
        $OBJECT_INHERIT_ACE_FLAG = 0x1
        $CONTAINER_INHERIT_ACE_FLAG = 0x2
        $ACCESS_ALLOWED_ACE_TYPE = 0x0
        $ACCESS_DENIED_ACE_TYPE = 0x1

        If ($Account.Contains('\')) {
            $domainaccount = $Account.Split('\')
            $domain = $domainaccount[0]
            If (($domain -eq ".") -or ($domain -eq "BUILTIN")) {
                $domain = $Computer
            }
            $accountname = $domainaccount[1]
        } ElseIf ($Account.Contains('@')) {
            $domainaccount = $Account.Split('@')
            $domain = $domainaccount[1].Split('.')[0]
            $accountname = $domainaccount[0]
        } Else {
            $domain = $Computer
            $accountname = $Account
        }

        $win32account = gwmi Win32_Account -Filter "Domain='$domain' and Name='$accountname'"

        If ($win32account -eq $null) {
            throw "$Computer : Account was not found: $Account"
        }

        switch ($Operation) {
            'add' {
                If ($Permissions -eq $null) {
                    throw '$Computer : Permissions must be specified for an add operation'
                }

                $AddSID = $true
                foreach ($ace in $acl.DACL) {
                    If ($ace.Trustee.SidString -eq $win32account.Sid) {
                        $AddSID = $false
                    }
                }
                If ($AddSID) {
                    $accessMask = Get-AccessMaskFromPermission($Permissions)
                    $ace = (New-Object System.Management.ManagementClass('win32_Ace')).CreateInstance()
                    $ace.AccessMask = $accessMask
                    If ($allowInherit) {
                        $ace.AceFlags = $OBJECT_INHERIT_ACE_FLAG + $CONTAINER_INHERIT_ACE_FLAG
                    } Else {
                        $ace.AceFlags = 0
                    }
                    $trustee = (New-Object System.Management.ManagementClass('win32_Trustee')).CreateInstance()
                    $trustee.SidString = $win32account.Sid
                    $ace.Trustee = $trustee
                    If ($deny) {
                        $ace.AceType = $ACCESS_DENIED_ACE_TYPE
                    } Else {
                        $ace.AceType = $ACCESS_ALLOWED_ACE_TYPE
                    }

                    $acl.DACL += $ace.psobject.immediateBaseObject
                    $msg = "$Computer : Added permissions for account $Account on namespace $Namespace"
                }
            }
            'delete' {
                $DeleteSID = $false
                If ($Permissions -ne $null) {
                    throw '$Computer : Permissions cannot be specified for a delete operation'
                }

                [System.Management.ManagementBaseObject[]]$newDACL = @()
                foreach ($ace in $acl.DACL) {
                    If ($ace.Trustee.SidString -ne $win32account.Sid) {
                        $newDACL += $ace.psobject.immediateBaseObject
                    }
                    ElseIf ($ace.Trustee.SidString -eq $win32account.Sid) {
                        $DeleteSID = $true
                    }
                }
                If ($DeleteSID) {
                    $acl.DACL = $newDACL.psobject.immediateBaseObject
                    $msg = "$Computer : Removed permissions for account $Account on namespace $Namespace"
                }
            }
            default {
                throw "$Computer : Unknown operation: $operation Allowed operations: add delete"
            }
        }

        $setparams = @{Name='SetSecurityDescriptor';ArgumentList=$acl.psobject.immediateBaseObject} + $invokeParams
        $output = Invoke-WmiMethod @setparams
        If ($output.ReturnValue -ne 0) {
            throw "$Computer : SetSecurityDescriptor failed: $($output.ReturnValue)"
        }

        if ($msg){Write-Output $msg}
    }
}

Function Set-RegistryPermission {
    [cmdletBinding()]
    Param( 
        [Parameter(Mandatory=$True)]$RemoteBaseKey,
        [Parameter(Mandatory=$True)]$AccessRule,
        [Parameter(Mandatory=$True)][String]$Path,
        [string] $Computer = '.'
    )
    $RegKey = $null
    $RegKey = $RemoteBaseKey.OpenSubKey($Path,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
    If ($RegKey) {
        $acl = $null
        $acl = $RegKey.GetAccessControl()
        if($acl){
            $AddRegPermission = $true
            foreach ($Access in $acl.Access) {
                If ($Access.IdentityReference -match $UserName) {
                    $AddRegPermission = $false
                }
            }
            If ($AddRegPermission) {
                $acl.SetAccessRuleProtection($true, $true)
                $acl.SetAccessRule($AccessRule)
                $RegKey.SetAccessControl($acl)
                $RegKey.Close()
                Write-Output "$Computer : Added permissions for account $UserName on registry key $($RegKey.Name)"
            }
            Else {
                Write-Output "$Computer : Permissions exist for account $UserName on registry key $($RegKey.Name)"
            }
        }
    }
}


# Load SQL Server Shared Management Objects
$smoloaded = $false
foreach ($a in [appdomain]::CurrentDomain.GetAssemblies()) {If($a.FullName -like 'Microsoft.SqlServer.Smo*'){$smoloaded = $true}}
If (!$smoloaded){If ([System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.Smo')){$smoloaded = $true}}
If (!$smoloaded){throw [System.TypeLoadException] "Required assembly SQL Server Shared Management Objects is not installed! This is freely available as part of SQL Server feature pack."}

# Set Computer and Domain to the same as local computer if this is not specified
If ($Computers -eq '.' -or $Computers -eq '') {$Computers = (gwmi Win32_ComputerSystem).Name}
If ($DomainName -eq '.' -or $DomainName -eq '') {$DomainName = $env:USERDOMAIN}
$LoginName = "$DomainName\$UserName"

# Groups that monitoring user must be member of in order to monitor SQL server
$LocalGroups = 'Distributed COM Users','Performance Monitor Users','Event Log Readers','Users'

foreach ($ComputerName in $Computers){
    # Verify that we can connect to computer
    If (Test-Connection -Computername $ComputerName -BufferSize 16 -Count 1 -Quiet) {
        $LocalGroups | %{Set-UserLocalGroup -Computer $ComputerName -Group $_ -Domain $DomainName -User $UserName -add}
        If ((gwmi -namespace 'root' -class '__Namespace' -ComputerName $ComputerName -ErrorAction SilentlyContinue) -ne $null) {
            Set-WMINamespaceSecurity -Namespace 'root' -Operation 'add' -Account $LoginName -Permissions 'Enable','MethodExecute','ReadSecurity','RemoteAccess' -Computer $ComputerName
        }
        If ((gwmi -namespace 'root\cimv2' -class '__Namespace' -ComputerName $ComputerName -ErrorAction SilentlyContinue) -ne $null) {
            Set-WMINamespaceSecurity -Namespace 'root/cimv2' -Operation 'add' -Account $LoginName -Permissions 'Enable','MethodExecute','ReadSecurity','RemoteAccess' -Computer $ComputerName
        }
        If ((gwmi -namespace 'root\DEFAULT' -class '__Namespace' -ComputerName $ComputerName -ErrorAction SilentlyContinue) -ne $null) {
            Set-WMINamespaceSecurity -Namespace 'root/DEFAULT' -Operation 'add' -Account $LoginName -Permissions 'Enable','MethodExecute','ReadSecurity','RemoteAccess' -Computer $ComputerName
        }
        # SQL Server 2005
        If ((gwmi -Namespace 'root\Microsoft\SqlServer\ComputerManagement' -Class '__Namespace' -ComputerName $ComputerName -ErrorAction SilentlyContinue) -ne $null) {
            Set-WMINamespaceSecurity -Namespace 'root\Microsoft\SqlServer\ComputerManagement' -Operation 'add' -Account $LoginName -Permissions 'Enable','MethodExecute','ReadSecurity','RemoteAccess' -Computer $ComputerName
        }
        # SQL Server 2008/2008 R2
        If ((gwmi -Namespace 'root\Microsoft\SqlServer\ComputerManagement10' -Class '__Namespace' -ComputerName $ComputerName -ErrorAction SilentlyContinue) -ne $null) {
            Set-WMINamespaceSecurity -Namespace 'root\Microsoft\SqlServer\ComputerManagement10' -Operation 'add' -Account $LoginName -Permissions 'Enable','MethodExecute','ReadSecurity','RemoteAccess' -Computer $ComputerName
        }
        # SQL Server 2012
        If ((gwmi -Namespace 'root\Microsoft\SqlServer\ComputerManagement11' -Class '__Namespace' -ComputerName $ComputerName -ErrorAction SilentlyContinue) -ne $null) {
            Set-WMINamespaceSecurity -Namespace 'root\Microsoft\SqlServer\ComputerManagement11' -Operation 'add' -Account $LoginName -Permissions 'Enable','MethodExecute','ReadSecurity','RemoteAccess' -Computer $ComputerName
        }
        # SQL Server 2014
        If ((gwmi -Namespace 'root\Microsoft\SqlServer\ComputerManagement12' -Class '__Namespace' -ComputerName $ComputerName -ErrorAction SilentlyContinue) -ne $null) {
            Set-WMINamespaceSecurity -Namespace 'root\Microsoft\SqlServer\ComputerManagement12' -Operation 'add' -Account $LoginName -Permissions 'Enable','MethodExecute','ReadSecurity','RemoteAccess' -Computer $ComputerName
        }
    
        $SQLInstances = $null
        $SQLInstancesFull = $null
        try{
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            If($Reg) {
                $RegKey = $Reg.OpenSubKey('SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL')
                If($RegKey) {
                    $SQLInstances = $RegKey.GetValueNames()
                    $SQLInstancesFull = foreach($SQLInstance in $SQLInstances) {$RegKey.GetValue($SQLInstance)}
                    If ($SQLInstancesFull) {
                        Write-Output "$ComputerName : Found SQL Instances:"
                        $SQLInstancesFull
                    }
                    Else {
                        Write-Output "$ComputerName : Found No SQL Instances!"
                    }
                }
                Else {
                    Write-Output "$ComputerName : Unable to open Remote registry Sub Key"
                }
            }
            Else {
                Write-Output "$ComputerName : Unable to open Remote registry Base Key"
            }
        } catch{}

    
        $Rule = New-Object System.Security.AccessControl.RegistryAccessRule ($LoginName,'ReadKey','Allow')
    
        If ($Reg -and $Rule) {
            Set-RegistryPermission -RemoteBaseKey $Reg -AccessRule $Rule -Computer $ComputerName -Path 'SOFTWARE\\Microsoft\\Microsoft SQL Server'
    
            If ($SQLInstances){
                foreach ($SQLInstance in $SQLInstancesFull) {
                    Write-Output "$ComputerName : Processing Registry Path SOFTWARE\\Microsoft\\Microsoft SQL Server\\$SQLInstance\\MSSQLServer\\Parameters"
                    Set-RegistryPermission -RemoteBaseKey $Reg -AccessRule $Rule -Computer $ComputerName -Path "SOFTWARE\\Microsoft\\Microsoft SQL Server\\$SQLInstance\\MSSQLServer\\Parameters"
                }
                foreach ($SQLInstance in $SQLInstances) {
                    If ($SQLInstance -eq 'MSSQLSERVER') {
                        $FullInstanceName = $ComputerName
                    }
                    Else {
                        $FullInstanceName = "$ComputerName\$SQLInstance"
                    }
                    Write-Output "$FullInstanceName : Processing SQL Instance"
                    $srv = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $FullInstanceName
                    Try {
                       $srv.Logins | Out-Null # Throws and exception if we cannot connect to the server
                    }
                    catch [Exception] {
                        $line = $_.InvocationInfo.ScriptLineNumber
                        Write-Error -Message "$FullInstanceName : Unable to connect to instance! Perhaps Firewall is blocking? $($_.Exception.Message) At line:$line" -Category ObjectNotFound
                        break
                    }
                    try {
                        If (!$srv.Logins.Contains($LoginName)) {
                            $login = New-Object ('Microsoft.SqlServer.Management.Smo.Login') $srv, $LoginName
                            If (([ADSI]"WinNT://$Domain/$UserName").SchemaClassName -eq 'Group') {
                                $login.LoginType = [Microsoft.SqlServer.Management.Smo.LoginType]::WindowsGroup
                            }
                            Else {
                                $login.LoginType = [Microsoft.SqlServer.Management.Smo.LoginType]::WindowsUser
                            }
                            $login.Create()
                            $srv.Logins.Refresh()
                            Write-Output "$FullInstanceName : Added login $LoginName to instance"
                        }
                        $login = $srv.Logins[$LoginName]
                        $numgrantedtypes = 0
                        foreach ($perm in $srv.EnumServerPermissions($login.Name)){
                            If($perm.PermissionState -eq 'Grant') {$numgrantedtypes += 1}
                        }
                        If($numgrantedtypes -lt 4) {
                            $sps = New-Object -TypeName Microsoft.SqlServer.Management.Smo.ServerPermissionSet
                            $sps.ViewAnyDatabase = $true
                            $sps.ViewAnyDefinition = $true
                            $sps.ViewServerState = $true
                            $sps.ConnectSql = $true
                            $srv.Grant($sps, $login.Name)
                            Write-Output "$FullInstanceName : Granted ViewAnyDatabase, ViewAnyDefinition, ViewServerState and ConnectSQL to login $LoginName"
                        }
                        foreach($database in $srv.Databases) {
                            Write-Output "$FullInstanceName : Processing database $($database.name)"
                            If(!$database.Users.Contains($login.Name)) {
                                $user = New-Object('Microsoft.SqlServer.Management.Smo.User') $database, $login.Name
                                $user.Login = $login.Name
                                $user.Create()
                                Write-Output "$FullInstanceName : Added login $LoginName to database $($database.Name)"
                            }
                            If($database.Name -eq 'master') {
                                $View = $database.Views|where{$_.Name -eq 'database_mirroring_witnesses'}
                                $addviewperm = $true
                                foreach ($perm in $View.EnumObjectPermissions($login.Name)){
                                    If($perm.PermissionType.Select -and $perm.PermissionState -eq 'Grant'){$addviewperm = $false}
                                }
                                If($addviewperm) {
                                    $ops = New-Object -TypeName Microsoft.SqlServer.Management.Smo.ObjectPermissionSet
                                    $ops.Select = $true
                                    $View.Grant($ops, $login.Name)
                                    Write-Output "$FullInstanceName : Granted select to login $LoginName on view database_mirroring_witnesses in database master"
                                }
                            }
                            ElseIf($database.Name -eq 'msdb') {
                                $Roles = $database.Roles|where{$_.Name -eq 'PolicyAdministratorRole' -or $_.Name -eq 'SQLAgentReaderRole'}
                                foreach($Role in $Roles) {
                                    If(!$Role.EnumMembers().Contains($login.Name)){
                                        $Role.AddMember($login.Name)
                                        Write-Output "$FullInstanceName : Added login $LoginName to role $($Role.name) in database msdb"
                                    }
                                }
                            }
                        }
                    } catch [System.Management.Automation.RuntimeException] {
                        $line = $_.InvocationInfo.ScriptLineNumber
                        Write-Error -Message "$FullInstanceName : Error setting SQL Instance Permissions. You must set permissions manually! $($_.Exception.Message) At line:$line" -Category PermissionDenied
                        break
                    }
                }
            }
        }
    }
    Else {
        Write-Error "$ComputerName : Unable to connect to Computer!"
    }
}
