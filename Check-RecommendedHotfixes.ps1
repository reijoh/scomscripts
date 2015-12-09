param
(
    [string[]]$ComputerName=$env:COMPUTERNAME
)
$UpdateNeeded = $False
Function Check-HotfixInstalled
{
    param
    (
        [string]$HotfixID,
        [string]$ComputerName
    )
    $HF = Get-HotFix -ComputerName $ComputerName -ErrorAction SilentlyContinue | where {$_.HotfixID -match $HotfixID}
    If(!($HF))
    {
        Write-Output "$ComputerName need hotfix $HotfixID"
        $UpdateNeeded = $True
    }
}
Function Check-ServicePackInstalled
{
    param
    (
        [string]$BuildNumber,
        [string]$Version,
        [string]$ComputerName
    )
    $CSDBuildNumber = Invoke-Command -ComputerName $ComputerName -ErrorAction SilentlyContinue -ScriptBlock {(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | select @{N='CSDBuildNumber'; E={$_.CSDBuildNumber}}).CSDBuildNumber}
    $CSDVersion = Invoke-Command -ComputerName $ComputerName -ErrorAction SilentlyContinue -ScriptBlock {(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | select @{N='CSDVersion'; E={$_.CSDVersion}}).CSDVersion}
    If($CSDBuildNumber -lt $BuildNumber -or $CSDVersion -lt $Version)
    {
        Write-Output "$ComputerName need $Version"
        $UpdateNeeded = $True
    }
}
foreach($Computer in $ComputerName)
{
    $OSVersion = Invoke-Command -ComputerName $Computer -ErrorAction SilentlyContinue -ScriptBlock {[Environment]::OSVersion.Version.ToString(3)}
    $OSName = Invoke-Command -ComputerName $Computer -ErrorAction SilentlyContinue -ScriptBlock {(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | select @{N='OSName'; E={$_.ProductName}}).OSName}
    If($OSVersion.Length -ge 8)
    {
        If($OSName -match 'Server')
        {
            $OS = switch($OSVersion.Substring(0,3))
            {
                '5.0' {'2000'}
                '5.2' {'2003'}
                '6.0' {'2008'}
                '6.1' {'2008R2'}
                '6.2' {'2012'}
                '6.3' {'2012R2'}
                default
                {
                    If($OSVersion.Substring(0,4) -eq '10.0')
                    {
                        '2016TP'
                    }
                    else
                    {
                        $OSName
                    }
                }
            }
        }
    }
    switch($OS)
    {
        '2003'
        {
            Check-ServicePackInstalled -BuildNumber '5583' -Version 'Service Pack 2' -ComputerName $Computer
            Check-HotfixInstalled -HotfixID 'KB955360' -ComputerName $Computer
        }
        '2008'
        {
            Check-ServicePackInstalled -BuildNumber '1621' -Version 'Service Pack 2' -ComputerName $Computer
            Check-HotfixInstalled -HotfixID 'KB968967' -ComputerName $Computer
        }
        '2008R2'
        {
            Check-ServicePackInstalled -BuildNumber '1130' -Version 'Service Pack 1' -ComputerName $Computer
            Check-HotfixInstalled -HotfixID 'KB2470949' -ComputerName $Computer
            Check-HotfixInstalled -HotfixID 'KB2547244' -ComputerName $Computer
            # Only check if IIS is installed
            If(Get-Service W3SVC -ComputerName $Computer -ErrorAction SilentlyContinue)
            {
                Check-HotfixInstalled -HotfixID 'KB2618982' -ComputerName $Computer
            }
        }
        '2012'
        {
            Check-HotfixInstalled -HotfixID 'KB2790831' -ComputerName $Computer
        }
        '2012R2'
        {
            # Only check if DNS role is installed
            $DNSStartNumber = Invoke-Command -ComputerName $Computer -ErrorAction SilentlyContinue -ScriptBlock {(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS' -ErrorAction SilentlyContinue | select @{N='Start'; E={$_.Start}}).Start}
            If($DNSStartNumber -and $DNSStartNumber -ne 4)
            {
                Check-HotfixInstalled -HotfixID 'KB2919394' -ComputerName $Computer
            }
            # Only check if Domain Controller role
            If((Get-WMIObject -Class Win32_ComputerSystem -ComputerName $Computer -Namespace 'root\cimv2' -ErrorAction SilentlyContinue).DomainRole -ge 4)
            {
                Check-HotfixInstalled -HotfixID 'KB2955164' -ComputerName $Computer
            }
        }
    }
}
If($UpdateNeeded)
{
    "Install hotfixes!
}
Else
{
    "All OK!"
}
