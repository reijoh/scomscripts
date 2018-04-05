param
(
    [string[]]$ComputerName=$env:COMPUTERNAME
)
<#
Original Script by Reidar Johansen (@reidartwitt):
https://github.com/reijoh/scomscripts/blob/master/Check-RecommendedHotfixes.ps1
 
Adjusted based on modified version by Christopher Keyaert (christopher@vnext.be)
Date: December 11th, 2015
https://www.vnext.be/2015/12/11/scom-agentos-recommended-hotfix-kb/
 
Based on the KB list available at:
http://blogs.technet.com/b/kevinholman/archive/2009/01/27/which-hotfixes-should-i-apply.aspx

Another source to look at for additional hotfix recommendations:
https://support.microsoft.com/en-us/help/2843219/system-center-2012-operations-manager-recommended-agent-operating-syst

Modified again by Reidar Johansen (@reidartwitt)
Date: April 4th, 2018
#>
# Global Variables
$global:TotalUpdatesNeeded = 0
$global:Description = $null
$KB2003 = 'KB955360','KB981263','KB933061','KB982167','KB932370'
$KB2008 = 'KB968967','KB981263','KB2710558','KB2812950'
$KB2008ClusSvc = 'KB968936'
$KB2008R2 = 'KB2470949','KB2547244','KB2878378','KB2734909','KB2692929'
$KB2008R2IIS = 'KB2618982'
$KB2012 = 'KB2790831'
$KB2012R2 = 'KB2919394','KB2955164' # We do not check for KB2923126 because it is included in update rollup KB2919394, and not KB2954185 because it is included in update rollup KB2955164
Function Update-HotfixNeeded
{
    param
    (
        [string]$HotfixID,
        [string]$ComputerName
    )
    $HF = $null
    $HF = Get-HotFix -ComputerName $ComputerName -ErrorAction SilentlyContinue | where {$_.HotfixID -match $HotfixID}
    If(!($HF))
    {
        $global:Description += "$ComputerName need hotfix $HotfixID`r`n"
        $global:TotalUpdatesNeeded += 1
    }
}
Function Update-ServicePackNeeded
{
    param
    (
        [string]$BuildNumber,
        [string]$Version,
        [string]$ComputerName
    )
    If($BuildNumber)
    {
        $CSDBuildNumber = Invoke-Command -ComputerName $ComputerName -ErrorAction SilentlyContinue -ScriptBlock {(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | select @{N='CSDBuildNumber'; E={$_.CSDBuildNumber}}).CSDBuildNumber}
        If(!($CSDBuildNumber))
        {
            $CSDBuildNumber = '9999'
        }
    }
    else
    {
        $CSDBuildNumber = ''
        $BuildNumber = ''
    }
    $CSDVersion = Invoke-Command -ComputerName $ComputerName -ErrorAction SilentlyContinue -ScriptBlock {(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | select @{N='CSDVersion'; E={$_.CSDVersion}}).CSDVersion}
    If($CSDVersion -notmatch 'Service Pack \d')
    {
        $CSDVersion = ''
    }
    If($CSDBuildNumber -lt $BuildNumber -or $CSDVersion -lt $Version)
    {
        $global:Description += "$ComputerName need $Version`r`n"
        $global:TotalUpdatesNeeded += 1
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
            Update-ServicePackNeeded -Version 'Service Pack 2' -ComputerName $Computer
            foreach($KB in $KB2003)
            {
                Update-HotfixNeeded -HotfixID $KB -ComputerName $Computer
            }
        }
        '2008'
        {
            Update-ServicePackNeeded -BuildNumber '1621' -Version 'Service Pack 2' -ComputerName $Computer
            foreach($KB in $KB2008)
            {
                Update-HotfixNeeded -HotfixID $KB -ComputerName $Computer
            }
            # Only check if Failover Clustering feature is installed
            If(Get-Service -Name ClusSvc -ComputerName $Computer -ErrorAction SilentlyContinue)
            {
                foreach($KB in $KB2008ClusSvc)
                {
                    Update-HotfixNeeded -HotfixID $KB -ComputerName $Computer
                }
            }
        }
        '2008R2'
        {
            Update-ServicePackNeeded -BuildNumber '1130' -Version 'Service Pack 1' -ComputerName $Computer
            foreach($KB in $KB2008R2)
            {
                Update-HotfixNeeded -HotfixID $KB -ComputerName $Computer
            }
            # Only check if IIS is installed
            If(Get-Service -Name W3SVC -ComputerName $Computer -ErrorAction SilentlyContinue)
            {
                foreach($KB in $KB2008R2IIS)
                {
                    Update-HotfixNeeded -HotfixID $KB -ComputerName $Computer
                }
            }
        }
        '2012'
        {
            foreach($KB in $KB2012)
            {
                Update-HotfixNeeded -HotfixID $KB -ComputerName $Computer
            }
        }
        '2012R2'
        {
            foreach($KB in $KB2012R2)
            {
                Update-HotfixNeeded -HotfixID $KB -ComputerName $Computer
            }
        }
    }
}
If($TotalUpdatesNeeded -gt 0)
{
    If($ComputerName.Count -eq 1)
    {
        "A total of $TotalUpdatesNeeded updates missing on $ComputerName"+':'
    }
    Else
    {
        "A total of $TotalUpdatesNeeded updates missing on $($ComputerName.Count) computers:"
    }
    $Description|sort
}
Else
{
    'All OK!'
}
