<#
.SYNOPSIS
Starts Maintenance Mode on selected objects
.DESCRIPTION
Start-SCOMMaintenanceMode will attempt to initiate connection to a Management Server and start Maintenance Mode on objects that meet the specified criteria.
.PARAMETER ManagementServer
Computer Name of a Management Server to connect to.
.PARAMETER Duration
Number of minutes Maintenance Mode will last.
.PARAMETER Reason
Reason for Maintenance Mode.
.PARAMETER Comment
Comment on why Maintenance Mode was started.
.PARAMETER DisableGUI
Do not show dialog (Command Line Mode).
.PARAMETER ObjectType
Specify Object Type for Maintenance Mode.
.PARAMETER ObjectName
Name of the object to start Maintenance Mode on. If ObjectName is not specified, Local Computer Name is used.

A part of the Name can be specified to include more than one object.

Multiple names kan be specified to include more than one object.
.PARAMETER NotRecursive
Includes only instances of the specified object(s) in the scope of the returned results. The default is to include instances of the specified object and all instances that are contained by those instances.
.NOTES
Start-SCOMMaintenanceMode requires SDK Binaries from Operations Manager to exist in the script directory.

Binaries can copied from a Console Computer or Management Server.

Look in the installation directory for the folder SDK Binaries.

Default path is C:\Program Files\Microsoft System Center 2012 R2\Operations Manager\Console\SDK Binaries

I addition the user must have permission to start Maintenance Mode in System Center Operations Manager 2012 R2 (Operators Role or higher).
https://technet.microsoft.com/en-us/library/hh872885.aspx

Example of shortcut/link for the scipt:
Target: %SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -Command "& .\Start-SCOMMaintenanceMode.ps1 -ManagementServer [ManagementServerName] -Comment 'Maintenance of Server'"
Path: [PathToScript]

PS! Replace [PathToScript] with the path of the script and SDK Binaries and [ManagementServerName] with FQDN of the Management Server.

Author:  Reidar Johansen, @reidartwitt
Date:    2015/12/01
Version: 1.0.1.0

Changelog:
2015/12/01 Initial release
.EXAMPLE
PS C:\>Start-SCOMMaintenanceMode.ps1 -ManagementServer SCOM01

This example will show a Dialog Window.
.EXAMPLE
PS C:\>Start-SCOMMaintenanceMode.ps1 -ManagementServer SCOM01 -Duration 10 -Reason PlannedApplicationMaintenance -Comment 'Installation of updates' -ObjectType 'Computer' -ObjectName AGENT01 -DisableGUI

This example will not show any GUI. It will attempt to start Maintenance Mode on Computer(s) that matches the name AGENT01 and sets duration for 10 minutes. A reason and a comment is also given.
.LINK
http://johansenreidar.blogspot.com/
#>
[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
param
(
    [parameter(Position=0,
               Mandatory=$True)]
    [string]$ManagementServer,
    [parameter(Position=1,
               Mandatory=$False)]
    [ValidateRange(5,500000)]
    [int]$Duration=30,
    [parameter(Position=2,
               Mandatory=$False)]
    [string][ValidateSet('ApplicationInstallation', 'ApplicationUnresponsive', 'ApplicationUnstable', 'LossOfNetworkConnectivity', 'PlannedApplicationMaintenance', 'PlannedHardwareInstallation', 'PlannedHardwareMaintenance', 'PlannedOperatingSystemReconfiguration', 'PlannedOther', 'SecurityIssue', 'UnplannedApplicationMaintenance', 'UnplannedHardwareInstallation', 'UnplannedHardwareMaintenance', 'UnplannedOperatingSystemReconfiguration', 'UnplannedOther')]
    $Reason='PlannedOther',
    [parameter(Position=3,
               Mandatory=$False)]
    [string]$Comment,
    [parameter(Position=4,
               Mandatory=$False)]
    [switch]$DisableGUI,
    [parameter(Position=5,
               Mandatory=$False)]
    [string][ValidateSet('Computer', 'Group', 'Class')]
    [string]$ObjectType='Computer',
    [parameter(Position=6,
               Mandatory=$False)]
    [string[]]$ObjectName='',
    [parameter(Position=7,
               Mandatory=$False)]
    [switch]$NotRecursive
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Function Load-OperationsManagerAssembly()
{
    $AssemblyCore = Join-Path -Path $ScriptPath -ChildPath 'Microsoft.EnterpriseManagement.Core.dll'
    If(Test-Path -Path $AssemblyCore -PathType Leaf)
    {
        [Reflection.Assembly]::LoadFile($AssemblyCore) | Out-Null
    }
    Else
    {
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.EnterpriseManagement.Core') | Out-Null
    }
    $AssemblySCOM = Join-Path -Path $ScriptPath -ChildPath 'Microsoft.EnterpriseManagement.OperationsManager.dll'
    If(Test-Path -Path $AssemblySCOM -PathType Leaf)
    {
        [Reflection.Assembly]::LoadFile($AssemblySCOM) | Out-Null
    }
    Else
    {
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.EnterpriseManagement.OperationsManager') | Out-Null
    }
    $AssemblyRuntime = Join-Path -Path $ScriptPath -ChildPath 'Microsoft.EnterpriseManagement.Runtime.dll'
    If(Test-Path -Path $AssemblyRuntime -PathType Leaf)
    {
        [Reflection.Assembly]::LoadFile($AssemblyRuntime) | Out-Null
    }
    Else
    {
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.EnterpriseManagement.Runtime') | Out-Null
    }
}
Function Load-WindowsFormsAssembly()
{
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms
}
Function Load-FormMain()
{
    $frmMain.Controls.Add($tbObjectName)
    $frmMain.Controls.Add($btnSearchObjectName)
    $frmMain.Controls.Add($lbObjectName)
    $frmMain.Controls.Add($gbObjectName)
    $frmMain.Controls.Add($tbDuration)
    $frmMain.Controls.Add($gbDuration)
    $frmMain.Controls.Add($tbComment)
    $frmMain.Controls.Add($gbComment)
    $frmMain.Controls.Add($cbReason)
    $frmMain.Controls.Add($gbReason)
    $frmMain.Controls.Add($chbRecursive)
    $frmMain.Controls.Add($gbRecursive)
    $frmMain.Controls.Add($btnOK)
    $frmMain.Controls.Add($btnAbort)
    $frmMain.Controls.Add($gbObjectType)
    $frmMain.Add_Shown({$frmMain.Activate()})
    [void] $frmMain.ShowDialog()
}
Function Validate-Form()
{
    $ErrorProvider.Clear()
    If($tbObjectName.Text.Length -eq 0)
    {
        $ErrorProvider.SetError($gbObjectName, 'Please enter a name.')
    }
    ElseIf($tbDuration.Text.Length -eq 0)
    {
        $ErrorProvider.SetError($gbDuration, 'Please enter a duration.')
    }
    ElseIf(!($tbDuration.Text -match '^\d+$'))
    {
        $ErrorProvider.SetError($gbDuration, 'Duration must be a number.')
    }
    ElseIf([int]$tbDuration.Text -le 4)
    {
        $ErrorProvider.SetError($gbDuration, 'Duration must be longer than 5 minutes.')
    }
    Else
    {
        $frmMain.Close()
    }
}
Function Abort-Form()
{
    $tbObjectName.Text = ''
    $frmMain.Close()
}
Function Get-MonitoringObjects
{
    param
    (
        [string]$ObjectType,
        [string[]]$ObjectName,
        $ManagementGroup,
        [switch]$GUIList
    )
    $ClassNames = @()
    $Classes = @()
    $PMObjects = @()
    Switch($ObjectType)
    {
        'Computer'
        {
            $ClassNames = 'System.Computer'
        }
        'Group'
        {
            $ClassNames = 'Microsoft.SystemCenter.InstanceGroup'
        }
        default
        {
            $ClassNames = $ObjectName
        }
    }
    ForEach($ClassName in $ClassNames)
    {
        If($ObjectType -eq 'Class' -and $GUIList)
        {
            $ClassCriteria = New-Object Microsoft.EnterpriseManagement.Configuration.MonitoringClassCriteria("DisplayName like '%" + $ClassName + "%'")
        }
        Else
        {
            $ClassCriteria = New-Object Microsoft.EnterpriseManagement.Configuration.MonitoringClassCriteria("DisplayName = '" + $ClassName + "' OR Name = '" + $ClassName + "'")
        }
        If($ClassCriteria)
        {
            $Classes += $ManagementGroup.GetMonitoringClasses($ClassCriteria)
        }
    }
    If($Classes.Count -gt 0)
    {
        If($ObjectType -eq 'Class' -and $GUIList)
        {
            $PMObjects = $Classes
        }
        Else
        {
            ForEach($Class in $Classes)
            {
                If($ObjectType -eq 'Class')
                {
                    $PMObjects += $ManagementGroup.GetPartialMonitoringObjects($Class)
                }
                Else
                {
                    ForEach($Object in $ObjectName)
                    {
                        $Criteria = New-Object Microsoft.EnterpriseManagement.Monitoring.MonitoringObjectGenericCriteria("DisplayName like '%" + $Object + "%'")
                        If($Criteria)
                        {
                            $PMObjects += $ManagementGroup.GetPartialMonitoringObjects($Criteria,$Class)
                        }
                    }
                }
            }
        }
    }
    $PMObjects
}
Function Search-ObjectName()
{
    $ErrorProvider.Clear()
    If($tbObjectName.Text.Length -eq 0)
    {
        $ErrorProvider.SetError($tbObjectName, 'Please enter a name.')
    }
    Else
    {
        $lbObjectName.Items.Clear()
        $ObjectName = $tbObjectName.Text -split ','
        ForEach($o in @($RBObjectType1, $RBObjectType2, $RBObjectType3))
        {
            If($o.Checked)
            {
                $ObjectType = $o.Text
            }
        }
        $PMObjects = @()
        $PMObjects = Get-MonitoringObjects -ObjectType $ObjectType -ObjectName $ObjectName -ManagementGroup $MG -GUIList
        If($PMObjects)
        {
            $lbObjectName.BeginUpdate()
            ForEach($PMObject in $PMObjects)
            {
                $lbObjectName.Items.Add($PMObject.DisplayName)
            }
            $lbObjectName.EndUpdate()
        }
    }
}
Function Set-ObjectName()
{
    $tbObjectName.Text = $lbObjectName.SelectedItems -Join ','
}
$Invocation = (Get-Variable MyInvocation).Value
$ScriptPath = Split-Path $Invocation.MyCommand.Path
If(!($ObjectName))
{
   $ObjectName = $env:COMPUTERNAME
}
If($NotRecursive)
{
    $TraversalDepth = 'OneLevel'
}
Else
{
    $TraversalDepth = 'Recursive'
}
$Reply = 'Yes'
Load-OperationsManagerAssembly
$MGConnSetting = New-Object Microsoft.EnterpriseManagement.ManagementGroupConnectionSettings($ManagementServer)
$MG = New-Object Microsoft.EnterpriseManagement.ManagementGroup($MGConnSetting)
If($DisableGUI -eq $False)
{
    Load-WindowsFormsAssembly
    $RBObjectType1 = New-Object System.Windows.Forms.RadioButton
    $RBObjectType1.Location = New-Object System.Drawing.Point(25,15)
    $RBObjectType1.Size = New-Object System.Drawing.Point(80,30)
    $RBObjectType1.Name = 'ObjectType1'
    $RBObjectType1.TabIndex = 15
    $RBObjectType1.Text = 'Computer'
    $RBObjectType2 = New-Object System.Windows.Forms.RadioButton
    $RBObjectType2.Location = New-Object System.Drawing.Point(110,15)
    $RBObjectType2.Size = New-Object System.Drawing.Point(60,30)
    $RBObjectType2.Name = 'ObjectType2'
    $RBObjectType2.TabIndex = 16
    $RBObjectType2.Text = 'Group'
    $RBObjectType3 = New-Object System.Windows.Forms.RadioButton
    $RBObjectType3.Location = New-Object System.Drawing.Point(185,15)
    $RBObjectType3.Size = New-Object System.Drawing.Point(60,30)
    $RBObjectType3.Name = 'ObjectType3'
    $RBObjectType3.TabIndex = 17
    $RBObjectType3.Text = 'Class'
    If($ObjectType -eq 'Group')
    {
        $RBObjectType2.Checked = $True
    }
    ElseIf($ObjectType -eq 'Class')
    {
        $RBObjectType3.Checked = $True
    }
    Else
    {
        $RBObjectType1.Checked = $True
    }
    $gbObjectType = New-Object System.Windows.Forms.GroupBox
    $gbObjectType.Controls.AddRange(
    @(
        $RBObjectType1,
        $RBObjectType2,
        $RBObjectType3
    ))
    $gbObjectType.Location = New-Object System.Drawing.Point(20,10)
    $gbObjectType.Name = 'ObjectType'
    $gbObjectType.Size = New-Object System.Drawing.Size(360,50)
    $gbObjectType.TabIndex = 18
    $gbObjectType.TabStop = $false
    $gbObjectType.Text = 'Object Type:'
    $tbObjectName = New-Object System.Windows.Forms.TextBox
    $tbObjectName.Name = 'tbObjectName'
    $tbObjectName.Location = New-Object System.Drawing.Size(25,85)
    $tbObjectName.Size = New-Object System.Drawing.Size(280,50)
    $tbObjectName.TabIndex = 1
    $tbObjectName.Text = $ObjectName -join ','
    $btnSearchObjectName = New-Object System.Windows.Forms.Button
    $btnSearchObjectName.Name = 'btnSearch'
    $btnSearchObjectName.Location = New-Object System.Drawing.Size(310,85)
    $btnSearchObjectName.Size = New-Object System.Drawing.Size(60,20)
    $btnSearchObjectName.Text = 'Search'
    $btnSearchObjectName.TabIndex = 2
    $btnSearchObjectName.Add_Click({Search-ObjectName})
    $lbObjectName = New-Object System.Windows.Forms.ListBox
    $lbObjectName.Name = 'lbObjectName'
    $lbObjectName.Location = New-Object System.Drawing.Size(25,110)
    $lbObjectName.Size = New-Object System.Drawing.Size(350,150)
    $lbObjectName.SelectionMode = 'MultiExtended'
    $lbObjectName.TabIndex = 3
    $lbObjectName.Add_SelectedValueChanged({Set-ObjectName})
    $gbObjectName = New-Object System.Windows.Forms.GroupBox
    $gbObjectName.Name = 'gbObjectName'
    $gbObjectName.Location = New-Object System.Drawing.Size(20,65)
    $gbObjectName.Size = New-Object System.Drawing.Size(360,200)
    $gbObjectName.TabIndex = 4
    $gbObjectName.TabStop = $false
    $gbObjectName.Text = 'Name:'
    $tbDuration = New-Object System.Windows.Forms.TextBox
    $tbDuration.Name = 'tbDuration'
    $tbDuration.Location = New-Object System.Drawing.Size(25,290)
    $tbDuration.Size = New-Object System.Drawing.Size(110,50)
    $tbDuration.Text = [string]$Duration
    $tbDuration.TabIndex = 5
    $gbDuration = New-Object System.Windows.Forms.GroupBox
    $gbDuration.Name = 'gbDuration'
    $gbDuration.Location = New-Object System.Drawing.Size(20,270)
    $gbDuration.Size = New-Object System.Drawing.Size(120,50)
    $gbDuration.TabIndex = 6
    $gbDuration.TabStop = $false
    $gbDuration.Text = 'Duration (minutes):'
    $tbComment = New-Object System.Windows.Forms.TextBox
    $tbComment.Name = 'tbComment'
    $tbComment.Location = New-Object System.Drawing.Size(150,290)
    $tbComment.Size = New-Object System.Drawing.Size(225,50)
    $tbComment.Text = [string]$Comment
    $tbComment.TabIndex = 7
    $gbComment = New-Object System.Windows.Forms.GroupBox
    $gbComment.Name = 'gbComment'
    $gbComment.Location = New-Object System.Drawing.Size(145,270)
    $gbComment.Size = New-Object System.Drawing.Size(235,50)
    $gbComment.TabIndex = 8
    $gbComment.TabStop = $false
    $gbComment.Text = 'Maintenance Comment:'
    $cbReason = New-Object System.Windows.Forms.ComboBox
    $cbReason.Name = 'cbReason'
    $cbReason.Location = New-Object System.Drawing.Size(25,345)
    $cbReason.Size = New-Object System.Drawing.Size(250,50)
    [array]$Reasons = 'ApplicationInstallation', 'ApplicationUnresponsive', 'ApplicationUnstable', 'LossOfNetworkConnectivity', 'PlannedApplicationMaintenance', 'PlannedHardwareInstallation', 'PlannedHardwareMaintenance', 'PlannedOperatingSystemReconfiguration', 'PlannedOther', 'SecurityIssue', 'UnplannedApplicationMaintenance', 'UnplannedHardwareInstallation', 'UnplannedHardwareMaintenance', 'UnplannedOperatingSystemReconfiguration', 'UnplannedOther'
    $cbReason.TabIndex = 9
    $cbReason.Items.AddRange($Reasons)
    If($Reason -and $Reasons -contains $Reason)
    {
        $cbReason.SelectedItem = $Reason
    }
    Else
    {
        $cbReason.SelectedItem = $cbReason.Items[0]
    }
    $gbReason = New-Object System.Windows.Forms.GroupBox
    $gbReason.Name = 'gbReason'
    $gbReason.Location = New-Object System.Drawing.Size(20,325)
    $gbReason.Size = New-Object System.Drawing.Size(260,50)
    $gbReason.TabIndex = 10
    $gbReason.TabStop = $false
    $gbReason.Text = 'Reason:'
    $chbRecursive = New-Object System.Windows.Forms.CheckBox
    $chbRecursive.Name = 'chbRecursive'
    $chbRecursive.Location = New-Object System.Drawing.Size(295,345)
    $chbRecursive.Size = New-Object System.Drawing.Size(20,20)
    $chbRecursive.Text = ''
    If(!($NotRecursive))
    {
        $chbRecursive.Checked = $True
    }
    $chbRecursive.TabIndex = 11
    $gbRecursive = New-Object System.Windows.Forms.GroupBox
    $gbRecursive.Name = 'gbRecursive'
    $gbRecursive.Location = New-Object System.Drawing.Size(285,325)
    $gbRecursive.Size = New-Object System.Drawing.Size(95,50)
    $gbRecursive.TabIndex = 12
    $gbRecursive.TabStop = $false
    $gbRecursive.Text = 'Recursive:'
    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Name = 'btnOK'
    $btnOK.Location = New-Object System.Drawing.Size(210,385)
    $btnOK.Size = New-Object System.Drawing.Size(80,20)
    $btnOK.Text = 'Start'
    $btnOK.TabIndex = 13
    $btnOK.Add_Click({Validate-Form})
    $btnAbort = New-Object System.Windows.Forms.Button
    $btnAbort.Name = 'btnAbort'
    $btnAbort.Location = New-Object System.Drawing.Size(300,385)
    $btnAbort.Size = New-Object System.Drawing.Size(80,20)
    $btnAbort.Text = 'Abort'
    $btnAbort.TabIndex = 14
    $btnAbort.Add_Click({Abort-Form})
    $Global:ErrorProvider = New-Object System.Windows.Forms.ErrorProvider
    $frmMain = New-Object System.Windows.Forms.Form
    $frmMain.Name = 'ScheduleMaintenance'
    $frmMain.Size = New-Object System.Drawing.Size(410,450)
    $frmMain.MinimumSize = New-Object System.Drawing.Size(410,450)
    $frmMain.MaximumSize = New-Object System.Drawing.Size(410,450)
    $frmMain.StartPosition = 'CenterScreen'
    $frmMain.SizeGripStyle = 'Hide'
    $frmMain.Text = 'Start Maintenance Mode'
    $frmMain.ControlBox = $false
    $frmMain.TopMost = $true
    $frmMain.KeyPreview = $True
    $frmMain.Add_KeyDown({If($_.KeyCode -eq "Enter"){Validate-Form}})
    $frmMain.Add_KeyDown({If($_.KeyCode -eq "Escape"){Abort-Form}})
    Load-FormMain
    If($tbObjectName.Text -eq '')
    {
        Exit
    }
    $Reply = 'No'
    ForEach($o in @($RBObjectType1, $RBObjectType2, $RBObjectType3))
    {
        If($o.Checked)
        {
            $ObjectType = $o.Text
        }
    }
    If($tbObjectName.Text.Length -gt 0 -and $tbDuration.Text -match "^\d+$" -and [int]$tbDuration.Text -gt 0)
    {
        $Reply = [System.Windows.Forms.MessageBox]::Show("Would you like to start Maintenance Mode on $ObjectType $($tbObjectName.Text) for $($tbDuration.Text) minutes?", 'Warning', 'YesNo', 'Warning')
    }
    $ObjectName = $tbObjectName.Text -split ','
    $Duration = [int]$tbDuration.Text
    $Comment = $tbComment.Text
    $Reason = $cbReason.SelectedItem.ToString()
    If($chbRecursive.Checked)
    {
        $TraversalDepth = 'Recursive'
    }
    Else
    {
        $TraversalDepth = 'OneLevel'
    }
}
If($Reply -eq 'Yes')
{
    Try
    {
        $PMObjects = @()
        $PMObjects = Get-MonitoringObjects -ObjectType $ObjectType -ObjectName $ObjectName -ManagementGroup $MG
        $MSG = ''
        $StartCount = 0
        $UpdateCount = 0
        If($PMObjects)
        {
            ForEach($PMObject in $PMObjects)
            {
                If($PMObject.InMaintenanceMode)
                {
                    $UpdateCount += 1
                    $MSG = "Updated Maintenance Mode on $($PMObject.DisplayName) for $Duration minutes."
                    If($pscmdlet.ShouldProcess($PMObject.DisplayName))
                    {
                        $PMObject.UpdateMaintenanceMode(([datetime]::Now).AddMinutes($Duration).touniversaltime(), $Reason, $Comment, $TraversalDepth)
                    }
                }
                Else
                {
                    $StartCount += 1
                    $MSG = "Started Maintenance Mode on $($PMObject.DisplayName) for $Duration minutes."
                    If($pscmdlet.ShouldProcess($PMObject.DisplayName))
                    {
                        $PMObject.ScheduleMaintenanceMode([datetime]::Now.touniversaltime(), ([datetime]::Now).AddMinutes($Duration).touniversaltime(), $Reason, $Comment, $TraversalDepth)
                    }
                }
            }
        }
        If($UpdateCount -gt 0 -and $StartCount -gt 0)
        {
            $MSG = "Started Maintenance Mode on $StartCount objects and updated $UpdateCount. Duration $Duration minutes."
        }
        ElseIf($UpdateCount -gt 1)
        {
            $MSG = "Updated Maintenance Mode on $UpdateCount objects. Duration $Duration minutes."
        }
        ElseIf($StartCount -gt 1)
        {
            $MSG = "Started Maintenance Mode on $StartCount objects for $Duration minutes."
        }
        If(($UpdateCount -gt 0 -or $StartCount -gt 0) -and $MSG -ne '')
        {
            If($DisableGUI -eq $False)
            {
                $Reply = [System.Windows.Forms.MessageBox]::Show($MSG, 'Information', 'OK', 'Information')
            }
            Else
            {
                $MSG
            }
        }
    }
    catch
    {
        $MSG += 'Exception on line ' + $_.InvocationInfo.ScriptLineNumber + ' column ' + $_.InvocationInfo.OffsetInLine + '. Message: ' + $_.Exception.Message
        If($DisableGUI -eq $False)
        {
            $Reply = [System.Windows.Forms.MessageBox]::Show($MSG, 'Error', 'OK', 'Error')
        }
        Else
        {
            $MSG
        }
    }
}
