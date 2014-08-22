function Disable-SCOMDiscovery {
  <#
  .SYNOPSIS
  Use this function to disable a Discovery
  .DESCRIPTION
  This function will create override to disable a Discovery
  .EXAMPLE
  $MPSource = Get-SCOMManagementPack -Name 'Microsoft.SystemCenter.Advisor'
  $MPTarget = Get-SCOMManagementPack -Name 'Microsoft.SystemCenter.Advisor.Overrides'
  Get-SCOMDiscovery -ManagementPack $MPSource | Disable-SCOMDiscovery -ManagementPack $MPTarget
  .PARAMETER Discoverys
  The Discovery(s) to disable (Get-SCOMDiscovery)
  .PARAMETER ManagementPack
  The Management Pack where the override will be stored
  #>
  [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
  param
  (
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
      HelpMessage='What discovery(s) would you like to disable?')]
    [Microsoft.EnterpriseManagement.Configuration.ManagementPackRule[]]$Discoverys,
    [Parameter(Mandatory=$True,
      HelpMessage='In what Management Pack would you like to store the override?')]
    [Microsoft.EnterpriseManagement.Configuration.ManagementPack]$ManagementPack
  )

  process {
    foreach($Discovery in $Discoverys){
      Write-Verbose "Processing Discovery $($Discovery.Name)"
      If(!(Get-SCOMOverride -Discovery $Discovery -Verbose:$False|where{$_.Property -eq 'Enabled' -and $_.Value -eq 'False' -and $_.Context -eq $Discovery.Target})){
        Write-Verbose "Creating Override"
        $Override = New-Object Microsoft.EnterpriseManagement.Configuration.ManagementPackDiscoveryPropertyOverride($ManagementPack,"Disable$($Discovery.Name)")
        Write-Verbose "Getting Management Pack Element Reference for Discovery"
        $DiscoveryRef = [Microsoft.EnterpriseManagement.Configuration.ManagementPackElementReference``1[Microsoft.EnterpriseManagement.Configuration.ManagementPackDiscovery]]::op_Implicit($Discovery)
        Write-Verbose "Setting Override Properties"
        $Override.Discovery = $DiscoveryRef
        $Override.Property = 'Enabled'
        $Override.Value = 'False'
        $Override.Context = $Discovery.Target
        $Override.DisplayName = "Disable $($Discovery.Name)"
        If ($pscmdlet.ShouldProcess($Discovery)){
          Write-Verbose "Verify Management Pack after adding Override"
          $ManagementPack.Verify()
          Write-Verbose "Save Management Pack"
          $ManagementPack.AcceptChanges()
          Write-Verbose "Disabled Discovery $($Discovery.Name)"
        }
        else {
          Write-Verbose "What If: Performing operation Disable on Discovery $($Discovery.Name)"
        }
      }
      else {
          Write-Verbose "Discovery already disabled $($Discovery.Name)"
      }
    }
  }
}

function Disable-SCOMMonitor {
  <#
  .SYNOPSIS
  Use this function to disable a monitor
  .DESCRIPTION
  This function will create override to disable a monitor
  .EXAMPLE
  $MPSource = Get-SCOMManagementPack -Name 'Microsoft.SystemCenter.Advisor'
  $MPTarget = Get-SCOMManagementPack -Name 'Microsoft.SystemCenter.Advisor.Overrides'
  Get-SCOMMonitor -ManagementPack $MPSource | Disable-SCOMMonitor -ManagementPack $MPTarget
  .PARAMETER Monitors
  The Monitors(s) to disable (Get-SCOMMonitor)
  .PARAMETER ManagementPack
  The Management Pack where the override will be stored
  #>
  [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
  param
  (
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
      HelpMessage='What monitor(s) would you like to disable?')]
    [Microsoft.EnterpriseManagement.Configuration.ManagementPackRule[]]$Monitors,
    [Parameter(Mandatory=$True,
      HelpMessage='In what Management Pack would you like to store the override?')]
    [Microsoft.EnterpriseManagement.Configuration.ManagementPack]$ManagementPack
  )

  process {
    foreach($Monitor in $Monitors){
      Write-Verbose "Processing Monitor $($Monitor.Name)"
      If(!(Get-SCOMOverride -Monitor $Monitor -Verbose:$False|where{$_.Property -eq 'Enabled' -and $_.Value -eq 'False' -and $_.Context -eq $Monitor.Target})){
        Write-Verbose "Creating Override"
        $Override = New-Object Microsoft.EnterpriseManagement.Configuration.ManagementPackMonitorPropertyOverride($ManagementPack,"Disable$($Monitor.Name)")
        Write-Verbose "Getting Management Pack Element Reference for Monitor"
        $MonitorRef = [Microsoft.EnterpriseManagement.Configuration.ManagementPackElementReference``1[Microsoft.EnterpriseManagement.Configuration.ManagementPackMonitor]]::op_Implicit($Monitor)
        Write-Verbose "Setting Override Properties"
        $Override.Monitor = $MonitorRef
        $Override.Property = 'Enabled'
        $Override.Value = 'False'
        $Override.Context = $Monitor.Target
        $Override.DisplayName = "Disable $($Monitor.Name)"
        If ($pscmdlet.ShouldProcess($Monitor)){
          Write-Verbose "Verify Management Pack after adding Override"
          $ManagementPack.Verify()
          Write-Verbose "Save Management Pack"
          $ManagementPack.AcceptChanges()
          Write-Verbose "Disabled Monitor $($Monitor.Name)"
        }
        else {
          Write-Verbose "What If: Performing operation Disable on Monitor $($Monitor.Name)"
        }
      }
      else {
          Write-Verbose "Monitor already disabled $($Monitor.Name)"
      }
    }
  }
}

function Disable-SCOMRule {
  <#
  .SYNOPSIS
  Use this function to disable a rule
  .DESCRIPTION
  This function will create override to disable a rule
  .EXAMPLE
  $MPSource = Get-SCOMManagementPack -Name 'Microsoft.SystemCenter.Advisor'
  $MPTarget = Get-SCOMManagementPack -Name 'Microsoft.SystemCenter.Advisor.Overrides'
  Get-SCOMRule -ManagementPack $MPSource | Disable-SCOMRule -ManagementPack $MPTarget
  .PARAMETER Rules
  The Rule(s) to disable (Get-SCOMRule)
  .PARAMETER ManagementPack
  The Management Pack where the override will be stored
  #>
  [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
  param
  (
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
      HelpMessage='What rule(s) would you like to disable?')]
    [Microsoft.EnterpriseManagement.Configuration.ManagementPackRule[]]$Rules,
    [Parameter(Mandatory=$True,
      HelpMessage='In what Management Pack would you like to store the override?')]
    [Microsoft.EnterpriseManagement.Configuration.ManagementPack]$ManagementPack
  )

  process {
    foreach($Rule in $Rules){
      Write-Verbose "Processing Rule $($Rule.Name)"
      If(!(Get-SCOMOverride -Rule $Rule -Verbose:$False|where{$_.Property -eq 'Enabled' -and $_.Value -eq 'False' -and $_.Context -eq $Rule.Target})){
        Write-Verbose "Creating Override"
        $Override = New-Object Microsoft.EnterpriseManagement.Configuration.ManagementPackRulePropertyOverride($ManagementPack,"Disable$($Rule.Name)")
        Write-Verbose "Getting Management Pack Element Reference for Rule"
        $RuleRef = [Microsoft.EnterpriseManagement.Configuration.ManagementPackElementReference``1[Microsoft.EnterpriseManagement.Configuration.ManagementPackRule]]::op_Implicit($Rule)
        Write-Verbose "Setting Override Properties"
        $Override.Rule = $RuleRef
        $Override.Property = 'Enabled'
        $Override.Value = 'False'
        $Override.Context = $Rule.Target
        $Override.DisplayName = "Disable $($Rule.Name)"
        If ($pscmdlet.ShouldProcess($Rule)){
          Write-Verbose "Verify Management Pack after adding Override"
          $ManagementPack.Verify()
          Write-Verbose "Save Management Pack"
          $ManagementPack.AcceptChanges()
          Write-Verbose "Disabled Rule $($Rule.Name)"
        }
        else {
          Write-Verbose "What If: Performing operation Disable on Rule $($Rule.Name)"
        }
      }
      else {
          Write-Verbose "Rule already disabled $($Rule.Name)"
      }
    }
  }
}
