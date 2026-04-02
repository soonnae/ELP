param(
    [string]$ScenarioPath = "C:\ELP\ForensicLab\scenario_access.json",
    [string]$OutputDir = "C:\ELP\ForensicLab\output",
    [string]$VictimTarget = "192.168.75.130",
    [string]$DCTarget = "192.168.75.128",

    [string]$DomainNetBIOS = "LAB",
    [string]$DomainFqdn = "lab.local",

    [string]$AttackerUser = "user1",
    [string]$VictimUser = "user3",

    [string]$InvalidPassword = "WrongPass123!",
    [string]$NewPassword = "TempPass123!",

    [int]$ObservationWindowSeconds = 12,
    [switch]$TryRemoteEventCollection,
    [switch]$EnableLabActions,
    [switch]$EnableAccountManipulationActions,
    [switch]$EnableFirewallAnomalyActions,
    [switch]$EnableIntegrityAnomalyActions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function ConvertTo-PrettyJson {
    param($InputObject)
    return ($InputObject | ConvertTo-Json -Depth 15)
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrMsg {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Load-Scenario {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Scenario file not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    return ($raw | ConvertFrom-Json)
}

function Get-NowIso {
    return (Get-Date).ToString("o")
}

function Safe-Message {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    return $Text.Trim()
}

function Resolve-CollectionTargets {
    param(
        [string[]]$Hosts,
        [string]$VictimTarget,
        [string]$DCTarget,
        [switch]$TryRemoteEventCollection
    )

    $resolved = @()

    foreach ($hostEntry in $Hosts) {
        switch ($hostEntry) {
            "attacker" {
                $resolved += [PSCustomObject]@{
                    role   = "attacker"
                    target = $env:COMPUTERNAME
                }
            }
            "victim" {
                if ($TryRemoteEventCollection -and -not [string]::IsNullOrWhiteSpace($VictimTarget)) {
                    $resolved += [PSCustomObject]@{
                        role   = "victim"
                        target = $VictimTarget
                    }
                }
            }
            "dc" {
                if ($TryRemoteEventCollection -and -not [string]::IsNullOrWhiteSpace($DCTarget)) {
                    $resolved += [PSCustomObject]@{
                        role   = "dc"
                        target = $DCTarget
                    }
                }
            }
        }
    }

    $seen = @{}
    $unique = @()

    foreach ($item in $resolved) {
        $key = "{0}|{1}" -f $item.role, $item.target
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $unique += $item
        }
    }

    return $unique
}

function Get-ObservedEvents {
    param(
        [datetime]$Since,
        [int[]]$EventIds,
        [string[]]$LogNames,
        [object[]]$ComputerTargets,
        [int]$MaxEventsPerLog = 30
    )

    $all = @()

    foreach ($entry in $ComputerTargets) {
        $role = $entry.role
        $computer = $entry.target

        foreach ($log in $LogNames) {
            try {
                $filter = @{
                    LogName   = $log
                    StartTime = $Since
                }

                $events = Get-WinEvent -FilterHashtable $filter -ComputerName $computer -ErrorAction Stop |
                    Where-Object { $EventIds -contains $_.Id } |
                    Select-Object -First $MaxEventsPerLog

                foreach ($ev in $events) {
                    $all += [PSCustomObject]@{
                        role         = $role
                        computer     = $computer
                        log_name     = $log
                        event_id     = [int]$ev.Id
                        time_created = $ev.TimeCreated
                        provider     = $ev.ProviderName
                        level        = $ev.LevelDisplayName
                        task         = $ev.TaskDisplayName
                        status       = "observed"
                        message      = Safe-Message -Text $ev.Message
                    }
                }
            }
            catch {
                $all += [PSCustomObject]@{
                    role         = $role
                    computer     = $computer
                    log_name     = $log
                    event_id     = $null
                    time_created = $null
                    provider     = $null
                    level        = $null
                    task         = $null
                    status       = "collection_failed"
                    message      = Safe-Message -Text $_.Exception.Message
                }
            }
        }
    }

    return $all
}

function Get-StageObservationProfile {
    param([string]$StageName)

    $profiles = @{
        "initial_system_integrity_anomaly" = @{
            CandidateEventIds = @(5038)
            Hosts             = @("attacker", "victim")
            LogNames          = @("System", "Security")
            Notes             = "System integrity anomaly related observation profile"
        }

        "first_password_change_attempt" = @{
            CandidateEventIds = @(4723)
            Hosts             = @("dc")
            LogNames          = @("Security")
            Notes             = "Password change attempt usually observed on DC in domain environments"
        }

        "first_failed_logon_attempt" = @{
            CandidateEventIds = @(4625, 4776, 4771)
            Hosts             = @("victim", "dc")
            LogNames          = @("Security")
            Notes             = "Invalid logon attempt; victim and/or DC may observe related failures"
        }

        "first_kerberos_service_ticket_attempt" = @{
            CandidateEventIds = @(4769, 4771)
            Hosts             = @("dc")
            LogNames          = @("Security")
            Notes             = "Kerberos service ticket / pre-auth related failures"
        }

        "first_kerberos_pre_auth_failure" = @{
            CandidateEventIds = @(4771)
            Hosts             = @("dc")
            LogNames          = @("Security")
            Notes             = "Kerberos pre-auth failure"
        }

        "first_password_reset_attempt" = @{
            CandidateEventIds = @(4724)
            Hosts             = @("dc")
            LogNames          = @("Security")
            Notes             = "Password reset attempt generally observed on DC"
        }

        "first_firewall_anomaly" = @{
            CandidateEventIds = @(5031, 5157)
            Hosts             = @("attacker", "victim")
            LogNames          = @("Security", "System")
            Notes             = "Firewall anomaly or blocked connection traces"
        }

        "first_ntlm_authentication_failure" = @{
            CandidateEventIds = @(4776, 4625)
            Hosts             = @("dc", "victim")
            LogNames          = @("Security")
            Notes             = "NTLM failure may show on DC and/or victim"
        }

        "second_kerberos_pre_auth_failure" = @{
            CandidateEventIds = @(4771)
            Hosts             = @("dc")
            LogNames          = @("Security")
            Notes             = "Repeated Kerberos pre-auth failure"
        }

        "second_password_change_attempt" = @{
            CandidateEventIds = @(4723)
            Hosts             = @("dc")
            LogNames          = @("Security")
            Notes             = "Repeated password change attempt"
        }

        "second_system_integrity_anomaly" = @{
            CandidateEventIds = @(5038)
            Hosts             = @("attacker", "victim")
            LogNames          = @("System", "Security")
            Notes             = "Repeated integrity anomaly"
        }

        "third_kerberos_pre_auth_failure" = @{
            CandidateEventIds = @(4771)
            Hosts             = @("dc")
            LogNames          = @("Security")
            Notes             = "Repeated Kerberos pre-auth failure"
        }

        "second_ntlm_authentication_failure" = @{
            CandidateEventIds = @(4776, 4625)
            Hosts             = @("dc", "victim")
            LogNames          = @("Security")
            Notes             = "Repeated NTLM failure"
        }

        "second_firewall_anomaly" = @{
            CandidateEventIds = @(5031, 5157)
            Hosts             = @("attacker", "victim")
            LogNames          = @("Security", "System")
            Notes             = "Repeated firewall anomaly or blocked connection"
        }

        "final_failed_logon_attempt" = @{
            CandidateEventIds = @(4625, 4776, 4771)
            Hosts             = @("victim", "dc")
            LogNames          = @("Security")
            Notes             = "Final invalid logon attempt"
        }
    }

    if ($profiles.ContainsKey($StageName)) {
        return $profiles[$StageName]
    }

    return @{
        CandidateEventIds = @()
        Hosts             = @("attacker")
        LogNames          = @("Security", "System")
        Notes             = "Fallback observation profile"
    }
}

function Invoke-InvalidSMBLogon {
    param(
        [string]$VictimTarget,
        [string]$DomainNetBIOS,
        [string]$VictimUser,
        [string]$InvalidPassword
    )

    $cmd = "net use \\$VictimTarget\IPC$ /user:$DomainNetBIOS\$VictimUser $InvalidPassword /persistent:no"

    try {
        $output = cmd /c $cmd 2>&1 | Out-String

        return [PSCustomObject]@{
            execution_status = "attempted"
            executed_command = $cmd
            message          = Safe-Message -Text $output
        }
    }
    catch {
        return [PSCustomObject]@{
            execution_status = "failed"
            executed_command = $cmd
            message          = Safe-Message -Text $_.Exception.Message
        }
    }
}

function Invoke-PasswordChangeAttempt {
    param(
        [string]$VictimUser,
        [string]$NewPassword,
        [switch]$EnableAccountManipulationActions
    )

    $cmd = "net user $VictimUser $NewPassword /domain"

    if (-not $EnableAccountManipulationActions) {
        return [PSCustomObject]@{
            execution_status = "manual_required"
            executed_command = $cmd
            message          = "Account manipulation actions are disabled by default."
        }
    }

    try {
        $output = cmd /c $cmd 2>&1 | Out-String
        return [PSCustomObject]@{
            execution_status = "attempted"
            executed_command = $cmd
            message          = Safe-Message -Text $output
        }
    }
    catch {
        return [PSCustomObject]@{
            execution_status = "failed"
            executed_command = $cmd
            message          = Safe-Message -Text $_.Exception.Message
        }
    }
}

function Invoke-PasswordResetAttempt {
    param(
        [string]$VictimUser,
        [string]$NewPassword,
        [switch]$EnableAccountManipulationActions
    )

    $cmd = "net user $VictimUser $NewPassword /domain"

    if (-not $EnableAccountManipulationActions) {
        return [PSCustomObject]@{
            execution_status = "manual_required"
            executed_command = $cmd
            message          = "Account reset/manipulation actions are disabled by default."
        }
    }

    try {
        $output = cmd /c $cmd 2>&1 | Out-String
        return [PSCustomObject]@{
            execution_status = "attempted"
            executed_command = $cmd
            message          = Safe-Message -Text $output
        }
    }
    catch {
        return [PSCustomObject]@{
            execution_status = "failed"
            executed_command = $cmd
            message          = Safe-Message -Text $_.Exception.Message
        }
    }
}

function Invoke-KerberosRelatedAttempt {
    param(
        [string]$VictimTarget,
        [string]$StageName,
        [switch]$EnableLabActions
    )

    if (-not $EnableLabActions) {
        return [PSCustomObject]@{
            execution_status = "manual_required"
            executed_command = "manual_kerberos_attempt_required"
            message          = "Kerberos-specific failure generation is environment-dependent. Add your lab-specific command here if needed."
        }
    }

    return [PSCustomObject]@{
        execution_status = "manual_required"
        executed_command = "manual_kerberos_attempt_required"
        message          = "Kerberos-specific generation not automatically implemented in the default script."
    }
}

function Invoke-FirewallAnomaly {
    param(
        [switch]$EnableFirewallAnomalyActions
    )

    if (-not $EnableFirewallAnomalyActions) {
        return [PSCustomObject]@{
            execution_status = "manual_required"
            executed_command = "manual_firewall_anomaly_required"
            message          = "Firewall anomaly generation is disabled by default."
        }
    }

    return [PSCustomObject]@{
        execution_status = "manual_required"
        executed_command = "manual_firewall_anomaly_required"
        message          = "Add your approved lab-only firewall anomaly command here."
    }
}

function Invoke-IntegrityAnomaly {
    param(
        [switch]$EnableIntegrityAnomalyActions
    )

    if (-not $EnableIntegrityAnomalyActions) {
        return [PSCustomObject]@{
            execution_status = "manual_required"
            executed_command = "manual_integrity_anomaly_required"
            message          = "Integrity anomaly generation is disabled by default."
        }
    }

    return [PSCustomObject]@{
        execution_status = "manual_required"
        executed_command = "manual_integrity_anomaly_required"
        message          = "Add your approved lab-only integrity anomaly command here."
    }
}

function Invoke-StageAction {
    param(
        $Stage,
        [string]$VictimTarget,
        [string]$DomainNetBIOS,
        [string]$DomainFqdn,
        [string]$AttackerUser,
        [string]$VictimUser,
        [string]$InvalidPassword,
        [string]$NewPassword,
        [switch]$EnableLabActions,
        [switch]$EnableAccountManipulationActions,
        [switch]$EnableFirewallAnomalyActions,
        [switch]$EnableIntegrityAnomalyActions
    )

    $name = $Stage.stage_name

    switch ($name) {
        "initial_system_integrity_anomaly" {
            return Invoke-IntegrityAnomaly -EnableIntegrityAnomalyActions:$EnableIntegrityAnomalyActions
        }

        "first_password_change_attempt" {
            return Invoke-PasswordChangeAttempt `
                -VictimUser $VictimUser `
                -NewPassword $NewPassword `
                -EnableAccountManipulationActions:$EnableAccountManipulationActions
        }

        "first_failed_logon_attempt" {
            if (-not $EnableLabActions) {
                return [PSCustomObject]@{
                    execution_status = "manual_required"
                    executed_command = "net use \\$VictimTarget\IPC$ /user:$DomainNetBIOS\$VictimUser <wrong_password>"
                    message          = "Authentication attempt execution is disabled. Use -EnableLabActions to run lab logon attempts."
                }
            }

            return Invoke-InvalidSMBLogon `
                -VictimTarget $VictimTarget `
                -DomainNetBIOS $DomainNetBIOS `
                -VictimUser $VictimUser `
                -InvalidPassword $InvalidPassword
        }

        "first_kerberos_service_ticket_attempt" {
            return Invoke-KerberosRelatedAttempt -VictimTarget $VictimTarget -StageName $name -EnableLabActions:$EnableLabActions
        }

        "first_kerberos_pre_auth_failure" {
            return Invoke-KerberosRelatedAttempt -VictimTarget $VictimTarget -StageName $name -EnableLabActions:$EnableLabActions
        }

        "first_password_reset_attempt" {
            return Invoke-PasswordResetAttempt `
                -VictimUser $VictimUser `
                -NewPassword $NewPassword `
                -EnableAccountManipulationActions:$EnableAccountManipulationActions
        }

        "first_firewall_anomaly" {
            return Invoke-FirewallAnomaly -EnableFirewallAnomalyActions:$EnableFirewallAnomalyActions
        }

        "first_ntlm_authentication_failure" {
            if (-not $EnableLabActions) {
                return [PSCustomObject]@{
                    execution_status = "manual_required"
                    executed_command = "net use \\$VictimTarget\IPC$ /user:$DomainNetBIOS\$VictimUser <wrong_password>"
                    message          = "Authentication attempt execution is disabled. Use -EnableLabActions to run lab NTLM attempts."
                }
            }

            return Invoke-InvalidSMBLogon `
                -VictimTarget $VictimTarget `
                -DomainNetBIOS $DomainNetBIOS `
                -VictimUser $VictimUser `
                -InvalidPassword $InvalidPassword
        }

        "second_kerberos_pre_auth_failure" {
            return Invoke-KerberosRelatedAttempt -VictimTarget $VictimTarget -StageName $name -EnableLabActions:$EnableLabActions
        }

        "second_password_change_attempt" {
            return Invoke-PasswordChangeAttempt `
                -VictimUser $VictimUser `
                -NewPassword $NewPassword `
                -EnableAccountManipulationActions:$EnableAccountManipulationActions
        }

        "second_system_integrity_anomaly" {
            return Invoke-IntegrityAnomaly -EnableIntegrityAnomalyActions:$EnableIntegrityAnomalyActions
        }

        "third_kerberos_pre_auth_failure" {
            return Invoke-KerberosRelatedAttempt -VictimTarget $VictimTarget -StageName $name -EnableLabActions:$EnableLabActions
        }

        "second_ntlm_authentication_failure" {
            if (-not $EnableLabActions) {
                return [PSCustomObject]@{
                    execution_status = "manual_required"
                    executed_command = "net use \\$VictimTarget\IPC$ /user:$DomainNetBIOS\$VictimUser <wrong_password>"
                    message          = "Authentication attempt execution is disabled. Use -EnableLabActions to run lab NTLM attempts."
                }
            }

            return Invoke-InvalidSMBLogon `
                -VictimTarget $VictimTarget `
                -DomainNetBIOS $DomainNetBIOS `
                -VictimUser $VictimUser `
                -InvalidPassword $InvalidPassword
        }

        "second_firewall_anomaly" {
            return Invoke-FirewallAnomaly -EnableFirewallAnomalyActions:$EnableFirewallAnomalyActions
        }

        "final_failed_logon_attempt" {
            if (-not $EnableLabActions) {
                return [PSCustomObject]@{
                    execution_status = "manual_required"
                    executed_command = "net use \\$VictimTarget\IPC$ /user:$DomainNetBIOS\$VictimUser <wrong_password>"
                    message          = "Authentication attempt execution is disabled. Use -EnableLabActions to run final failed logon attempt."
                }
            }

            return Invoke-InvalidSMBLogon `
                -VictimTarget $VictimTarget `
                -DomainNetBIOS $DomainNetBIOS `
                -VictimUser $VictimUser `
                -InvalidPassword $InvalidPassword
        }

        default {
            return [PSCustomObject]@{
                execution_status = "skipped"
                executed_command = $null
                message          = "No action handler defined for stage_name: $name"
            }
        }
    }
}

function Get-ObservationStatus {
    param(
        [object[]]$ObservedEvents
    )

    $realEvents = @($ObservedEvents | Where-Object { $_.status -eq "observed" -and $_.event_id -ne $null })
    $collectionErrors = @($ObservedEvents | Where-Object { $_.status -eq "collection_failed" })

    if ($realEvents.Count -gt 0) {
        return "matched"
    }

    if ($collectionErrors.Count -gt 0) {
        return "collection_failed"
    }

    return "no_match"
}

function Build-StageAssessment {
    param(
        [string]$ExecutionStatus,
        [string]$ObservationStatus,
        [string]$Message
    )

    $key = "$ExecutionStatus|$ObservationStatus"

    if ($key -eq "attempted|matched") {
        return "Action executed and related logs observed"
    }
    elseif ($key -eq "attempted|no_match") {
        return "Action executed but no related logs observed"
    }
    elseif ($key -eq "attempted|collection_failed") {
        return "Action executed but remote or local log collection failed"
    }
    elseif ($key -eq "manual_required|matched") {
        return "Not auto-executed but related logs were observed"
    }
    elseif ($key -eq "manual_required|no_match") {
        return "Not auto-executed and no related logs observed"
    }
    elseif ($key -eq "manual_required|collection_failed") {
        return "Not auto-executed and log collection failed"
    }
    elseif ($key -eq "failed|matched") {
        return "Action execution failed but some related logs observed"
    }
    elseif ($key -eq "failed|no_match") {
        return "Action execution failed and no logs observed"
    }
    elseif ($key -eq "failed|collection_failed") {
        return "Action execution failed and log collection failed"
    }
    elseif ($key -eq "skipped|matched") {
        return "Stage skipped but related logs observed"
    }
    else {
        if (-not [string]::IsNullOrWhiteSpace($Message)) {
            return $Message
        }
        return "Status undetermined"
    }
}

function Complete-Stage {
    param(
        $Stage,
        [datetime]$Since,
        [string]$ExecutionStatus,
        [string]$ExecutedCommand,
        [string]$Message,
        [string]$VictimTarget,
        [string]$DCTarget,
        [switch]$TryRemoteEventCollection
    )

    $profile = Get-StageObservationProfile -StageName $Stage.stage_name

    $targets = Resolve-CollectionTargets `
        -Hosts $profile.Hosts `
        -VictimTarget $VictimTarget `
        -DCTarget $DCTarget `
        -TryRemoteEventCollection:$TryRemoteEventCollection

    if ($targets.Count -eq 0) {
        $targets = @(
            [PSCustomObject]@{
                role   = "attacker"
                target = $env:COMPUTERNAME
            }
        )
    }

    $observed = @()

    if ($profile.CandidateEventIds.Count -gt 0) {
        $observed = Get-ObservedEvents `
            -Since $Since `
            -EventIds $profile.CandidateEventIds `
            -LogNames $profile.LogNames `
            -ComputerTargets $targets
    }

    $observationStatus = Get-ObservationStatus -ObservedEvents $observed
    $assessment = Build-StageAssessment `
        -ExecutionStatus $ExecutionStatus `
        -ObservationStatus $observationStatus `
        -Message $Message

    return [PSCustomObject]@{
        stage_id            = $Stage.stage_id
        stage_name          = $Stage.stage_name
        description         = $Stage.description
        behavior            = $Stage.behavior
        related_tactic      = $Stage.related_tactic
        related_techniques  = $Stage.related_techniques
        execution_status    = $ExecutionStatus
        executed_command    = $ExecutedCommand
        observation_status  = $observationStatus
        candidate_event_ids = $profile.CandidateEventIds
        collection_hosts    = $targets
        observed_events     = $observed
        observation_notes   = $profile.Notes
        assessment          = $assessment
        message             = $Message
        timestamp           = Get-NowIso
    }
}

Ensure-Directory -Path $OutputDir

Write-Info "Loading scenario: $ScenarioPath"
$scenario = Load-Scenario -Path $ScenarioPath

$stageResults = @()
$flatArtifacts = @()

Write-Info "Scenario: $($scenario.scenario_name)"
Write-Info "Stages: $($scenario.scenario_flow.Count)"
Write-Info "TryRemoteEventCollection: $TryRemoteEventCollection"
Write-Info "EnableLabActions: $EnableLabActions"
Write-Info "EnableAccountManipulationActions: $EnableAccountManipulationActions"

foreach ($stage in $scenario.scenario_flow) {
    Write-Info "Running stage $($stage.stage_id): $($stage.stage_name)"

    $since = Get-Date

    $actionResult = Invoke-StageAction `
        -Stage $stage `
        -VictimTarget $VictimTarget `
        -DomainNetBIOS $DomainNetBIOS `
        -DomainFqdn $DomainFqdn `
        -AttackerUser $AttackerUser `
        -VictimUser $VictimUser `
        -InvalidPassword $InvalidPassword `
        -NewPassword $NewPassword `
        -EnableLabActions:$EnableLabActions `
        -EnableAccountManipulationActions:$EnableAccountManipulationActions `
        -EnableFirewallAnomalyActions:$EnableFirewallAnomalyActions `
        -EnableIntegrityAnomalyActions:$EnableIntegrityAnomalyActions

    Start-Sleep -Seconds $ObservationWindowSeconds

    $stageResult = Complete-Stage `
        -Stage $stage `
        -Since $since `
        -ExecutionStatus $actionResult.execution_status `
        -ExecutedCommand $actionResult.executed_command `
        -Message $actionResult.message `
        -VictimTarget $VictimTarget `
        -DCTarget $DCTarget `
        -TryRemoteEventCollection:$TryRemoteEventCollection

    $stageResults += $stageResult

    if ($stageResult.observed_events) {
        foreach ($item in $stageResult.observed_events) {
            $flatArtifacts += [PSCustomObject]@{
                stage_id     = $stage.stage_id
                stage_name   = $stage.stage_name
                role         = $item.role
                computer     = $item.computer
                log_name     = $item.log_name
                event_id     = $item.event_id
                time_created = $item.time_created
                provider     = $item.provider
                level        = $item.level
                task         = $item.task
                status       = $item.status
                message      = $item.message
            }
        }
    }

    Write-Host ("  -> execution_status: {0}, observation_status: {1}" -f `
        $stageResult.execution_status, $stageResult.observation_status) -ForegroundColor Green
}

$summary = [PSCustomObject]@{
    scenario_id                   = $scenario.scenario_id
    scenario_name                 = $scenario.scenario_name
    scenario_type                 = $scenario.scenario_type
    description                   = $scenario.description
    generated_at                  = Get-NowIso
    collector_host                = $env:COMPUTERNAME
    victim_target                 = $VictimTarget
    dc_target                     = $DCTarget
    try_remote_collection         = [bool]$TryRemoteEventCollection
    enable_lab_actions            = [bool]$EnableLabActions
    stage_count                   = $stageResults.Count
    matched_stage_count           = @($stageResults | Where-Object { $_.observation_status -eq "matched" }).Count
    no_match_stage_count          = @($stageResults | Where-Object { $_.observation_status -eq "no_match" }).Count
    collection_failed_stage_count = @($stageResults | Where-Object { $_.observation_status -eq "collection_failed" }).Count
    stages                        = $stageResults
}

$groundTruthPath = Join-Path $OutputDir "ground_truth.json"
$artifactPath    = Join-Path $OutputDir "raw_artifacts.json"
$summaryPath     = Join-Path $OutputDir "run_summary.json"

ConvertTo-PrettyJson -InputObject $summary      | Set-Content -LiteralPath $groundTruthPath -Encoding UTF8
ConvertTo-PrettyJson -InputObject $flatArtifacts | Set-Content -LiteralPath $artifactPath    -Encoding UTF8

[PSCustomObject]@{
    scenario_id       = $scenario.scenario_id
    scenario_name     = $scenario.scenario_name
    generated_at      = Get-NowIso
    output_dir        = $OutputDir
    ground_truth      = $groundTruthPath
    raw_artifacts     = $artifactPath
    total_stages      = $stageResults.Count
    matched           = @($stageResults | Where-Object { $_.observation_status -eq "matched" }).Count
    no_match          = @($stageResults | Where-Object { $_.observation_status -eq "no_match" }).Count
    collection_failed = @($stageResults | Where-Object { $_.observation_status -eq "collection_failed" }).Count
} | ConvertTo-PrettyJson | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Info "Done."
Write-Info "ground_truth.json  -> $groundTruthPath"
Write-Info "raw_artifacts.json -> $artifactPath"
Write-Info "run_summary.json   -> $summaryPath"
