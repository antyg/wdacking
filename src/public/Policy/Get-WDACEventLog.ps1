function Get-WDACEventLog {
    <#
    .SYNOPSIS
        Queries Code Integrity event logs for policy violation events.

    .DESCRIPTION
        Reads the Microsoft-Windows-CodeIntegrity/Operational event log for CI policy
        events using .NET EventLog APIs. Filters for key event IDs:
        - 3076: Audit mode block (would have been blocked if enforced)
        - 3077: Enforcement mode block (execution was blocked)
        - 3089: Signing information for a blocked file
        - 3099: Policy refresh events

        Uses C# interop for high-performance event log reading with structured output.

    .PARAMETER MaxEvents
        Maximum number of events to return. Defaults to 50.

    .PARAMETER EventId
        Filter to specific event ID(s). If not specified, returns all CI-relevant events.

    .PARAMETER HoursBack
        Only return events from the last N hours. Defaults to 24.

    .OUTPUTS
        PSCustomObject[] with properties:
            - EventId        [int]      Event ID (3076, 3077, 3089, 3099, etc.)
            - EventType      [string]   Human-readable type ('AuditBlock', 'EnforcedBlock', etc.)
            - TimeCreated    [datetime] When the event occurred
            - Message        [string]   Full event message
            - ProcessName    [string]   Process that triggered the event (if available)
            - FilePath       [string]   File path that was blocked (if available)

    .EXAMPLE
        Get-WDACEventLog -MaxEvents 10 -Verbose
        Returns the 10 most recent CI events.

    .EXAMPLE
        Get-WDACEventLog -EventId 3077 -HoursBack 1
        Returns only enforcement blocks from the last hour.

    .EXAMPLE
        Get-WDACEventLog | Where-Object EventType -eq 'EnforcedBlock' | Format-Table
        Filters for enforced blocks and displays as a table.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows only
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 10000)]
        [int]$MaxEvents = 50,

        [ValidateSet(3076, 3077, 3089, 3099)]
        [int[]]$EventId,

        [ValidateRange(1, 8760)]
        [int]$HoursBack = 24
    )

    if (-not ([System.Management.Automation.PSTypeName]'WDACEventReader').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;
using System.Text.RegularExpressions;

public static class WDACEventReader
{
    // CI event log path
    private const string LogName = "Microsoft-Windows-CodeIntegrity/Operational";

    // Known CI event IDs and their human-readable types
    private const int AuditBlock = 3076;
    private const int EnforcedBlock = 3077;
    private const int SigningInfo = 3089;
    private const int PolicyRefresh = 3099;

    // Pattern to extract file path from event messages
    private static readonly Regex FilePathPattern = new Regex(
        @"(?:file|path|image)[:\s]+(.+?)(?:\s+was|\s*$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Pattern to extract process name
    private static readonly Regex ProcessPattern = new Regex(
        @"(?:process|application)[:\s]+(.+?)(?:\s|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static void EnsureElevated()
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            var principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException(
                    "This operation requires Administrator elevation. Run PowerShell as Administrator.");
        }
    }

    public static string GetEventType(int eventId)
    {
        switch (eventId)
        {
            case AuditBlock:     return "AuditBlock";
            case EnforcedBlock:  return "EnforcedBlock";
            case SigningInfo:    return "SigningInfo";
            case PolicyRefresh:  return "PolicyRefresh";
            default:             return "Unknown";
        }
    }

    /// <summary>
    /// Queries CI event logs. Returns list of object[]:
    /// [EventId, EventType, TimeCreated, Message, ProcessName, FilePath]
    /// </summary>
    public static List<object[]> Query(int maxEvents, int[] eventIds, int hoursBack)
    {
        EnsureElevated();

        var results = new List<object[]>();

        // Build XPath query — use absolute UTC time to avoid timediff/XML-entity issues
        string cutoffUtc = DateTime.UtcNow.AddHours(-hoursBack)
            .ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");
        string timeFilter = string.Format(
            "TimeCreated[@SystemTime >= '{0}']", cutoffUtc);

        string idFilter;
        if (eventIds != null && eventIds.Length > 0)
        {
            var parts = new List<string>();
            foreach (int id in eventIds)
                parts.Add(string.Format("EventID={0}", id));
            idFilter = "(" + string.Join(" or ", parts.ToArray()) + ")";
        }
        else
        {
            idFilter = string.Format("(EventID={0} or EventID={1} or EventID={2} or EventID={3})",
                AuditBlock, EnforcedBlock, SigningInfo, PolicyRefresh);
        }

        string xpath = string.Format("*[System[{0} and {1}]]", idFilter, timeFilter);

        try
        {
            using (var logReader = new EventLogReader(
                new EventLogQuery(LogName, PathType.LogName, xpath)
                { ReverseDirection = true }))
            {
                EventRecord record;
                int count = 0;
                while ((record = logReader.ReadEvent()) != null && count < maxEvents)
                {
                    using (record)
                    {
                        string message = record.FormatDescription() ?? "(No message)";
                        int eventId = record.Id;

                        // Try to extract file path and process from message
                        string filePath = "";
                        string processName = "";

                        var fileMatch = FilePathPattern.Match(message);
                        if (fileMatch.Success)
                            filePath = fileMatch.Groups[1].Value.Trim();

                        var procMatch = ProcessPattern.Match(message);
                        if (procMatch.Success)
                            processName = procMatch.Groups[1].Value.Trim();

                        // Also check event properties for structured data
                        if (string.IsNullOrEmpty(filePath) && record.Properties.Count > 1)
                        {
                            var fpVal = record.Properties[1].Value;
                            filePath = fpVal != null ? fpVal.ToString() : "";
                        }
                        if (string.IsNullOrEmpty(processName) && record.Properties.Count > 0)
                        {
                            var pnVal = record.Properties[0].Value;
                            processName = pnVal != null ? pnVal.ToString() : "";
                        }

                        results.Add(new object[]
                        {
                            eventId,
                            GetEventType(eventId),
                            record.TimeCreated ?? DateTime.MinValue,
                            message,
                            processName,
                            filePath
                        });

                        count++;
                    }
                }
            }
        }
        catch (EventLogNotFoundException)
        {
            // Log doesn't exist — CI logging may not be configured
        }

        return results;
    }
}
'@ -ReferencedAssemblies $CIRefEvt
    }

    Write-Verbose "Querying CI event log (last $HoursBack hours, max $MaxEvents events)..."

    $events = [WDACEventReader]::Query($MaxEvents, $EventId, $HoursBack)

    foreach ($row in $events) {
        [PSCustomObject]@{
            EventId     = [int]$row[0]
            EventType   = [string]$row[1]
            TimeCreated = [datetime]$row[2]
            Message     = [string]$row[3]
            ProcessName = [string]$row[4]
            FilePath    = [string]$row[5]
        }
    }

    if ($events.Count -eq 0) {
        Write-Verbose 'No CI policy events found in the specified time range.'
    }
    else {
        Write-Verbose "Found $($events.Count) CI policy event(s)."
    }
}
