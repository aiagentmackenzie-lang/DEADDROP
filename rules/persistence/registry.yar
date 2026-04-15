rule Registry_Persistence {
    meta:
        description = "Windows registry persistence mechanisms"
        severity = "high"
    strings:
        $run1 = "CurrentVersion\\Run" nocase wide
        $run2 = "CurrentVersion\\RunOnce" nocase wide
        $svc = "CurrentControlSet\\Services" nocase wide
        $task = "Schedule\\TaskCache" nocase wide
    condition:
        any of them
}