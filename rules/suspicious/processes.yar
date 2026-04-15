rule Suspicious_Process_Names {
    meta:
        description = "Known suspicious process names"
        severity = "medium"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "procdump" nocase
        $s3 = "psexec" nocase
        $s4 = "ncat" nocase
        $s5 = "bloodhound" nocase
        $s6 = "crackmapexec" nocase
        $s7 = "cobaltstrike" nocase
    condition:
        any of them
}