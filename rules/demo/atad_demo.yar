// Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
// SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

/*
  atad demo rules — SIMULATED.
  These rules match harmless marker strings placed in the demo dataset.
  They do not detect real malware. Add real rule sets in other folders.
*/

rule ATAD_Demo_Simulated_Dropper
{
    meta:
        description = "Matches the simulated dropper marker used in the atad demo"
        author = "atad"
        simulated = "true"
        severity = "high"
    strings:
        $marker = "ATAD-DEMO-SIMULATED-DROPPER" ascii wide
    condition:
        $marker
}

rule ATAD_Demo_Encoded_PowerShell
{
    meta:
        description = "Text that launches PowerShell with an encoded command (common attacker pattern)"
        author = "atad"
        severity = "medium"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc1 = "-encodedcommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
    condition:
        $ps and any of ($enc*)
}
