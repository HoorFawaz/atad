# SigmaHQ rules used as test fixtures

These rule files are copied unchanged from the SigmaHQ project
(https://github.com/SigmaHQ/sigma), commit 53b90df66c5b6d1b9be6ba9289c56fe49dd74a73, to test that ATAD loads and
matches public Sigma rules. ATAD does not bundle them in releases.

The rules are licensed under the **Detection Rule License (DRL) 1.1**
(https://github.com/SigmaHQ/Detection-Rule-License). Each file keeps its
`author` field, which identifies the authors as the licence requires, and ATAD
repeats the author in every finding produced from a rule.

| File | Source |
|---|---|
| file_event_win_susp_double_extension.yml | https://github.com/SigmaHQ/sigma/blob/53b90df66c5b6d1b9be6ba9289c56fe49dd74a73/rules/windows/file/file_event/file_event_win_susp_double_extension.yml |
| proc_creation_lnx_curl_usage.yml | https://github.com/SigmaHQ/sigma/blob/53b90df66c5b6d1b9be6ba9289c56fe49dd74a73/rules/linux/process_creation/proc_creation_lnx_curl_usage.yml |
| proc_creation_win_powershell_base64_encoded_cmd.yml | https://github.com/SigmaHQ/sigma/blob/53b90df66c5b6d1b9be6ba9289c56fe49dd74a73/rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml |
| proc_creation_win_powershell_base64_iex.yml | https://github.com/SigmaHQ/sigma/blob/53b90df66c5b6d1b9be6ba9289c56fe49dd74a73/rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml |
| proc_creation_win_powershell_set_policies_to_unsecure_level.yml | https://github.com/SigmaHQ/sigma/blob/53b90df66c5b6d1b9be6ba9289c56fe49dd74a73/rules/windows/process_creation/proc_creation_win_powershell_set_policies_to_unsecure_level.yml |
| proc_creation_win_susp_double_extension.yml | https://github.com/SigmaHQ/sigma/blob/53b90df66c5b6d1b9be6ba9289c56fe49dd74a73/rules/windows/process_creation/proc_creation_win_susp_double_extension.yml |
| win_security_user_creation.yml | https://github.com/SigmaHQ/sigma/blob/53b90df66c5b6d1b9be6ba9289c56fe49dd74a73/rules/windows/builtin/security/win_security_user_creation.yml |
