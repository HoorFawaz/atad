# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""SIMULATED Linux log samples in the exact formats of OpenSSH, sudo, useradd,
systemd-journald (`journalctl -o json`) and auditd (raw audit.log)."""

AUTH_BSD = """\
Nov  7 10:01:02 web01 sshd[2211]: Failed password for root from 203.0.113.9 port 51234 ssh2
Nov  7 10:01:05 web01 sshd[2211]: Failed password for invalid user admin from 203.0.113.9 port 51240 ssh2
Nov  7 10:01:09 web01 sshd[2211]: Failed password for root from 203.0.113.9 port 51244 ssh2
Nov  7 10:01:14 web01 sshd[2211]: Failed password for deploy from 203.0.113.9 port 51248 ssh2
Nov  7 10:01:20 web01 sshd[2211]: Failed password for deploy from 203.0.113.9 port 51252 ssh2
Nov  7 10:02:00 web01 sshd[2215]: Accepted password for deploy from 203.0.113.9 port 51300 ssh2
Nov  7 10:02:00 web01 sshd[2215]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)
Nov  7 10:03:10 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m backup
Nov  7 10:03:10 web01 useradd[2301]: new user: name=backup, UID=1002, GID=1002, home=/home/backup, shell=/bin/bash, from=/dev/pts/0
Nov  7 10:04:00 web01 sudo:   deploy : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Nov  7 10:05:00 web01 CRON[2400]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
this line is not syslog
"""

AUTH_ISO = """\
2026-11-07T13:01:02.123456+03:00 web01 sshd[2211]: Failed password for root from 203.0.113.9 port 51234 ssh2
2026-11-07T10:02:00Z web01 sshd[2215]: Accepted publickey for deploy from 2001:db8::7 port 51300 ssh2: ED25519 SHA256:abc
"""

# 2026-11-07T10:01:02Z = 1794045662
JOURNAL = "\n".join([
    ('{"__REALTIME_TIMESTAMP":"1794045662000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd",'
     '"_PID":"2211","MESSAGE":"Failed password for root from 203.0.113.9 port 51234 ssh2"}'),
    ('{"__REALTIME_TIMESTAMP":"1794045720000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd",'
     '"_PID":"2215","MESSAGE":"Accepted password for deploy from 203.0.113.9 port 51300 ssh2"}'),
    ('{"__REALTIME_TIMESTAMP":"1794045800000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"systemd",'
     '"_PID":"1","MESSAGE":"Started backdoor.service - System Helper."}'),
    ('{"__REALTIME_TIMESTAMP":"1794045801000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"kernel",'
     '"MESSAGE":"eth0: link up"}'),
    ('{"__REALTIME_TIMESTAMP":"1794045802000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sudo",'
     '"MESSAGE":[100,101,112,108,111,121,32,58,32,84,84,89,61,112,116,115,47,48,32,59,32,80,87,68,61,47,32,59,32,85,83,69,82,61,114,111,111,116,32,59,32,67,79,77,77,65,78,68,61,47,117,115,114,47,98,105,110,47,105,100]}'),
    "not json",
]) + "\n"

AUDIT = """\
type=SYSCALL msg=audit(1794045750.120:812): arch=c000003e syscall=59 success=yes exit=0 a0=55d a1=55e a2=55f a3=0 items=2 ppid=2215 pid=2290 auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" subj=unconfined key="exec"
type=EXECVE msg=audit(1794045750.120:812): argc=4 a0="curl" a1="-s" a2="-o" a3=2F746D702F2E782073682E656C66
type=CWD msg=audit(1794045750.120:812): cwd="/root"
type=PATH msg=audit(1794045750.120:812): item=0 name="/usr/bin/curl" inode=1234 dev=08:01 mode=0100755
type=PROCTITLE msg=audit(1794045750.120:812): proctitle=6375726C002D73
type=SYSCALL msg=audit(1794045751.500:813): arch=c000003e syscall=42 success=no exit=-115 a0=5 a1=7ffd a2=10 a3=0 items=0 ppid=2215 pid=2290 auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="net"
type=SOCKADDR msg=audit(1794045751.500:813): saddr=020001BBCB0071320000000000000000
type=SYSCALL msg=audit(1794045752.000:814): arch=c000003e syscall=42 success=yes exit=0 a0=5 a1=7ffd a2=10 a3=0 items=0 ppid=1 pid=900 auid=4294967295 uid=0 comm="systemd-resolve" exe="/usr/lib/systemd/systemd-resolved" key=(null)
type=SOCKADDR msg=audit(1794045752.000:814): saddr=01002F72756E2F7379737465
type=USER_LOGIN msg=audit(1794045753.000:815): pid=2215 uid=0 auid=1001 ses=3 msg='op=login id=1001 exe="/usr/sbin/sshd" hostname=? addr=203.0.113.9 terminal=/dev/pts/0 res=success'
garbage
"""
