"""Collects FTP and SSH stats from logs and writes to JSON files."""
import json
import os
import re
import time
import subprocess

FTP_STATS_FILE = '/tmp/ftp_stats.json'
SSH_STATS_FILE = '/tmp/ssh_stats.json'
FTP_LOG = '/var/log/vsftpd.log'
AUTH_LOG = '/var/log/auth.log'

ftp_stats = {
    'downloads': 0,
    'uploads': 0,
    'bytes_sent': 0,
    'bytes_recv': 0,
    'connections': 0,
    'errors': 0,
}

ssh_stats = {
    'sessions': 0,
    'failed_logins': 0,
    'active_sessions': 0,
    'commands_executed': 0,
}

ftp_pos = 0
auth_pos = 0


def parse_ftp_log():
    global ftp_pos
    if not os.path.exists(FTP_LOG):
        return

    try:
        size = os.path.getsize(FTP_LOG)
        if size < ftp_pos:
            ftp_pos = 0

        with open(FTP_LOG) as f:
            f.seek(ftp_pos)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Count connections
                if 'CONNECT' in line:
                    ftp_stats['connections'] += 1
                # Count downloads - OK DOWNLOAD
                if 'OK DOWNLOAD' in line:
                    ftp_stats['downloads'] += 1
                    match = re.search(r',\s*(\d+)\s*bytes', line)
                    if match:
                        ftp_stats['bytes_sent'] += int(match.group(1))
                # Count uploads - OK UPLOAD
                if 'OK UPLOAD' in line:
                    ftp_stats['uploads'] += 1
                    match = re.search(r',\s*(\d+)\s*bytes', line)
                    if match:
                        ftp_stats['bytes_recv'] += int(match.group(1))
                # Count failures
                if 'FAIL' in line:
                    ftp_stats['errors'] += 1

            ftp_pos = f.tell()
    except Exception:
        pass


def parse_ssh_log():
    global auth_pos
    if not os.path.exists(AUTH_LOG):
        return

    try:
        size = os.path.getsize(AUTH_LOG)
        if size < auth_pos:
            auth_pos = 0

        with open(AUTH_LOG) as f:
            f.seek(auth_pos)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if 'Accepted' in line:
                    ssh_stats['sessions'] += 1
                if 'Failed' in line or 'fatal' in line.lower():
                    ssh_stats['failed_logins'] += 1

            auth_pos = f.tell()
    except Exception:
        pass

    # Count active SSH sessions via who or ss
    try:
        result = subprocess.run(
            ['ss', '-tn', 'state', 'established', 'sport', '=', ':2222'],
            capture_output=True, text=True, timeout=5
        )
        ssh_stats['active_sessions'] = max(0, len(result.stdout.strip().split('\n')) - 1)
    except Exception:
        pass


def save_stats():
    with open(FTP_STATS_FILE, 'w') as f:
        json.dump(ftp_stats, f)
    with open(SSH_STATS_FILE, 'w') as f:
        json.dump(ssh_stats, f)


RESET_SIGNAL = '/tmp/stats_reset_collector'


def check_reset():
    global ftp_pos, auth_pos
    if os.path.exists(RESET_SIGNAL):
        for k in ftp_stats:
            ftp_stats[k] = 0
        for k in ssh_stats:
            ssh_stats[k] = 0
        # Seek to end of log files so old entries aren't recounted
        try:
            ftp_pos = os.path.getsize(FTP_LOG) if os.path.exists(FTP_LOG) else 0
        except OSError:
            ftp_pos = 0
        try:
            auth_pos = os.path.getsize(AUTH_LOG) if os.path.exists(AUTH_LOG) else 0
        except OSError:
            auth_pos = 0
        save_stats()
        try:
            os.remove(RESET_SIGNAL)
        except OSError:
            pass


if __name__ == '__main__':
    # Touch log files to ensure they exist
    for log in [FTP_LOG, AUTH_LOG]:
        if not os.path.exists(log):
            open(log, 'w').close()

    while True:
        check_reset()
        parse_ftp_log()
        parse_ssh_log()
        save_stats()
        time.sleep(2)
