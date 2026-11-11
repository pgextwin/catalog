#!/usr/bin/env python3
"""Pinned community http ZIP re-GET and disposable Windows SQL qualification.

This test is not signed admission, license acceptance or a public GET adapter.
Reuse the existing original ZIP guards; never upload downloaded/staged bytes.
"""
import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
import urllib.request
import uuid
import zipfile

from issue112_http_original_receipts import (
    CANDIDATES, ORIGIN, DenyRedirect, copy_stream, inspect_archive,
)

# Observed in original PR Run 42951353844. Research equality pins only.
PINS = {
    '14': (1375832, 'e2b4fe130f145875710e61d43f055e7fb6642f61eb65051457d7e49d6e6f9a96'),
    '15': (1371729, '15202e92b4170e4f81b7369496789bdcd7f870cff23aed17f10403a37d342685'),
    '16': (800277, '946429cc25d3b4235f276777d01ff89d2161d898a5dd4ce2c46305dbdb98edb8'),
    '17': (3640379, 'f4fad2ca74e172fdb77d53f21ed63f27d08b271bfbe3084572f703171c67566a'),
    '18': (7043584, '7904f4498c9c011f7a433aed3d735ce38100b4564248e91654e81f9eebc24964'),
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_pin(pg, size, sha):
    if pg not in PINS or (size, sha) != PINS[pg]:
        raise ValueError('Independent original byte equality failed')


def stage_archive(archive_path, root, pg):
    """Strict relative layout; preserve every existing host dependency."""
    observation = inspect_archive(archive_path)
    root = Path(root).resolve(strict=True)
    prefix = f'pg{pg}http_w64/'
    records = []
    planned = []
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.startswith(prefix):
                continue
            relative = info.filename[len(prefix):]
            if not (re.fullmatch(r'bin/[A-Za-z0-9_.-]+[.]dll', relative, re.I) or
                    relative == 'lib/http.dll' or
                    re.fullmatch(r'share/extension/http[A-Za-z0-9_.-]*[.](?:control|sql)', relative)):
                continue
            target = root.joinpath(*relative.split('/'))
            if not target.resolve().is_relative_to(root):
                raise ValueError('Runtime target escapes host root')
            payload = archive.read(info)
            member_sha = hashlib.sha256(payload).hexdigest()
            exists = target.exists()
            if exists and not relative.startswith('bin/'):
                raise ValueError('Non-bin host collision prohibited')
            planned.append((target, payload, exists))
            records.append({
                'zipMember': info.filename, 'targetPath': str(target),
                'originalMemberSha256': member_sha,
                'existingHostPreserved': exists,
                'effectiveFileSha256': digest(target) if exists else member_sha,
            })
        required = {'lib/http.dll', 'share/extension/http.control'}
        if not required.issubset({str(t.relative_to(root)).replace('\\', '/') for t, _, _ in planned}):
            raise ValueError('Missing exact candidate layout')
        if not any(r['zipMember'].endswith('.sql') for r in records):
            raise ValueError('Missing extension SQL')
        # Validate the entire plan before any writes. No extractall or overwrite.
        for target, payload, exists in planned:
            if not exists:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as file:
                    file.write(payload)
    return observation, records


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/issue112':
            self.send_error(404)
            return
        body = b'issue112-loopback-ok'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    if result.returncode:
        print(result.stdout, flush=True)
        print(result.stderr, flush=True)
        result.check_returncode()
    return result.stdout.strip()


def run_control(command):
    # A server inherits controller handles on Windows. Waiting for pipe EOF
    # can hang even after pg_ctl exited; wait for the controller process only.
    subprocess.run(command, check=True, timeout=90)


def control_version(text):
    versions = re.findall(r"^\s*default_version\s*=\s*'([0-9]+(?:[.][0-9]+){1,2})'\s*(?:#.*)?$",
                          text, re.MULTILINE)
    if len(versions) != 1:
        raise ValueError('Ambiguous or missing packaged SQL extension version')
    return versions[0]


@contextmanager
def runtime_workspace(parent):
    # Python 3.12.4+ mkdtemp uses a Windows 0700 DACL. initdb launches with
    # PostgreSQL's restricted token and must inherit the runner temp ACL,
    # as in the existing successful PowerShell runtime pilots. No ACL edit.
    path = Path(parent) / ('issue112-http-' + uuid.uuid4().hex)
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path)


def loaded_modules(backend_pid):
    # Numeric database-selected PID only; no caller-controlled shell text.
    command = ("$ErrorActionPreference='Stop'; (Get-Process -Id " + str(int(backend_pid)) +
               ").Modules | Select-Object ModuleName,FileName | ConvertTo-Json -Compress")
    rows = json.loads(run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command]))
    if not isinstance(rows, list) or not rows:
        raise ValueError('No live backend module inventory')
    receipts = []
    for row in rows:
        path = Path(row['FileName']).resolve(strict=True)
        receipts.append({'module': row['ModuleName'], 'actualLoadedPath': str(path),
                         'sha256': digest(path)})
    return receipts


def qualify(pg):
    if (os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('GITHUB_REPOSITORY') != 'pgextwin/catalog' or
            os.environ.get('RUNNER_OS') != 'Windows'):
        raise ValueError('Only ephemeral pgextwin/catalog Windows CI is supported')
    root = Path(os.environ['PGROOT']).resolve(strict=True)
    bin_dir = root / 'bin'
    version = run([str(bin_dir / 'pg_config.exe'), '--version'])
    if not re.match(r'^PostgreSQL\s+' + pg + r'(?:[.]|\s)', version):
        raise ValueError('PostgreSQL host major mismatch')
    host_receipts = {str(p): digest(p) for p in bin_dir.glob('*.dll')}
    with runtime_workspace(os.environ['RUNNER_TEMP']) as tmp:
        archive_path = tmp / CANDIDATES[pg][0]
        url = ORIGIN + CANDIDATES[pg][0]
        request = urllib.request.Request(url, headers={'User-Agent': 'pgextwin-issue112-private-sql/1'})
        with urllib.request.build_opener(DenyRedirect).open(request, timeout=60) as response:
            if response.status != 200 or response.geturl() != url:
                raise ValueError('Original response identity differs')
            size, sha = copy_stream(response, archive_path, limit=PINS[pg][0])
        verify_pin(pg, size, sha)
        observation, staged = stage_archive(archive_path, root, pg)
        packaged_sql_version = control_version(
            (root / 'share' / 'extension' / 'http.control').read_text(encoding='utf-8'))
        print('HTTP_INDEPENDENT_ORIGINAL_REGET=PASS ' + json.dumps({
            'pg': pg, 'bytes': size, 'sha256': sha, **observation, 'stagedFileReceipts': staged,
        }), flush=True)
        ctl = str(bin_dir / 'pg_ctl.exe')
        data = str(tmp / 'data')
        log = str(tmp / 'postgres.log')
        run([str(bin_dir / 'initdb.exe'), '-D', data, '-A', 'trust', '-U', 'postgres', '--no-instructions'])
        print('HTTP_HOST_INITDB=PASS PG=' + pg, flush=True)
        started = False
        probe = None
        fixture = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        threading.Thread(target=fixture.serve_forever, daemon=True).start()
        try:
            run_control([ctl, '-D', data, '-l', log, '-o', '-h 127.0.0.1 -p 55454', '-w', 'start'])
            started = True
            print('HTTP_HOST_STARTED=PASS PG=' + pg, flush=True)
            psql = [str(bin_dir / 'psql.exe'), '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                    '-h', '127.0.0.1', '-p', '55454', '-U', 'postgres', '-d', 'postgres']
            run(psql + ['-c', 'CREATE EXTENSION http;'])
            actual_version = run(psql + ['-c', "SELECT extversion FROM pg_extension WHERE extname='http';"])
            if actual_version != packaged_sql_version:
                raise ValueError('Installed extension version differs: ' + actual_version)
            # Hold the same backend after the libcurl call for actual loaded-path capture.
            sql = ("SET application_name='issue112-http-probe'; SET statement_timeout='45s'; "
                   "SET http.curlopt_timeout_msec='5000'; "
                   "SELECT CASE WHEN status=200 AND content='issue112-loopback-ok' "
                   "THEN 'HTTP_LOOPBACK_SQL=PASS' ELSE 'HTTP_LOOPBACK_SQL=FAIL' END "
                   "FROM http_get('http://127.0.0.1:" + str(fixture.server_port) +
                   "/issue112'); SELECT pg_sleep(20);")
            # PG14 psql -c prints only the final command result (pg_sleep).
            # A command file preserves the HTTP assertion result on all majors.
            sql_path = tmp / 'http-probe.sql'
            sql_path.write_text(sql, encoding='utf-8')
            probe = subprocess.Popen(psql + ['-f', str(sql_path)], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
            modules = None
            for _ in range(30):
                if probe.poll() is not None:
                    break
                backend = run(psql + ['-c', "SELECT pid FROM pg_stat_activity WHERE "
                                      "application_name='issue112-http-probe' AND wait_event='PgSleep';"])
                if backend.isdecimal():
                    modules = loaded_modules(int(backend))
                    break
                time.sleep(0.25)
            output, errors = probe.communicate(timeout=50)
            if probe.returncode != 0 or 'HTTP_LOOPBACK_SQL=PASS' not in output or 'HTTP_LOOPBACK_SQL=FAIL' in output:
                raise ValueError('Loopback SQL failed, psql exit=' + str(probe.returncode) + ': ' + output + errors)
            if not modules:
                raise ValueError('Live tested backend module capture missing')
            http_rows = [r for r in modules if r['module'].casefold() == 'http.dll']
            expected_path = root / 'lib' / 'http.dll'
            if len(http_rows) != 1 or not expected_path.samefile(http_rows[0]['actualLoadedPath']):
                raise ValueError('http.dll loaded from unexpected path')
            if http_rows[0]['sha256'] != digest(expected_path):
                raise ValueError('Loaded http.dll receipt differs')
            if not any('curl' in r['module'].casefold() for r in modules):
                raise ValueError('No actual libcurl module observed')
            for path, expected_sha in host_receipts.items():
                if digest(path) != expected_sha:
                    raise ValueError('Preinstalled host DLL changed')
            print('HTTP_WINDOWS_REAL_SQL=PASS ' + json.dumps({
                'pg': pg, 'installedSqlExtensionVersion': actual_version,
                'publisherAdvertisedReleaseVersionUnverified': CANDIDATES[pg][1],
                'createExtension': 'PASS', 'loopbackGet': 'PASS',
                'loadedBackendModules': modules, 'preexistingHostDllsUnchanged': True,
                'tlsHttpsBehaviorVerified': False, 'allDynamicPathsVerified': False,
                'sourceToBinaryProducerAttestationVerified': False,
                'allComponentLicensesAndNoticesVerified': False,
                'downloadAuthorized': False, 'publisherAuthorized': False,
            }), flush=True)
        except Exception:
            if Path(log).exists():
                print(Path(log).read_text(errors='replace')[-16000:], flush=True)
            raise
        finally:
            if probe is not None and probe.poll() is None:
                probe.kill()
                probe.communicate(timeout=10)
            fixture.shutdown()
            fixture.server_close()
            if started or (Path(data) / 'postmaster.pid').exists():
                run_control([ctl, '-D', data, '-m', 'immediate', '-w', 'stop'])
    print('CANDIDATE_ONLY=YES PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY ARTIFACT_UPLOAD=NONE')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--pg', required=True, choices=tuple(PINS))
    qualify(parser.parse_args().pg)
