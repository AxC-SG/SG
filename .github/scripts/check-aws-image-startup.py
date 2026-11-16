#!/usr/bin/env python3
"""Boot the exact candidate's migrator, API and worker against disposable PostgreSQL.

Uses the deployed prod profile, external JWT configuration and restricted DB role.
No AWS credentials, live databases or external services are used.
"""
import json
import secrets
import re
import subprocess
import sys
import time
import uuid

POSTGRES = 'postgres:16@sha256:d4d4f1579fcfba19c2257326f6a93f4bcf677a430619f084ced704e18eb428ce'


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()


def status(container, path):
    result = subprocess.run(['docker', 'exec', container, 'busybox', 'wget', '-S', '-T', '5',
                             '-O', '/dev/null', 'http://127.0.0.1:8080' + path],
                            capture_output=True, text=True, timeout=15)
    found = re.search(r'HTTP/1\.[01]\s+(\d{3})', result.stderr)
    return int(found[1]) if found else None


def check(image):
    image = docker('image', 'inspect', '--format={{.Id}}', image)
    prefix = 'candidate-' + uuid.uuid4().hex[:12]
    names = []
    password, runtime_password = secrets.token_hex(24), secrets.token_hex(24)
    common = {'APP_CREDENTIAL_ENCRYPTION_KEY': __import__('base64').b64encode(secrets.token_bytes(32)).decode(),
              'APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED': 'false'}

    def start(role, env, *args):
        name = prefix + '-' + role
        names.append(name)
        return docker('run', '-d', '--name', name, '--network', prefix,
                      *[part for key, value in env.items() for part in ('-e', f'{key}={value}')], *args)

    docker('network', 'create', '--internal', prefix)
    try:
        start('db', {'POSTGRES_PASSWORD': password, 'POSTGRES_DB': 'candidate'}, POSTGRES)
        deadline = time.monotonic() + 90
        while subprocess.run(['docker', 'exec', prefix + '-db', 'pg_isready', '-U', 'postgres', '-d', 'candidate'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            if time.monotonic() > deadline:
                raise RuntimeError('PostgreSQL did not become ready')
            time.sleep(2)
        start('migrator', {**common, 'APP_RUNTIME_ROLE': 'schema-migrator',
                          'MIGRATION_DB_HOST': prefix + '-db', 'MIGRATION_DB_NAME': 'candidate',
                          'MIGRATION_DB_USERNAME': 'postgres', 'MIGRATION_DB_PASSWORD': password,
                          'RUNTIME_DB_USERNAME': 'scout_runtime', 'RUNTIME_DB_PASSWORD': runtime_password}, image)
        # Bound docker wait as well: a hung migration must fail qualification.
        result = subprocess.run(['docker', 'wait', prefix + '-migrator'], capture_output=True, text=True, timeout=240)
        if result.returncode or result.stdout.strip() != '0':
            raise RuntimeError('candidate migrator failed')
        runtime = {**common, 'SPRING_PROFILES_ACTIVE': 'prod', 'APP_ENVIRONMENT': 'preproduction',
                   'DB_URL': f'jdbc:postgresql://{prefix}-db:5432/candidate',
                   'DB_USERNAME': 'scout_runtime', 'DB_PASSWORD': runtime_password,
                   'APP_AI_SECURITY_IDENTITY_HMAC_KEY': secrets.token_hex(32),
                   'APP_JWT_AUTH_MODE': 'EXTERNAL', 'APP_JWT_ISSUER_URI': 'https://issuer.invalid',
                   'APP_JWT_JWK_SET_URI': 'https://issuer.invalid/jwks',
                   'APP_CORS_ALLOWED_ORIGINS': 'https://frontend.invalid',
                   'APP_PUBLIC_RATE_LIMIT_TRUSTED_PROXY_CIDRS': '127.0.0.1/32',
                   'APP_PLATFORM_MIGRATION_ENABLED': 'false', 'APP_SCHEMA_MIGRATION_ENABLED': 'false',
                   'DB_MAX_POOL_SIZE': '5', 'DB_MIN_IDLE': '1'}
        for role in ('api', 'worker'):
            start(role, {**runtime, 'APP_RUNTIME_ROLE': role}, image)
        deadline = time.monotonic() + 240
        for role in ('api', 'worker'):
            container = prefix + '-' + role
            while status(container, '/actuator/health/readiness') != 200:
                if docker('inspect', '--format={{.State.Running}}', prefix + '-' + role) != 'true' or time.monotonic() > deadline:
                    raise RuntimeError(role + ' failed readiness')
                time.sleep(3)
            if role == 'api' and (status(container, '/api/auth/csrf') != 200 or status(container, '/api/me') != 401):
                raise RuntimeError('candidate API public/protected contract failed')
        print(json.dumps({'image_id': image, 'migrator': 'passed', 'api': 'passed', 'worker': 'passed'}))
    except BaseException:
        for name in names:
            # Disposable fixture configuration only; no live credentials enter this harness.
            subprocess.run(['docker', 'logs', '--tail', '100', name], check=False)
        raise
    finally:
        for name in reversed(names):
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['docker', 'network', 'rm', prefix], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    check(sys.argv[1])
