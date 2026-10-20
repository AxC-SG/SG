\set ON_ERROR_STOP on

SELECT format(
    'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'runtime_role'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'runtime_role')
\gexec

SELECT EXISTS (
    SELECT 1
    FROM pg_roles
    WHERE rolname = :'runtime_role'
      AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
) AS immutable_unsafe_role
\gset
\if :immutable_unsafe_role
    \echo 'Runtime role has unsafe attributes that require a database superuser to remove'
    \quit 1
\endif

SELECT format(
    'ALTER ROLE %I WITH LOGIN NOINHERIT PASSWORD %L',
    :'runtime_role', :'runtime_password'
)
\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'runtime_role')
\gexec
SELECT format('REVOKE CREATE ON DATABASE %I FROM %I', current_database(), :'runtime_role')
\gexec
SELECT format('REVOKE CREATE ON SCHEMA public FROM %I', :'runtime_role')
\gexec

WITH protected_schemas AS (
    SELECT nspname AS schema_name
    FROM pg_namespace
    WHERE nspname IN ('platform', 'tenant_default') OR nspname ~ '^tenant_'
)
SELECT format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, :'runtime_role')
FROM protected_schemas
\gexec

WITH protected_schemas AS (
    SELECT nspname AS schema_name
    FROM pg_namespace
    WHERE nspname IN ('platform', 'tenant_default') OR nspname ~ '^tenant_'
)
SELECT format(
    'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO %I',
    schema_name, :'runtime_role'
)
FROM protected_schemas
\gexec

WITH protected_schemas AS (
    SELECT nspname AS schema_name
    FROM pg_namespace
    WHERE nspname IN ('platform', 'tenant_default') OR nspname ~ '^tenant_'
)
SELECT format(
    'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I',
    schema_name, :'runtime_role'
)
FROM protected_schemas
\gexec

WITH protected_schemas AS (
    SELECT nspname AS schema_name
    FROM pg_namespace
    WHERE nspname IN ('platform', 'tenant_default') OR nspname ~ '^tenant_'
)
SELECT format('REVOKE CREATE ON SCHEMA %I FROM %I', schema_name, :'runtime_role')
FROM protected_schemas
\gexec

WITH protected_schemas AS (
    SELECT nspname AS schema_name
    FROM pg_namespace
    WHERE nspname IN ('platform', 'tenant_default') OR nspname ~ '^tenant_'
)
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
    current_user, schema_name, :'runtime_role'
)
FROM protected_schemas
\gexec

WITH protected_schemas AS (
    SELECT nspname AS schema_name
    FROM pg_namespace
    WHERE nspname IN ('platform', 'tenant_default') OR nspname ~ '^tenant_'
)
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT USAGE, SELECT ON SEQUENCES TO %I',
    current_user, schema_name, :'runtime_role'
)
FROM protected_schemas
\gexec

SELECT EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname = :'runtime_role'
      AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
) AS unsafe_role
\gset
\if :unsafe_role
    \echo 'Runtime role has unsafe PostgreSQL role attributes'
    \quit 1
\endif

SELECT EXISTS (
    SELECT 1
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles r ON r.oid = c.relowner
    WHERE (n.nspname IN ('platform', 'tenant_default') OR n.nspname ~ '^tenant_')
      AND c.relkind IN ('r', 'p')
      AND r.rolname = :'runtime_role'
) AS owns_protected_table
\gset
\if :owns_protected_table
    \echo 'Runtime role owns a protected table'
    \quit 1
\endif

-- Dedicated legacy GHSA routes retain these two explicitly enumerated public tables.
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'runtime_role')
\gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.github_security_advisories, public.github_advisory_sync_state TO %I', :'runtime_role')
\gexec
