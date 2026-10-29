#!/bin/sh
set -eu

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 \
  --set=migration_password="$BG_MIGRATION_PASSWORD" \
  --set=app_password="$BG_APP_PASSWORD" <<'SQL'
CREATE ROLE bg_migration LOGIN NOBYPASSRLS PASSWORD :'migration_password';
CREATE ROLE bg_api LOGIN NOBYPASSRLS PASSWORD :'app_password';
ALTER DATABASE baselineguard OWNER TO bg_migration;
GRANT CONNECT ON DATABASE baselineguard TO bg_api;
ALTER DEFAULT PRIVILEGES FOR ROLE bg_migration IN SCHEMA public
  GRANT SELECT ON TABLES TO bg_api;
SQL

