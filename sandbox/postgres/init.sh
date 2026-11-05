#!/bin/sh
# Two databases on one server:
#   mallya   - MALLYA control plane (metadata only)
#   meridian - Meridian Bank customer-side data (synthetic). Only the worker has these credentials.
set -e
psql -v ON_ERROR_STOP=1 --username postgres <<-EOSQL
  CREATE ROLE mallya_app LOGIN PASSWORD '${MALLYA_DB_PASSWORD}';
  CREATE ROLE meridian_app LOGIN PASSWORD '${MERIDIAN_DB_PASSWORD}' CREATEROLE;
  CREATE DATABASE mallya OWNER mallya_app;
  CREATE DATABASE meridian OWNER meridian_app;
  REVOKE ALL ON DATABASE meridian FROM PUBLIC;
  REVOKE ALL ON DATABASE mallya FROM PUBLIC;
EOSQL
