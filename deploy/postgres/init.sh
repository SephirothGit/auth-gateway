#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<-EOSQL
    CREATE ROLE gateway LOGIN PASSWORD '${GATEWAY_DB_PASSWORD}';
    CREATE DATABASE gateway OWNER gateway;

    CREATE ROLE tokensvc LOGIN PASSWORD '${TOKENSVC_DB_PASSWORD}';
    CREATE DATABASE tokensvc OWNER tokensvc;
EOSQL