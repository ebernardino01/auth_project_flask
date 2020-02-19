#!/bin/sh
rm -rf migrations/
psql -d psqlappdb -f drop.sql
psql -d psqlappdb -f create_lookup.sql
flask db init

