#!/bin/sh
rm -rf migrations/
psql -d psqlappdb -f drop.sql
psql -d psqlappdb -f create_lookup.sql
export FLASK_APP=service
flask db init
flask db migrate
flask db upgrade
