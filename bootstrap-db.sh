#!/usr/bin/env bash
# Bootstrap dns-api's database

set -e

db_name="dns-api.db"

#if [ -e "${db_name}" ]; then
#  echo "Database file exists already."
#  exit 1
#fi

# Create the users database
sqlite3 "${db_name}" <<EOF
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  disabled INTEGER CHECK (disabled >= 0 AND disabled <= 1) NOT NULL
);
EOF

# Create our user
sqlite3 "${db_name}" <<EOF
INSERT OR IGNORE INTO users (username, password_hash, disabled)
VALUES('dns-admin', 'bogus', 0)
EOF

# Set up the hashed password if desired.
read -p "Update password? (Y/N): " update_password_prompt

if [ "${update_password_prompt}" == "Y" ]; then
  if ! which htpasswd 2>&1 >/dev/null; then
    echo "htpasswd not installed. Required for password hashing."
    exit 1
  fi

  htpasswd_out=$(htpasswd -nB -C 12 USER)
  password=$(echo ${htpasswd_out} | cut -d ':' -f 2)
  echo "Password hash is: ${password}"
  sqlite3 "${db_name}" <<EOF
UPDATE users
SET password_hash = '${password}'
WHERE username = 'dns-admin';
EOF
else
  echo "Skipping password update"
fi
