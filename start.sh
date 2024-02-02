#!/usr/bin/env bash

. .secrets.env

if [ -z "${DNS_API_SECRET_KEY}" ]; then
  echo "DNS_API_SECRET_KEY needs to be set."
  echo "Generate a key with 'openssl rand -hex 32'"
  exit 1
fi

if [ -z "${CF_TOKEN}" ]; then
  echo "CF_TOKEN needs to be set."
fi

if [ -z "${CF_ZONE_ID}" ]; then
  echo "CF_ZONE_ID needs to be set."
fi

uvicorn main:app --reload --host "::0" --port 8000 2>stderr.log 1>stdout.log &
