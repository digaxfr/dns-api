#!/usr/bin/env bash

set -e

dns_api_endpoint="http://[::0]:8000"
ipv6="fd73:6172:6168:a10::aaaa"
username="dns-admin"
password=""
test_dns_host="sheep.example.com"

function main() {
  case "${1}" in
    "get-token")
      curl -X "POST" \
        --silent \
        -H "accept: application/json" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=&username=${username}&password=${password}&scope=me%20request-dns-token" \
        "${dns_api_endpoint}/token" \
        | jq '.access_token' -r
        ;;

    "get-dns-token")
      if [ -z "${dns_api_token}" ]; then
        echo "dns_api_token needs to be set."
        exit 1
      fi

      curl -X POST \
        --silent \
        -H "accept: application/json" \
        -H "Authorization: Bearer ${dns_api_token}" \
        "${dns_api_endpoint}/dns/token?hostname=${test_dns_host}" \
        | jq -r '.access_token'
      ;;
    "update-test-record")
      if [ -z "${dns_update_token}" ]; then
        echo "dns_update_token needs to be set."
        exit 1
      fi

      curl -X PUT \
        --silent \
        -H "accept: application/json" \
        -H "Authorization: Bearer ${dns_update_token}" \
        "${dns_api_endpoint}/dns/update?ipv6=${ipv6}"
      ;;
    *)
      echo "Not a valid command."
      exit 1
      ;;
  esac
}

if [ -z "${1}" ]; then
  echo """
Usage: "${0}" [get-dns-token|get-token|update-test-record]
  """
  exit 1
fi

main "${@}"
