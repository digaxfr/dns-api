# dns-api

## Problems/Scope

* Dynamically updating DNS when a new host comes online.
* The host should only be able to update a specific record, not everything.
* The token is expected to only be used once per generation (or have a short lifetime).

## Goals

* Write some Python.
* Learn how to protect an endpoint.
* Keeping it simple for now. We do not need "Bigger Applications" design yet.
  Let's see this thing actually work first!
* Have unit tests
* Store the stateful data somewhere (e.g. sqlite)

## TODO

* Better logging

## Design

* Hosts
  * IPv4 / A
  * IPv6 / AAAA
  * Token ID

* Token ID
    * Hostname record

* Store the data in a DB (sqlite?)

* User auth in with user/password
  --> Gets jwt with a scope to be able to make new update-record tokens
  --> Take jwt and request a new update-record token
  --> update-record token is then placed into VM
  --> On launch of new VM, use jwt to update dns record
