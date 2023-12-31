# dns-api

The bulk of this code follows the FastAPI guide and modified where need be.

## Problems/Scope

* Dynamically updating DNS when a new host comes online.
* The host should only be able to update a specific record, not everything.
* The token is expected to only be used once per generation (or have a short lifetime).
* This will not cover the use case of having multiple IPs returned for a given
  record.

## Goals

* Write some Python.
* Learn how to protect an endpoint.
* Keeping it simple for now. We do not need "Bigger Applications" design yet.
  Let's see this thing actually work first!
* Have unit tests
* Store the stateful data somewhere (e.g. sqlite)

## TODO

* Better logging
* Filter out unknown scopes
* Filter out allowed scopes on what is allowed to be asked for

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

dNsUpdaterToken

/dns/token --> Check incoming token


This example, as long as you pass `Authorization: Bearer` with nothing/anything, it will pass. Something that Depends(oauth2_scheme) is the "root" function that does all the heavy lifting of validing the token for expiration. Maybe even first pass of scope check.

```
@app.post("/dns/token")
async def get_dns_token(request: Annotated[TokenRequest, Depends()], token: Annotated[str, Depends(oauth2_scheme)] ):❮
```
