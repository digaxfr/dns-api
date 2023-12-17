#!/usr/bin/env python3
"""
DNS API
"""

import logging
import os
import sqlite3

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from fastapi.testclient import TestClient
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, ValidationError

import requests


# openssl rand -hex 32
SECRET_KEY = os.environ.get("DNS_API_SECRET_KEY")
if SECRET_KEY is None: # pragma: no cover
    # pylint: disable=W0719
    raise Exception("DNS_API_SECRET_KEY needs to be defined.")

ACCESS_TOKEN_EXPIRE_MINUTES = 5
ALGORITHM = "HS256"
DNS_UPDATER_SCOPE_NAME = "dns-updater"
DNS_UPDATER_USERNAME = "dns-updater"
REQUEST_DNS_TOKEN_SCOPE = "request-dns-token"
SQLITE_DB_NAME = "dns-api.db"

# Different "categories" of scopes. Not sure if there is a better way to handle
# this. Mainly used for checking the requested scope on login.
scopes_user_pw = {
    "me": "Read information about the current user.",
    "request-dns-token": "Allows requesting a token for DNS updates.",
}

scopes_dns_updater = {
    "dns-updater": "Allows updating DNS on the specified record name."
}


# Configure Logging
logging.basicConfig(
    # level = logging.DEBUG
    level = logging.INFO
)


# Set up FastAPI app and other aux things.
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes=dict(scopes_user_pw, **scopes_dns_updater)
)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Token(BaseModel):
    """
    Model of a token presented to the client.
    """
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """
    Model describing the exact shape of scopes and username.
    """
    scopes: list[str] = []
    username: str | None = None


class User(BaseModel):
    """
    Model that describes a user of the API to generate tokens.
    """
    username: str
    disabled: bool | None = None


class UserInDB(User):
    """
    Child model that describes a User that exists in the databsae.
    """
    password_hash: str


def verify_password(plain_password, password_hash):
    """
    Verify the incoming password matches the stored hashed password.
    """
    return pwd_context.verify(plain_password, password_hash)


def get_password_hash(password):
    """
    Hash the incoming password.
    """
    return pwd_context.hash(password)


def get_user(username: str):
    """
    Discover if the user exists in the DB. If so, we return a UserInDB type
    that will have the hashed password in addition to the usual attributes.

    Note that this only works for Fake/MockDB at the moment.
    """
    # Connect to sqlite db
    con = sqlite3.connect(SQLITE_DB_NAME)
    cur = con.cursor()
    res = cur.execute(f"SELECT username,password_hash,disabled \
        FROM users WHERE username == '{username}'")
    rows = res.fetchall()
    con.close()
    if len(rows) == 1:
        return UserInDB(
            username = username,
            password_hash = rows[0][1],
            disabled = rows[0][2],
        )
    return False


def authenticate_user(username: str, password: str):
    """
    Authentication flow for a user.
    """
    user = get_user(username)
    if not user:
        return False
    # pylint: disable=E1101
    if not verify_password(password, user.password_hash):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """
    Generate a JWT.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


class DnsUpdaterToken(BaseModel):
    """
    This model describes a DnsUpdaterToken token.
    """
    username : str = Field(DNS_UPDATER_USERNAME, Literal=True)
    scopes: list[str]

async def validate_dns_updater_token(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)]):
    """
    Figure out if the incoming token is a valid dns_updater scope.
    """

    # Some setup of vars.
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Check the jwt for basic stuff.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Retrieve the subject/user out.
        subject: str = payload.get("sub")
        if subject is None:
            raise credentials_exception

        # Retrieve the scopes out.
        token_scopes = payload.get("scopes", [])

        # Finally we create a class of TokenData which allows strict checking and whatnot.
        # From here on, we refer to the model and not the variables.
        token_data = TokenData(scopes=token_scopes, username=subject)

    except (JWTError, ValidationError) as exc:
        raise credentials_exception from exc

    # Verify we have the relelvant scopes.
    # Iterate over the list of required scopes.
    for scope in security_scopes.scopes:
        # Edge case: dns-updater:* scopes
        if scope.startswith(f"{DNS_UPDATER_SCOPE_NAME}:"):
            # Now iterate over the list of token's scopes
            dns_updater_scope_found = False
            for token_scope in token_data.scopes:
                if token_scope.startswith(f"{DNS_UPDATER_SCOPE_NAME}:"):
                    # This is probably bad practice, but I am being lazy.
                    # While we are here, let us check the subject value is
                    # what it should be.
                    # This whole thing should also probably be a separate
                    # function, but... lazy.
                    if subject == DNS_UPDATER_USERNAME:
                        dns_updater_scope_found = True

            # If we do not find a proper dns updater scope, raise an error.
            if not dns_updater_scope_found:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not enough permissions",
                    headers={"WWW-Authenticate": authenticate_value}
                )

        # Check if the current iteration exists in the token's list of scopes.
        elif scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )

    # We get here it means the scope is found. We need to construct a model and return it back.
    dns_updater = DnsUpdaterToken(scopes=token_data.scopes)

    return dns_updater


async def get_current_user(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)]):
    """
    Figures out if the current token is valid. If so, return a UserInDB object.
    """
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)

    except (JWTError, ValidationError) as exc:
        raise credentials_exception from exc

    user = get_user(username=token_data.username)

    if user is None:
        raise credentials_exception

    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value}
            )

    return user


async def get_current_active_user(
    current_user: Annotated[User, Security(get_current_user, scopes=["me"])]):
    """
    Figures out if the current user is disabled or not.

    Depends on get_current_user which in turn means a valid token.
    """

    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.get("/")
async def get_root():
    """
    Root route.
    """
    return {"message": "Hello World"}


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """
    Endpoint to login with username/password and obtain a JWT.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check for only valid scopes for login with user/pass.
    # Dump attributes
    # for attribute in vars(form_data):
    #     print(attribute, getattr(form_data, attribute))
    for scope in form_data.scopes:
        if scope not in scopes_user_pw:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect scope detected: {scope}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        # pylint: disable=E1101
        data={"sub": user.username, "scopes": form_data.scopes}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me")
async def get_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    """
    Left here as part of the tutorial.
    Return data about ourself.
    """
    return current_user


@app.get("/users/me/items/")
async def get_own_items(
    current_user: Annotated[User, Security(
        get_current_active_user,
        scopes=["request-dns-token"])
    ]):
    """
    Left here as part of the tutorial.
    """
    return [{"item_id": "Foo", "owner": current_user.username}]


class Hostname(BaseModel):
    """
    Hostname model.
    """
    hostname : str


@app.post("/dns/token", response_model=Token)
async def get_dns_token(
    hostname: Annotated[Hostname, Depends()],
    token: Annotated[DnsUpdaterToken,
    Security(validate_dns_updater_token, scopes=["request-dns-token"])]
):
    """
    Given a valid incoming token, provide a token back that allows updating
    the DNS record for the specified host.
    """

    # pylint: disable=W0511
    # TODO: Validate hostname is proper format.

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": token.username,
            "scopes": [f"{DNS_UPDATER_SCOPE_NAME}:{hostname.hostname}"]},
            expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.put("/dns/update")
async def put_dns_record(
    ipv6: str,
    token: Annotated[
        DnsUpdaterToken,
        Security(validate_dns_updater_token, scopes=["dns-updater:"])
    ]):
    """
    Make the update to CloudFlare.
    """

    # Check to see if CF vars are cset up.
    if ("CF_TOKEN" not in os.environ
        or "CF_ZONE_ID" not in os.environ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="CF configuration incorrect",
        )

    cf_token = os.environ.get("CF_TOKEN")
    cf_zone_id = os.environ.get("CF_ZONE_ID")

    cf_endpoint = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records"

    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json"
    }

    # Extract the hostname from the scope.
    token_data = DnsUpdaterToken(username=token.username, scopes=token.scopes)

    # Validate scopes. Lazy approach for now.
    # - List length is 1
    # - Must start with dns-updater:
    scope_found = False
    if len(token_data.scopes) == 1:
        if token_data.scopes[0].startswith(f"{DNS_UPDATER_SCOPE_NAME}:"):
            scope_found = True

    if not scope_found:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid scope"
        )

    hostname = token_data.scopes[0].split(":")[1]

    record_data = {
        "content": ipv6,
        "name": hostname,
        "proxied": False,
        "type": "AAAA",
        "comment": "dns-api",
        "ttl": 120
    }

    # First we need to figure out if the record exists already
    current_record_response = requests.get(
        f"{cf_endpoint}?name={hostname}&type=AAAA",
        headers=headers,
        timeout=30
    )
    current_record = current_record_response.json()

    # There should be a result key and it should be 1 (since we will not
    # account for the use case of multiple IPs returned for a record.
    # Maybe in the future for funsies.
    if len(current_record["result"]) == 0:
        create_record_response = requests.post(
            cf_endpoint,
            json=record_data,
            headers=headers,
            timeout=30
        )
        if create_record_response.status_code == 200:
            return {
                "status": "success",
                "message": "Created record"
            }

        return {
            "status": "error",
            "message": "Failed to create record"
        }

    if len(current_record["result"]) == 1:
        record_id = current_record["result"][0]["id"]
        update_record_response = requests.put(
            f"{cf_endpoint}/{record_id}",
            json=record_data,
            headers=headers,
            timeout=30
        )
        if update_record_response.status_code == 200:
            return {
                "status": "success",
                "message": "Updated record"
            }

        return {
            "status": "error",
            "message": "Failed to update record"
        }

    return {
        "status": "error",
        "message": "More than 1 result returned; doing nothing"
    }


# Tests
client = TestClient(app)

def test_get_root():
    """
    Unit test the root route.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}
