#!/usr/bin/env python3
"""
Fill me in later.
"""

import logging
import os
import uuid

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Body, Depends, FastAPI, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from fastapi.testclient import TestClient
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, ValidationError

import requests


# Crypt things. THese are all demo values.
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Others
DNS_UPDATER_SCOPE_NAME = "dns-updater"
DNS_UPDATER_USERNAME = "dns-updater"
REQUEST_DNS_TOKEN_SCOPE = "request-dns-token"

# Configure Logging
logging.basicConfig(
    # level = logging.DEBUG
    level = logging.INFO
)


# Set up FastAPI app and other aux things.
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={
        "me": "Read information about the current user.",
        "request-dns-token": "Allows requesting a token for DNS updates.",
        "dns-updater": "Allows updating DNS on the specified record name."   # How do I make this not selectable, but still within the schema? Does that even make any sense?
    }
)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Fake/Mock values
mock_db = {}
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False
    },
    "fired-admin": {
        "username": "fired-admin",
        "hashed_password": "fakehashedsecret2",
        "disabled": True
    }
}


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
    hashed_password: str


def verify_password(plain_password, hashed_password):
    """
    Verify the incoming password matches the stored hashed password.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """
    Hash the incoming password.
    """
    return pwd_context.hash(password)


def get_user(db, username: str):
    """
    Discover if the user exists in the DB. If so, we return a UserInDB type
    that will have the hashed password in addition to the usual attributes.

    Note that this only works for Fake/MockDB at the moment.
    """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    """
    Authentication flow for a user.
    """
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
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


class DnsUpdater(BaseModel):
    """
    This model describes a DnsUpdater token.
    """
    username : str = Field(DNS_UPDATER_USERNAME, Literal=True)
    scopes: list[str]

async def validate_dns_updater_token(security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]):
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

    except (JWTError, ValidationError):
        raise credentials_exception

    # We are looking for a specific scope.
    if REQUEST_DNS_TOKEN_SCOPE not in token_data.scopes:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not enough permissions",
            headers={"WWW-Authenticate": authenticate_value}
        )

    # We get here it means the scope is found. We need to construct a model and return it back.
    dns_updater = DnsUpdater(scopes=token_data.scopes)

    return dns_updater


async def get_current_user(security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]):
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

    except (JWTError, ValidationError):
        raise credentials_exception

    # TODO: If user is dns-updater, go down a different flow.
    if token_data.username == "dns-updater":
        print(token_data.scopes)
        dns_updater_scope_found = False
        for scope in token_data.scopes:
            if "dns-updater:" in scope:
                dns_updater_scope_found = True
                break

        if dns_updater_scope_found:
            # Super duper cheap hack. Let's fix it in the future with a proper class/model.
            return UserInDB(username="dns-updater", hashed_password="doesnotexist")
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions (dns-updater)",
                headers={"WWW-Authenticate": authenticate_value}
            )

    user = get_user(fake_users_db, username=token_data.username)

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
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "scopes": form_data.scopes}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me")
async def get_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    """
    Return data about ourself.
    """
    return current_user


@app.get("/users/me/items/")
async def get_own_items(current_user: Annotated[User, Security(get_current_active_user, scopes=["request-dns-token"])]):
    return [{"item_id": "Foo", "owner": current_user.username}]


class Hostname(BaseModel):
    hostname : str


# Depends/Security uses ww-urlencoded, Body uses json.
# TODO: Figure out why scoopes=[] isn't working as I think.
@app.post("/dns/token", response_model=Token)
async def get_dns_token(hostname: Annotated[Hostname, Depends()], dns_updater: Annotated[DnsUpdater, Security(validate_dns_updater_token, scopes=["request-dns-tokena"])]):
#async def get_dns_token(hostname: Annotated[Hostname, Depends()], dns_updater: Annotated[DnsUpdater, Depends(validate_dns_updater_token)]):
#async def get_dns_token(hostname: Annotated[Hostname, Body()], dns_updater: Annotated[DnsUpdater, Depends(validate_dns_updater_token)]):
    """
    Given a valid incoming token, provide a token back that allows updating
    the DNS record for the specified host.
    """

    print(hostname)
    # TODO: Validate hostname is proper format.

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": dns_updater.username, "scopes": [f"{DNS_UPDATER_SCOPE_NAME}:{hostname}"]}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


# TODO: We should not use get_current_active_user. We should make our own flow. Cheap hack for now because it is getting late and I want to see this somewhat work.
@app.put("/dns/update")
async def put_dns_record(ipv6: str, current_token: Annotated[str, Security(get_current_active_user, scopes=["hi"])]):
    print(ipv6)
    print(current_token)
    CF_TOKEN = os.environ.get("CF_TOKEN")
    CF_ZONE_ID = os.environ.get("CF_ZONE_ID")

    cf_endpoint = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"

    headers = {
        "Authorization": f"Bearer {CF_TOKEN}",
        "Content-Type": "application/json"
    }

    new_record_data = {
        "content": "fd73:6172:6168:a10::1",
        "name": "stinky2.my.tld",
        "proxied": False,
        "type": "AAAA",
        "comment": "dns-api",
        "ttl": 120
    }

    response = requests.post(cf_endpoint, json=new_record_data, headers=headers)

    print(response.content)

    if response.status_code == 201:
        print("Worked")
    else:
        print("Fart")

    # We have to also perform a check if it exist already, because then it is a PUT.
    # For tomorrow...

    return "Hi"


# Tests
client = TestClient(app)

def test_get_root():
    """
    Unit test the root route.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}

def test_create_token():
    """
    Unit test creating a DNS consumer token.
    """
    response = client.post(
        "/tokens",
        headers={"X-Blah": "Blah"},
        json={"host": "sheep.t0fu.dev"},
    )
    print(f"Response is: {response.content}")
    assert response.status_code == 200
    assert response.json() == {"message": "success"}
